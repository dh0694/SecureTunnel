//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/model"
)

// Device trust on Windows: sign the server's challenge with certificates from
// the Windows certificate store (keys never leave CNG; TPM-backed keys work),
// and read the Entra/AD join state from dsregcmd.

var (
	modcrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procAcquireKey       = modcrypt32.NewProc("CryptAcquireCertificatePrivateKey")
	modncrypt            = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptSignHash   = modncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject = modncrypt.NewProc("NCryptFreeObject")
)

const (
	acquireSilentFlag    = 0x40
	acquireOnlyNCryptKey = 0x40000
	certNCryptKeySpec    = 0xFFFFFFFF
	bcryptPadPKCS1       = 0x2
	entraDeviceIssuer    = "MS-Organization-Access"
)

type storeCert struct {
	cert *x509.Certificate
	ctx  *windows.CertContext
}

// openCerts lists the certificates in LocalMachine\My (machine) or
// CurrentUser\My. Call the returned func to release them.
func openCerts(machine bool) ([]storeCert, func(), error) {
	loc := uint32(windows.CERT_SYSTEM_STORE_CURRENT_USER)
	if machine {
		loc = uint32(windows.CERT_SYSTEM_STORE_LOCAL_MACHINE)
	}
	name, _ := windows.UTF16PtrFromString("MY")
	st, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0,
		loc|windows.CERT_STORE_READONLY_FLAG|windows.CERT_STORE_OPEN_EXISTING_FLAG, uintptr(unsafe.Pointer(name)))
	if err != nil {
		return nil, func() {}, fmt.Errorf("open certificate store: %w", err)
	}
	var out []storeCert
	var prev *windows.CertContext
	for {
		cc, err := windows.CertEnumCertificatesInStore(st, prev)
		if err != nil || cc == nil {
			break
		}
		prev = cc
		der := bytes.Clone(unsafe.Slice(cc.EncodedCert, cc.Length))
		c, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		out = append(out, storeCert{cert: c, ctx: windows.CertDuplicateCertificateContext(cc)})
	}
	free := func() {
		for _, s := range out {
			_ = windows.CertFreeCertificateContext(s.ctx)
		}
		_ = windows.CertCloseStore(st, 0)
	}
	return out, free, nil
}

// signProof signs the challenge for one kind of proof with the certificate's
// private key. silent is false for user certificates, so a smart card or
// Windows Hello PIN prompt can appear.
func signProof(sc storeCert, nonce, kind string, silent bool) (clientapi.DeviceProof, error) {
	flags := uint32(acquireOnlyNCryptKey)
	if silent {
		flags |= acquireSilentFlag
	}
	var key uintptr
	var spec uint32
	var mustFree int32
	r, _, e := procAcquireKey.Call(uintptr(unsafe.Pointer(sc.ctx)), uintptr(flags), 0,
		uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&spec)), uintptr(unsafe.Pointer(&mustFree)))
	if r == 0 {
		return clientapi.DeviceProof{}, fmt.Errorf("no usable private key: %v", e)
	}
	if mustFree != 0 {
		defer procNCryptFreeObject.Call(key)
	}
	if spec != certNCryptKeySpec {
		return clientapi.DeviceProof{}, errors.New("the key isn't a CNG key")
	}

	msg := model.ProofMessage(nonce, kind)
	var hash []byte
	var alg string
	var pad unsafe.Pointer
	var padFlags uint32
	type pkcs1Padding struct{ alg *uint16 }
	var pk pkcs1Padding
	switch pub := sc.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		hash, alg = h[:], "RS256"
		pk.alg, _ = windows.UTF16PtrFromString("SHA256")
		pad, padFlags = unsafe.Pointer(&pk), bcryptPadPKCS1
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			h := sha256.Sum256(msg)
			hash, alg = h[:], "ES256"
		case 384:
			h := sha512.Sum384(msg)
			hash, alg = h[:], "ES384"
		default:
			return clientapi.DeviceProof{}, errors.New("unsupported curve")
		}
	default:
		return clientapi.DeviceProof{}, errors.New("unsupported key type")
	}

	var size uint32
	if st, _, _ := procNCryptSignHash.Call(key, uintptr(pad), uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)),
		0, 0, uintptr(unsafe.Pointer(&size)), uintptr(padFlags)); st != 0 {
		return clientapi.DeviceProof{}, fmt.Errorf("sign: 0x%08x", uint32(st))
	}
	sig := make([]byte, size)
	if st, _, _ := procNCryptSignHash.Call(key, uintptr(pad), uintptr(unsafe.Pointer(&hash[0])), uintptr(len(hash)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), uintptr(padFlags)); st != 0 {
		return clientapi.DeviceProof{}, fmt.Errorf("sign: 0x%08x", uint32(st))
	}
	return clientapi.DeviceProof{Kind: kind, Alg: alg, Sig: base64.StdEncoding.EncodeToString(sig[:size]),
		Chain: []string{base64.StdEncoding.EncodeToString(sc.cert.Raw)}}, nil
}

func validNow(c *x509.Certificate) bool {
	now := time.Now()
	return now.After(c.NotBefore) && now.Before(c.NotAfter)
}

func clientAuth(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// candidates returns client certificates from acceptable issuers, newest first.
func candidates(list []storeCert, issuers []string) []storeCert {
	want := map[string]bool{}
	for _, i := range issuers {
		if b, err := base64.StdEncoding.DecodeString(i); err == nil {
			want[string(b)] = true
		}
	}
	var out []storeCert
	for _, s := range list {
		c := s.cert
		if !validNow(c) || !clientAuth(c) || c.IsCA || strings.Contains(c.Issuer.CommonName, entraDeviceIssuer) {
			continue
		}
		if len(want) > 0 && !want[string(c.RawIssuer)] {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].cert.NotBefore.After(out[j].cert.NotBefore) })
	return out
}

// deviceProof is the engine's DeviceProof hook (runs in the SYSTEM service).
func (a *agentService) deviceProof(ctx context.Context, ch clientapi.Challenge) ([]clientapi.DeviceProof, *clientapi.JoinInfo) {
	join := joinInfo(ctx)
	certs, free, err := openCerts(true)
	defer free()
	if err != nil {
		a.log.Warn("device proof", "err", err)
		return nil, join
	}
	var out []clientapi.DeviceProof
	if ch.Entra {
		for _, s := range certs {
			c := s.cert
			if !strings.Contains(c.Issuer.CommonName, entraDeviceIssuer) || !validNow(c) {
				continue
			}
			if join != nil && join.DeviceID != "" && !strings.EqualFold(c.Subject.CommonName, join.DeviceID) {
				continue
			}
			p, err := signProof(s, ch.Nonce, "entra_device", true)
			if err != nil {
				a.log.Warn("entra device proof", "cert", c.Subject.CommonName, "err", err)
				continue
			}
			out = append(out, p)
			break
		}
	}
	if ch.DeviceCert {
		// Send every candidate that signs; the server accepts the first that passes.
		pin := deviceCertPin()
		list, pinned := pick(certs, deviceRule(ch), pin)
		if pin != "" && !pinned {
			a.log.Warn("the chosen device certificate is missing or expired; choosing automatically", "thumbprint", pin)
		}
		for _, s := range list {
			p, err := signProof(s, ch.Nonce, "device_cert", true)
			if err != nil {
				a.log.Warn("device certificate proof", "cert", s.cert.Subject.String(), "err", err)
				continue
			}
			out = append(out, p)
		}
	}
	return out, join
}

// userProof signs with a certificate from the user's own store. It runs in
// the GUI (as the user); the service can't reach the user's keys.
func userProof(ch clientapi.Challenge) []clientapi.DeviceProof {
	if !ch.UserCert || ch.Nonce == "" {
		return nil
	}
	certs, free, err := openCerts(false)
	defer free()
	if err != nil {
		return nil
	}
	list, pinned := pick(certs, userRule(ch), userCertPin())
	if pinned { // the user chose this one: allow a PIN or smart card prompt
		if p, err := signProof(list[0], ch.Nonce, "user_cert", false); err == nil {
			return []clientapi.DeviceProof{p}
		}
		return nil
	}
	// Automatic: sign silently with each candidate, so there's at most one
	// prompt; only if none can sign silently, try the newest with a prompt.
	var out []clientapi.DeviceProof
	for _, s := range list {
		if p, err := signProof(s, ch.Nonce, "user_cert", true); err == nil {
			out = append(out, p)
		}
	}
	if len(out) == 0 && len(list) > 0 {
		if p, err := signProof(list[0], ch.Nonce, "user_cert", false); err == nil {
			out = append(out, p)
		}
	}
	return out
}

var (
	joinMu   sync.Mutex
	joinAt   time.Time
	joinLast *clientapi.JoinInfo
)

// joinInfo reads "dsregcmd /status" (cached for 10 minutes).
func joinInfo(ctx context.Context) *clientapi.JoinInfo {
	joinMu.Lock()
	defer joinMu.Unlock()
	if !joinAt.IsZero() && time.Since(joinAt) < 10*time.Minute {
		return joinLast
	}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "dsregcmd.exe"), "/status")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	joinAt = time.Now()
	if err != nil {
		joinLast = nil
		return nil
	}
	joinLast = parseDsreg(string(out))
	if joinLast.DomainJoined {
		// The AD DNS domain is the primary DNS suffix of a domain-joined PC.
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, registry.QUERY_VALUE); err == nil {
			if v, _, err := k.GetStringValue("Domain"); err == nil {
				joinLast.ADDomain = strings.ToLower(strings.TrimSpace(v))
			}
			k.Close()
		}
	}
	return joinLast
}

func parseDsreg(s string) *clientapi.JoinInfo {
	j := &clientapi.JoinInfo{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		yes := strings.EqualFold(v, "YES")
		switch k {
		case "AzureAdJoined":
			j.EntraJoined = yes
		case "DomainJoined":
			j.DomainJoined = yes
		case "WorkplaceJoined":
			j.WorkplaceJoined = j.WorkplaceJoined || yes
		case "DeviceId":
			if j.DeviceID == "" {
				j.DeviceID = strings.ToLower(v)
			}
		case "DomainName":
			if j.ADNetBIOS == "" {
				j.ADNetBIOS = v
			}
		case "TenantId":
			if j.TenantID == "" {
				j.TenantID = strings.ToLower(v)
			}
		}
	}
	return j
}
