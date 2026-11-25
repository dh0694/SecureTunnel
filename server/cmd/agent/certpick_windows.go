//go:build windows

package main

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/model"
)

// Certificate choice: by default the app picks certificates itself (the
// newest few that fit); in Settings the user can pin one instead. Device
// certificate choice lives in HKLM (set through the service), user
// certificate choice in the user's own HKCU.

const (
	deviceCertValue = "DeviceCertThumbprint" // HKLM\SOFTWARE\SecureTunnel
	userCertValue   = "UserCertThumbprint"   // HKCU\Software\SecureTunnel
	maxAutoCerts    = 3
)

// certChoice describes one certificate for the Settings picker.
type certChoice struct {
	Thumb    string    `json:"thumb"`
	Name     string    `json:"name"`
	Issuer   string    `json:"issuer"`
	NotAfter time.Time `json:"not_after"`
	Usable   bool      `json:"usable"`
	Why      string    `json:"why,omitempty"` // why it can't be used
}

// certList is what the picker shows for one store.
type certList struct {
	Certs  []certChoice `json:"certs"`
	Pinned string       `json:"pinned,omitempty"` // "" = automatic
	Auto   []string     `json:"auto,omitempty"`   // what automatic would try, in order
}

func certThumb(raw []byte) string {
	h := sha1.Sum(raw)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

func certName(s storeCert) string {
	c := s.cert
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	for _, e := range c.EmailAddresses {
		return e
	}
	return c.Subject.String()
}

func issuerSet(issuers []string) map[string]bool {
	want := map[string]bool{}
	for _, i := range issuers {
		if b, err := base64.StdEncoding.DecodeString(i); err == nil {
			want[string(b)] = true
		}
	}
	return want
}

// certRule is what the server accepts for one kind of certificate.
type certRule struct {
	Issuers []string       // acceptable issuers (empty: any)
	Names   []string       // name patterns (empty: any), see model.CertNameAllowed
	User    bool           // user certificate (match email/UPN) rather than device
	Vars    model.NameVars // what $hostname / $upn stand for here
}

func deviceRule(ch clientapi.Challenge) certRule {
	return certRule{Issuers: ch.Issuers, Names: ch.DeviceNames, Vars: model.NameVars{Hostname: deviceName()}}
}

func userRule(ch clientapi.Challenge) certRule {
	return certRule{Issuers: ch.Issuers, Names: ch.UserNames, User: true, Vars: model.NameVars{Hostname: deviceName(), UPN: currentUPN()}}
}

func (r certRule) nameOK(c *x509.Certificate) bool {
	return model.CertNameAllowed(c, r.User, r.Names, r.Vars)
}

// fitting returns the candidates whose names match the rule first, then the
// others (the server explains why those are turned down).
func fitting(list []storeCert, r certRule) []storeCert {
	var good, rest []storeCert
	for _, s := range candidates(list, r.Issuers) {
		if r.nameOK(s.cert) {
			good = append(good, s)
		} else {
			rest = append(rest, s)
		}
	}
	return append(good, rest...)
}

// currentUPN is the signed-in user's UPN (GUI process; "" for local accounts).
func currentUPN() string {
	buf := make([]uint16, 256)
	n := uint32(len(buf))
	if r, _, _ := procGetUserNameExW.Call(nameUserPrincipal, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// choices lists the store's certificates for the picker: usable ones first
// (newest first), then the rest with the reason they can't be used.
func choices(list []storeCert, r certRule, pinned string) certList {
	want := issuerSet(r.Issuers)
	out := certList{Pinned: pinned}
	for _, s := range list {
		c := s.cert
		if c.IsCA || strings.Contains(c.Issuer.CommonName, entraDeviceIssuer) {
			continue
		}
		ch := certChoice{Thumb: certThumb(c.Raw), Name: certName(s), Issuer: c.Issuer.CommonName, NotAfter: c.NotAfter, Usable: true}
		if ch.Issuer == "" {
			ch.Issuer = c.Issuer.String()
		}
		switch {
		case time.Now().After(c.NotAfter):
			ch.Usable, ch.Why = false, "Expired"
		case time.Now().Before(c.NotBefore):
			ch.Usable, ch.Why = false, "Not valid yet"
		case !clientAuth(c):
			ch.Usable, ch.Why = false, "Not for signing in"
		case len(want) > 0 && !want[string(c.RawIssuer)]:
			ch.Usable, ch.Why = false, "Not from a CA your organization accepts"
		case !r.nameOK(c):
			ch.Usable, ch.Why = false, "Name doesn't match "+strings.Join(r.Names, " or ")
		}
		out.Certs = append(out.Certs, ch)
	}
	sort.SliceStable(out.Certs, func(i, j int) bool {
		a, b := out.Certs[i], out.Certs[j]
		if a.Usable != b.Usable {
			return a.Usable
		}
		return a.NotAfter.After(b.NotAfter)
	})
	for i, s := range fitting(list, r) {
		if i == maxAutoCerts {
			break
		}
		out.Auto = append(out.Auto, certThumb(s.cert.Raw))
	}
	return out
}

// pick returns the certificates to try: the pinned one if it's still in the
// store and valid, otherwise the newest few that fit (pinned=false then).
func pick(list []storeCert, r certRule, pin string) (certs []storeCert, pinned bool) {
	if pin != "" {
		for _, s := range list {
			if strings.EqualFold(certThumb(s.cert.Raw), pin) && validNow(s.cert) {
				return []storeCert{s}, true
			}
		}
	}
	c := fitting(list, r)
	if len(c) > maxAutoCerts {
		c = c[:maxAutoCerts]
	}
	return c, false
}

func deviceCertPin() string { return readString(settingsKey, deviceCertValue) }

func setDeviceCertPin(thumb string) error {
	if thumb == "" {
		deleteValue(settingsKey, deviceCertValue)
		return nil
	}
	return writeString(settingsKey, deviceCertValue, strings.ToUpper(thumb))
}

func userCertPin() string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\SecureTunnel`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue(userCertValue)
	return v
}

func setUserCertPin(thumb string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, `Software\SecureTunnel`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if thumb == "" {
		if err := k.DeleteValue(userCertValue); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}
	return k.SetStringValue(userCertValue, strings.ToUpper(thumb))
}

func validThumb(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// certsForGUI gathers both lists and the server's requirements as JSON for
// the Settings page.
func certsForGUI() string {
	out := map[string]any{"ok": true}
	var ch clientapi.Challenge
	resp, err := pipeCall(ipcRequest{Cmd: "certs"}, 15*time.Second)
	switch {
	case err != nil:
		out["device_error"] = "The SecureTunnel service isn't running."
	case !resp.OK:
		out["device_error"] = resp.Error
	default:
		out["device"] = resp.Certs
		if resp.Challenge != nil {
			ch = *resp.Challenge
			out["wants_device"], out["wants_user"] = ch.DeviceCert, ch.UserCert
			out["known"] = true
		}
	}
	if certs, free, err := openCerts(false); err == nil {
		cl := choices(certs, userRule(ch), userCertPin())
		free()
		out["user"] = cl
	} else {
		out["user_error"] = err.Error()
	}
	b, _ := json.Marshal(out)
	return string(b)
}
