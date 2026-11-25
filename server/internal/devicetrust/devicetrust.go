// Package devicetrust checks the PC behind a connect request: its Entra
// device identity (proven with the Entra device certificate), join type and
// Intune compliance from Microsoft Graph, and optional device/user
// certificates from your own CAs. See model.DeviceTrustPolicy.
package devicetrust

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // Windows certificate thumbprints are SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

const policyKey = "device_trust_policy"

// Checker issues challenges and evaluates device proofs.
type Checker struct {
	Store store.Store
	Graph *Graph  // nil: no Graph lookups
	Key   []byte  // HMAC key for challenges
	Now   func() time.Time
	// CertWants says whether any policy group needs device / user
	// certificates, so the agent knows what to sign (nil: from the policy).
	CertWants func(ctx context.Context) (device, user bool)
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Policy returns the saved policy (everything off if none).
func (c *Checker) Policy(ctx context.Context) model.DeviceTrustPolicy {
	p := model.DeviceTrustPolicy{CertMode: model.CertOff}
	_, _ = c.Store.GetSetting(ctx, policyKey, &p)
	if p.CertMode == "" {
		p.CertMode = model.CertOff
	}
	return p
}

// SavePolicy validates and stores the policy.
func (c *Checker) SavePolicy(ctx context.Context, p model.DeviceTrustPolicy) (model.DeviceTrustPolicy, error) {
	if _, err := p.Normalize(); err != nil {
		return p, err
	}
	return p, c.Store.SetSetting(ctx, policyKey, p)
}

// Challenge is what the agent signs, plus hints about which proofs to send.
type Challenge struct {
	Nonce      string    `json:"nonce"`
	ExpiresAt  time.Time `json:"expires_at"`
	Entra      bool      `json:"entra_device"` // send the Entra device certificate proof
	DeviceCert bool      `json:"device_cert"`
	UserCert   bool      `json:"user_cert"`
	// Issuers of acceptable device/user certificates (base64 DER subject names).
	Issuers []string `json:"issuers,omitempty"`
	// Name rules the certificates must match (see model.CertNameAllowed).
	DeviceNames []string `json:"device_names,omitempty"`
	UserNames   []string `json:"user_names,omitempty"`
}

// nameRuleError explains a certificate that fails the name rule.
func nameRuleError(c *x509.Certificate, user bool, patterns []string) string {
	names := model.CertNames(c, user)
	got := "no name"
	if len(names) > 0 {
		got = strings.Join(names, ", ")
	}
	return "its name (" + got + ") doesn't match the required pattern (" + strings.Join(patterns, " or ") + ")"
}

const nonceTTL = 5 * time.Minute

// NewChallenge returns a signed, self-expiring nonce (no server state, so it
// works across control servers).
func (c *Checker) NewChallenge(ctx context.Context) Challenge {
	p := c.Policy(ctx)
	b := make([]byte, 8+16)
	binary.BigEndian.PutUint64(b, uint64(c.now().Unix()))
	_, _ = rand.Read(b[8:])
	m := hmac.New(sha256.New, c.Key)
	m.Write(b)
	nonce := base64.RawURLEncoding.EncodeToString(append(b, m.Sum(nil)...))
	ch := Challenge{Nonce: nonce, ExpiresAt: c.now().Add(nonceTTL),
		DeviceCert: p.WantsDeviceCert(), UserCert: p.WantsUserCert(),
		DeviceNames: p.DeviceNamePatterns, UserNames: p.UserNamePatterns}
	if c.CertWants != nil {
		ch.DeviceCert, ch.UserCert = c.CertWants(ctx)
	}
	if cas, err := model.ParseCAs(p.TrustedCAs); err == nil {
		for _, ca := range cas {
			ch.Issuers = append(ch.Issuers, base64.StdEncoding.EncodeToString(ca.RawSubject))
		}
	}
	return ch
}

func (c *Checker) nonceOK(nonce string) bool {
	b, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(b) != 8+16+32 {
		return false
	}
	m := hmac.New(sha256.New, c.Key)
	m.Write(b[:24])
	if !hmac.Equal(m.Sum(nil), b[24:]) {
		return false
	}
	at := time.Unix(int64(binary.BigEndian.Uint64(b[:8])), 0)
	age := c.now().Sub(at)
	return age >= -time.Minute && age <= nonceTTL
}

// Input is one connect attempt.
type Input struct {
	DeviceID   string // machine ID (our device record)
	DeviceName string // computer name
	UPN        string
	Nonce      string
	Proofs     []model.DeviceProof
	Join       *model.JoinInfo
	Group      string // policy group name, recorded with the result
	// RequireName: the device certificate must name this computer even when
	// the policy doesn't ask for it (the pre-logon device tunnel always does).
	RequireName bool
}

// ErrUntrusted means the device trust policy blocks this connect.
type ErrUntrusted struct{ Problems []string }

func (e *ErrUntrusted) Error() string { return strings.Join(e.Problems, "; ") }

// Evaluate checks the proofs and the policy. It always returns the trust
// result (to store and show); err is *ErrUntrusted when the policy blocks it.
func (c *Checker) Evaluate(ctx context.Context, in Input, req model.TrustRequirements) (model.DeviceTrust, error) {
	pol := c.Policy(ctx)
	t := model.DeviceTrust{CheckedAt: c.now(), User: strings.ToLower(in.UPN), Group: in.Group}
	nonceOK := in.Nonce != "" && c.nonceOK(in.Nonce)

	var cas []*x509.Certificate
	cas, _ = model.ParseCAs(pol.TrustedCAs)
	vars := model.NameVars{Hostname: in.DeviceName, UPN: in.UPN}

	for _, p := range in.Proofs {
		leaf, chain, err := parseChain(p.Chain)
		if err != nil {
			continue
		}
		info := &model.CertInfo{Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
			Thumbprint: thumbprint(leaf), NotAfter: leaf.NotAfter}
		sigErr := errors.New("the challenge had expired")
		if nonceOK {
			sigErr = verifySig(leaf, p.Alg, p.Sig, model.ProofMessage(in.Nonce, p.Kind))
		}
		switch p.Kind {
		case "device_cert":
			if t.DeviceCert == nil || !t.DeviceCert.OK {
				info.OK, info.Error = checkCert(leaf, chain, cas, sigErr, c.now())
				if info.OK && (pol.MatchDeviceName || in.RequireName) && !nameMatches(leaf, in.DeviceName) {
					info.OK, info.Error = false, "the certificate isn't for this computer ("+in.DeviceName+")"
				}
				if info.OK && !model.CertNameAllowed(leaf, false, pol.DeviceNamePatterns, vars) {
					info.OK, info.Error = false, nameRuleError(leaf, false, pol.DeviceNamePatterns)
				}
				t.DeviceCert = info
			}
		case "user_cert":
			if t.UserCert == nil || !t.UserCert.OK {
				info.OK, info.Error = checkCert(leaf, chain, cas, sigErr, c.now())
				if info.OK && pol.MatchUser && !userMatches(leaf, in.UPN) {
					info.OK, info.Error = false, "the certificate isn't for "+in.UPN
				}
				if info.OK && !model.CertNameAllowed(leaf, true, pol.UserNamePatterns, vars) {
					info.OK, info.Error = false, nameRuleError(leaf, true, pol.UserNamePatterns)
				}
				t.UserCert = info
			}
		}
	}

	// Policy: only certificates. Join type, compliance and domain are left to
	// Entra (Conditional Access).
	var problems []string
	devOK := t.DeviceCert != nil && t.DeviceCert.OK
	userOK := t.UserCert != nil && t.UserCert.OK
	certProblem := func(kind string, ci *model.CertInfo) string {
		if ci == nil {
			return "No valid " + kind + " certificate was found on this PC."
		}
		return "The " + kind + " certificate wasn't accepted: " + ci.Error + "."
	}
	switch req.CertMode {
	case model.CertDevice:
		if !devOK {
			problems = append(problems, certProblem("device", t.DeviceCert))
		}
	case model.CertUser:
		if !userOK {
			problems = append(problems, certProblem("user", t.UserCert))
		}
	case model.CertEither:
		if !devOK && !userOK {
			problems = append(problems, "No valid device or user certificate was found on this PC.")
		}
	case model.CertBoth:
		if !devOK {
			problems = append(problems, certProblem("device", t.DeviceCert))
		}
		if !userOK {
			problems = append(problems, certProblem("user", t.UserCert))
		}
	}
	t.Problems = problems
	t.Passed = len(problems) == 0
	if !t.Passed {
		return t, &ErrUntrusted{Problems: problems}
	}
	return t, nil
}

func parseChain(chain []string) (*x509.Certificate, []*x509.Certificate, error) {
	if len(chain) == 0 || len(chain) > 5 {
		return nil, nil, errors.New("bad chain")
	}
	var certs []*x509.Certificate
	for _, s := range chain {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(der) > 16<<10 {
			return nil, nil, errors.New("bad certificate")
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, c)
	}
	return certs[0], certs[1:], nil
}

func thumbprint(c *x509.Certificate) string {
	s := sha1.Sum(c.Raw) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(s[:]))
}

func verifySig(leaf *x509.Certificate, alg, sigB64 string, msg []byte) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return errors.New("bad signature encoding")
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return errors.New("unexpected signature algorithm")
		}
		h := sha256.Sum256(msg)
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) != nil {
			return errors.New("the signature didn't verify")
		}
		return nil
	case *ecdsa.PublicKey:
		var h []byte
		switch alg {
		case "ES256":
			s := sha256.Sum256(msg)
			h = s[:]
		case "ES384":
			s := sha512.Sum384(msg)
			h = s[:]
		default:
			return errors.New("unexpected signature algorithm")
		}
		if len(sig)%2 != 0 || len(sig) == 0 {
			return errors.New("bad signature")
		}
		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])
		if !ecdsa.Verify(pub, h, r, s) {
			return errors.New("the signature didn't verify")
		}
		return nil
	}
	return errors.New("unsupported key type")
}

// checkCert verifies a device/user certificate against the trusted CAs.
func checkCert(leaf *x509.Certificate, intermediates, cas []*x509.Certificate, sigErr error, now time.Time) (bool, string) {
	if sigErr != nil {
		return false, sigErr.Error()
	}
	if len(cas) == 0 {
		return false, "no trusted CAs are set up"
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, ca := range cas {
		roots.AddCert(ca) // issuing CAs count as trust anchors too
	}
	for _, c := range intermediates {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		var inv x509.CertificateInvalidError
		switch {
		case errors.As(err, &inv) && inv.Reason == x509.Expired:
			return false, "it expired on " + leaf.NotAfter.Format("Jan 2, 2006")
		case errors.As(err, &inv) && inv.Reason == x509.IncompatibleUsage:
			return false, "it isn't for client authentication"
		}
		var ua x509.UnknownAuthorityError
		if errors.As(err, &ua) {
			return false, "it isn't issued by a trusted CA"
		}
		return false, fmt.Sprint(err)
	}
	return true, ""
}

func nameMatches(c *x509.Certificate, computer string) bool {
	computer = strings.ToLower(strings.TrimSpace(computer))
	if computer == "" {
		return false
	}
	first := func(s string) string {
		s = strings.ToLower(s)
		if i := strings.IndexByte(s, '.'); i > 0 {
			return s[:i]
		}
		return s
	}
	if first(c.Subject.CommonName) == computer {
		return true
	}
	for _, d := range c.DNSNames {
		if first(d) == computer {
			return true
		}
	}
	return false
}

// userMatches checks the UPN (SAN otherName 1.3.6.1.4.1.311.20.2.3), email
// SANs and the subject CN against the signed-in user.
func userMatches(c *x509.Certificate, upn string) bool {
	upn = strings.ToLower(strings.TrimSpace(upn))
	if upn == "" {
		return false
	}
	for _, e := range c.EmailAddresses {
		if strings.ToLower(e) == upn {
			return true
		}
	}
	for _, u := range sanUPNs(c) {
		if strings.ToLower(u) == upn {
			return true
		}
	}
	return strings.ToLower(c.Subject.CommonName) == upn
}
