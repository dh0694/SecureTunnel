package devicetrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"crypto"

	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

type pki struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  string
}

func newPKI(t *testing.T) pki {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Contoso Issuing CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return pki{caCert: c, caKey: key, caPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (p pki) leaf(t *testing.T, cn string, dns, emails []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: dns, EmailAddresses: emails,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key
}

func esProof(t *testing.T, c *x509.Certificate, key *ecdsa.PrivateKey, nonce, kind string) model.DeviceProof {
	h := sha256.Sum256(model.ProofMessage(nonce, kind))
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return model.DeviceProof{Kind: kind, Alg: "ES256", Sig: base64.StdEncoding.EncodeToString(sig),
		Chain: []string{base64.StdEncoding.EncodeToString(c.Raw)}}
}

func newChecker(t *testing.T, pol model.DeviceTrustPolicy) *Checker {
	c := &Checker{Store: store.NewMemory(), Key: []byte("k")}
	if _, err := c.SavePolicy(context.Background(), pol); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDeviceCertificate(t *testing.T) {
	ctx := context.Background()
	p := newPKI(t)
	c := newChecker(t, model.DeviceTrustPolicy{CertMode: model.CertDevice, TrustedCAs: p.caPEM, MatchDeviceName: true})
	ch := c.NewChallenge(ctx)
	if !ch.DeviceCert || ch.UserCert || len(ch.Issuers) != 1 {
		t.Fatalf("challenge = %+v", ch)
	}
	leaf, key := p.leaf(t, "LT-4100.contoso.com", nil, nil)
	in := Input{DeviceID: "m1", DeviceName: "LT-4100", UPN: "jane@contoso.com", Nonce: ch.Nonce,
		Proofs: []model.DeviceProof{esProof(t, leaf, key, ch.Nonce, "device_cert")}}
	tr, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertDevice})
	if err != nil || !tr.Passed || tr.DeviceCert == nil || !tr.DeviceCert.OK {
		t.Fatalf("good cert: err=%v trust=%+v cert=%+v", err, tr, tr.DeviceCert)
	}

	// Wrong computer name.
	in.DeviceName = "OTHER-PC"
	if _, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertDevice}); err == nil {
		t.Fatal("name mismatch accepted")
	}
	in.DeviceName = "LT-4100"

	// Signature over a different nonce.
	ch2 := c.NewChallenge(ctx)
	in2 := in
	in2.Nonce = ch2.Nonce
	if _, err := c.Evaluate(ctx, in2, model.TrustRequirements{CertMode: model.CertDevice}); err == nil {
		t.Fatal("signature for another nonce accepted")
	}

	// Forged nonce.
	in3 := in
	in3.Nonce = strings.Repeat("A", len(in.Nonce))
	if _, err := c.Evaluate(ctx, in3, model.TrustRequirements{CertMode: model.CertDevice}); err == nil {
		t.Fatal("forged nonce accepted")
	}

	// Expired challenge.
	c.Now = func() time.Time { return time.Now().Add(10 * time.Minute) }
	if _, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertDevice}); err == nil {
		t.Fatal("expired challenge accepted")
	}
	c.Now = nil

	// Certificate from another CA.
	other := newPKI(t)
	ol, ok := other.leaf(t, "LT-4100", nil, nil)
	in.Proofs = []model.DeviceProof{esProof(t, ol, ok, ch.Nonce, "device_cert")}
	if tr, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertDevice}); err == nil || tr.DeviceCert.Error == "" {
		t.Fatalf("untrusted CA accepted: %+v", tr.DeviceCert)
	}

	// No certificate at all.
	in.Proofs = nil
	if _, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertDevice}); err == nil {
		t.Fatal("missing certificate accepted")
	}
}

func TestUserCertificateEither(t *testing.T) {
	ctx := context.Background()
	p := newPKI(t)
	c := newChecker(t, model.DeviceTrustPolicy{CertMode: model.CertEither, TrustedCAs: p.caPEM, MatchUser: true})
	ch := c.NewChallenge(ctx)
	leaf, key := p.leaf(t, "Jane Smith", nil, []string{"Jane@Contoso.com"})
	in := Input{DeviceID: "m1", DeviceName: "PC", UPN: "jane@contoso.com", Nonce: ch.Nonce,
		Proofs: []model.DeviceProof{esProof(t, leaf, key, ch.Nonce, "user_cert")}}
	if tr, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertEither}); err != nil || !tr.UserCert.OK {
		t.Fatalf("user cert: %v %+v", err, tr.UserCert)
	}
	in.UPN = "bob@contoso.com"
	if _, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertEither}); err == nil {
		t.Fatal("someone else's user certificate accepted")
	}
	// A device proof signed as "user_cert" can't be replayed as "device_cert".
	in.UPN = "jane@contoso.com"
	in.Proofs[0].Kind = "device_cert"
	if _, err := c.Evaluate(ctx, in, model.TrustRequirements{CertMode: model.CertEither}); err == nil {
		t.Fatal("proof replayed as another kind")
	}
}


func TestMonitoringOnlyNeverBlocks(t *testing.T) {
	c := newChecker(t, model.DeviceTrustPolicy{})
	tr, err := c.Evaluate(context.Background(), Input{DeviceID: "m1", UPN: "u"}, model.TrustRequirements{})
	if err != nil || !tr.Passed {
		t.Fatalf("%v %+v", err, tr)
	}
}

func TestPolicyValidation(t *testing.T) {
	c := &Checker{Store: store.NewMemory(), Key: []byte("k")}
	if _, err := c.SavePolicy(context.Background(), model.DeviceTrustPolicy{CertMode: model.CertDevice}); err == nil {
		t.Fatal("certificate mode without CAs accepted")
	}
	if _, err := c.SavePolicy(context.Background(), model.DeviceTrustPolicy{CertMode: "bogus"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := c.SavePolicy(context.Background(), model.DeviceTrustPolicy{TrustedCAs: "not pem"}); err == nil {
		t.Fatal("bad PEM accepted")
	}
}

func TestKeyMatches(t *testing.T) {
	s := "X509:<SHA1-TP-PUBKEY>3F2A9C51D07E44B8A1C6E2F90B13D7A58C4E61F2abcdef=="
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, v := range u {
		b[2*i], b[2*i+1] = byte(v), byte(v>>8)
	}
	d := &GraphDevice{}
	d.AltSecIDs = append(d.AltSecIDs, struct {
		Type int    `json:"type"`
		Key  string `json:"key"`
	}{2, base64.StdEncoding.EncodeToString(b)})
	if m, ok := d.KeyMatches("3f2a9c51d07e44b8a1c6e2f90b13d7a58c4e61f2"); !m || !ok {
		t.Fatal("registered key not matched")
	}
	if m, ok := d.KeyMatches("0000000000000000000000000000000000000000"); m || !ok {
		t.Fatal("other key matched")
	}
}

func TestRSASignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	msg := model.ProofMessage("n", "device_cert")
	h := sha256.Sum256(msg)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err := verifySig(c, "RS256", base64.StdEncoding.EncodeToString(sig), msg); err != nil {
		t.Fatal(err)
	}
	if err := verifySig(c, "RS256", base64.StdEncoding.EncodeToString(sig), []byte("other")); err == nil {
		t.Fatal("bad signature accepted")
	}
}
