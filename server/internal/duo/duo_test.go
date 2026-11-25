package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"time"

	"securetunnel/server/internal/store"
)

func TestCanonicalAndSignature(t *testing.T) {
	p := url.Values{"username": {"jane doe"}, "factor": {"auto"}, "a~b": {"x*y"}}
	if got, want := canonParams(p), "a~b=x%2Ay&factor=auto&username=jane%20doe"; got != want {
		t.Fatalf("canon = %q, want %q", got, want)
	}
	s := Settings{APIHost: "api-abc123.duosecurity.com", IntegrationKey: "DIWJ8X6AEYOR5OMC6TQ1", SecretKey: "secret"}
	date := "Tue, 21 Aug 2012 17:29:18 -0000"
	got := sign(s, "post", "/auth/v2/auth", date, p)
	m := hmac.New(sha512.New, []byte("secret"))
	m.Write([]byte(date + "\nPOST\napi-abc123.duosecurity.com\n/auth/v2/auth\n" + canonParams(p)))
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(s.IntegrationKey+":"+hex.EncodeToString(m.Sum(nil))))
	if got != want {
		t.Fatal("signature mismatch")
	}
}

func TestSettings(t *testing.T) {
	s := Settings{APIHost: "https://API-abc123.duosecurity.com/", IntegrationKey: "diwj8x6aeyor5omc6tq1"}
	if err := s.Normalize(); err != nil {
		t.Fatal(err)
	}
	if s.APIHost != "api-abc123.duosecurity.com" || s.IntegrationKey != "DIWJ8X6AEYOR5OMC6TQ1" || s.UsernameFormat != "upn" {
		t.Fatalf("%+v", s)
	}
	if err := (&Settings{APIHost: "evil.example.com", IntegrationKey: "DIWJ8X6AEYOR5OMC6TQ1"}).Normalize(); err == nil {
		t.Fatal("non-Duo host accepted")
	}
	s.UsernameFormat = "prefix"
	if s.Username("Jane.Doe@Contoso.com") != "jane.doe" {
		t.Fatal("prefix mapping")
	}
	d := &Service{Store: store.NewMemory()}
	ctx := context.Background()
	if _, err := d.Save(ctx, Settings{APIHost: "api-abc123.duosecurity.com", IntegrationKey: "DIWJ8X6AEYOR5OMC6TQ1"}); err == nil {
		t.Fatal("saved without a secret")
	}
	if _, err := d.Save(ctx, Settings{APIHost: "api-abc123.duosecurity.com", IntegrationKey: "DIWJ8X6AEYOR5OMC6TQ1", SecretKey: "k"}); err != nil {
		t.Fatal(err)
	}
	// An empty secret keeps the saved one.
	if _, err := d.Save(ctx, Settings{APIHost: "api-abc123.duosecurity.com", IntegrationKey: "DIWJ8X6AEYOR5OMC6TQ1"}); err != nil || !d.Settings(ctx).Ready() {
		t.Fatalf("secret not kept: %v", err)
	}
}

func TestTxToken(t *testing.T) {
	d := &Service{Key: []byte("k")}
	tok := d.Token("tx1", "Jane@Contoso.com")
	tx, u, ok := d.ParseToken(tok)
	if !ok || tx != "tx1" || u != "jane@contoso.com" {
		t.Fatalf("%v %v %v", tx, u, ok)
	}
	if _, _, ok := d.ParseToken("x" + strings.TrimPrefix(tok, tok[:1])); ok {
		t.Fatal("tampered token accepted")
	}
	d.Now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	if _, _, ok := d.ParseToken(tok); ok {
		t.Fatal("expired token accepted")
	}
	if !d.Use("tx1") || d.Use("tx1") {
		t.Fatal("a transaction must be usable once")
	}
}
