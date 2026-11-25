package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const tid = "11111111-2222-3333-4444-555555555555"

type staticKeys map[string]*rsa.PublicKey

func (s staticKeys) Key(_ context.Context, kid string) (*rsa.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

func fixture(t *testing.T) (*Validator, *rsa.PrivateKey, time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	v := NewValidator(Config{
		TenantID:        tid,
		Audiences:       []string{"api://securetunnel"},
		RequiredScope:   "access_as_user",
		RequireMFA:      true,
		MaxAuthAge:      10 * time.Minute,
		RequireAuthTime: true,
	}, staticKeys{"k1": &key.PublicKey}, func() time.Time { return now })
	return v, key, now
}

func goodClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":                "https://login.microsoftonline.com/" + tid + "/v2.0",
		"aud":                "api://securetunnel",
		"tid":                tid,
		"oid":                "user-oid",
		"preferred_username": "user@example.com",
		"scp":                "access_as_user",
		"amr":                []string{"pwd", "mfa"},
		"auth_time":          now.Add(-1 * time.Minute).Unix(),
		"iat":                now.Add(-1 * time.Minute).Unix(),
		"nbf":                now.Add(-1 * time.Minute).Unix(),
		"exp":                now.Add(time.Hour).Unix(),
	}
}

func sign(t *testing.T, key *rsa.PrivateKey, kid string, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestValidToken(t *testing.T) {
	v, key, now := fixture(t)
	id, err := v.Validate(context.Background(), sign(t, key, "k1", goodClaims(now)))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if id.UserOID != "user-oid" || id.UPN != "user@example.com" {
		t.Errorf("identity = %+v", id)
	}
}

func TestRejections(t *testing.T) {
	v, key, now := fixture(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
		key    *rsa.PrivateKey
		kid    string
		want   error
	}{
		{"no mfa", func(c jwt.MapClaims) { c["amr"] = []string{"pwd"} }, key, "k1", ErrMFARequired},
		{"stale sign-in", func(c jwt.MapClaims) { c["auth_time"] = now.Add(-2 * time.Hour).Unix() }, key, "k1", ErrStaleAuth},
		{"no auth_time", func(c jwt.MapClaims) { delete(c, "auth_time") }, key, "k1", ErrStaleAuth},
		{"wrong tenant", func(c jwt.MapClaims) { c["tid"] = "other" }, key, "k1", ErrInvalidToken},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "api://other" }, key, "k1", ErrInvalidToken},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "https://evil.example.com/" }, key, "k1", ErrInvalidToken},
		{"missing scope", func(c jwt.MapClaims) { c["scp"] = "User.Read" }, key, "k1", ErrInvalidToken},
		{"expired", func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() }, key, "k1", ErrInvalidToken},
		{"no oid", func(c jwt.MapClaims) { delete(c, "oid") }, key, "k1", ErrInvalidToken},
		{"wrong signing key", func(jwt.MapClaims) {}, other, "k1", ErrInvalidToken},
		{"unknown kid", func(jwt.MapClaims) {}, key, "k9", ErrInvalidToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goodClaims(now)
			tc.mutate(c)
			_, err := v.Validate(context.Background(), sign(t, tc.key, tc.kid, c))
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestV1IssuerAccepted(t *testing.T) {
	v, key, now := fixture(t)
	c := goodClaims(now)
	c["iss"] = "https://sts.windows.net/" + tid + "/"
	if _, err := v.Validate(context.Background(), sign(t, key, "k1", c)); err != nil {
		t.Errorf("v1 issuer rejected: %v", err)
	}
}

func TestAlgNoneRejected(t *testing.T) {
	v, _, now := fixture(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, goodClaims(now))
	tok.Header["kid"] = "k1"
	s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := v.Validate(context.Background(), s); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("alg=none accepted: %v", err)
	}
}
