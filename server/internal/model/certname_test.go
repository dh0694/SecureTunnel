package model

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
)

func TestNamePatterns(t *testing.T) {
	v := NameVars{Hostname: "LAPTOP-7Q2", UPN: "JSmith@cb-sisco.com"}
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"$hostname.cb-sisco.com", "laptop-7q2.cb-sisco.com", true},
		{"$hostname.cb-sisco.com", "LAPTOP-7Q2.CB-SISCO.COM", true},
		{"$hostname.cb-sisco.com", "other-pc.cb-sisco.com", false},
		{"$hostname.cb-sisco.com", "laptop-7q2xcb-sisco.com", false}, // dots are literal
		{"*.cb-sisco.com", "anything.cb-sisco.com", true},
		{"*.cb-sisco.com", "pc.sub.cb-sisco.com", true},
		{"*.cb-sisco.com", "cb-sisco.com.evil.com", false},
		{"$upn", "jsmith@cb-sisco.com", true},
		{"$user@*", "jsmith@contoso.com", true},
		{"$upn", "adoe@cb-sisco.com", false},
	}
	for _, c := range cases {
		if got := patternMatches(c.pattern, c.name, v); got != c.want {
			t.Errorf("%q vs %q = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
	if patternMatches("$hostname.x.com", "pc.x.com", NameVars{}) {
		t.Error("an unknown hostname must not match")
	}
}

func TestNormalizeNamePatterns(t *testing.T) {
	got, err := NormalizeNamePatterns([]string{" $Hostname.CB-Sisco.com ", "", "*.cb-sisco.com", "*.cb-sisco.com"})
	if err != nil || len(got) != 2 || got[0] != "$hostname.cb-sisco.com" {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"*", "$computer.x.com", "a b.com", "*.*"} {
		if _, err := NormalizeNamePatterns([]string{bad}); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestCertNameAllowed(t *testing.T) {
	c := &x509.Certificate{Subject: pkix.Name{CommonName: "LAPTOP-7Q2"}, DNSNames: []string{"laptop-7q2.cb-sisco.com"}}
	v := NameVars{Hostname: "laptop-7q2"}
	if !CertNameAllowed(c, false, nil, v) {
		t.Error("no patterns allows everything")
	}
	if !CertNameAllowed(c, false, []string{"$hostname.cb-sisco.com"}, v) {
		t.Error("DNS name should match")
	}
	if CertNameAllowed(c, false, []string{"*.contoso.com"}, v) {
		t.Error("wrong domain should not match")
	}
}
