package realip

import (
	"net/http/httptest"
	"testing"
)

func TestCountry(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-IPCountry", "fr")
	r.RemoteAddr = "172.20.0.1:1"
	if got := Country(r); got != "FR" {
		t.Errorf("via local proxy: %q, want FR", got)
	}
	r.RemoteAddr = "203.0.113.9:1"
	if got := Country(r); got != "" {
		t.Errorf("direct client faking the header: %q, want empty", got)
	}
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("CF-IPCountry", "XX")
	if got := Country(r); got != "" {
		t.Errorf("unknown: %q, want empty", got)
	}
}

func TestFrom(t *testing.T) {
	cases := []struct {
		name, remote, cf, xff, want string
	}{
		{"direct client, no headers", "203.0.113.9:5000", "", "", "203.0.113.9"},
		{"direct client faking the header", "203.0.113.9:5000", "1.2.3.4", "", "203.0.113.9"},
		{"cloudflared via docker bridge", "172.20.0.1:40000", "47.32.2.7", "", "47.32.2.7"},
		{"cloudflared via loopback", "127.0.0.1:40000", "47.32.2.7", "", "47.32.2.7"},
		{"local proxy with x-forwarded-for", "10.0.0.5:1", "", "47.32.2.7, 10.0.0.1", "47.32.2.7"},
		{"local proxy with garbage header", "172.20.0.1:1", "not-an-ip", "", "172.20.0.1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.cf != "" {
			r.Header.Set("CF-Connecting-IP", c.cf)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := From(r); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}
