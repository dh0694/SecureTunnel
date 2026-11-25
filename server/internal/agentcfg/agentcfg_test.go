package agentcfg

import "testing"

func TestNormalizeServer(t *testing.T) {
	ok := map[string]string{
		"vpn.example.com":                 "https://vpn.example.com",
		"  VPN.Example.com  ":             "https://vpn.example.com",
		"https://vpn.example.com/":        "https://vpn.example.com",
		"vpn.example.com:443":             "https://vpn.example.com",
		"vpn.example.com:9443":            "https://vpn.example.com:9443",
		"172.234.204.252":                 "https://172.234.204.252:8443",
		"172.234.204.252:8443":            "https://172.234.204.252:8443",
		"https://172.234.204.252:443":     "https://172.234.204.252",
		"[2001:db8::1]":                   "https://[2001:db8::1]:8443",
		"vpn.cott1nghambutler.com":        "https://vpn.cott1nghambutler.com",
	}
	for in, want := range ok {
		got, err := NormalizeServer(in)
		if err != nil || got != want {
			t.Errorf("NormalizeServer(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "http://vpn.example.com", "vpn.example.com/path", "user@vpn.example.com", "bad host", "vpn.example.com:99999", "-bad.example.com"} {
		if got, err := NormalizeServer(bad); err == nil {
			t.Errorf("NormalizeServer(%q) = %q, want an error", bad, got)
		}
	}
}

func TestHost(t *testing.T) {
	if h := Host("https://172.234.204.252:8443"); h != "172.234.204.252" {
		t.Errorf("Host = %q", h)
	}
	if h := Host("https://vpn.example.com"); h != "vpn.example.com" {
		t.Errorf("Host = %q", h)
	}
}
