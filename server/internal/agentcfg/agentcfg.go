// Package agentcfg turns what an admin types for the server ("vpn.example.com",
// "172.234.204.252", "host:9443", "https://host/") into a control-server URL.
package agentcfg

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// DefaultIPPort is used for a bare IP address: the control server's own port.
// A bare host name uses 443, which suits a reverse proxy or Cloudflare Tunnel.
const DefaultIPPort = 8443

// NormalizeServer returns an https URL with no path, e.g. https://vpn.example.com.
func NormalizeServer(in string) (string, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return "", errors.New("enter the server's name or IP address")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", errors.New("that doesn't look like a server name or IP address")
	}
	if u.Scheme != "https" {
		return "", errors.New("the server address must use https")
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("enter just the server's name or IP address, without a path")
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" {
		return "", errors.New("that doesn't look like a server name or IP address")
	}
	if ip := net.ParseIP(host); ip == nil && !validHostname(host) {
		return "", errors.New("that doesn't look like a server name or IP address")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("the port must be between 1 and 65535")
		}
	} else if net.ParseIP(host) != nil {
		port = strconv.Itoa(DefaultIPPort)
	}
	h := host
	if strings.Contains(host, ":") { // IPv6 literal
		h = "[" + host + "]"
	}
	if port != "" && port != "443" {
		h += ":" + port
	}
	return "https://" + strings.ToLower(h), nil
}

// Host returns the host name or IP of a normalized server URL.
func Host(server string) string {
	u, err := url.Parse(server)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func validHostname(h string) bool {
	if len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
