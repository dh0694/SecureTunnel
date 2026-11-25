// Package realip finds a request's real client IP behind a reverse proxy.
//
// When the server sits behind Cloudflare Tunnel (cloudflared on the same
// host), every request arrives from a local or Docker-internal address and the
// real client IP is in the CF-Connecting-IP header (or X-Forwarded-For). Those
// headers are only believed when the request comes from such a local address:
// a client connecting to the server directly can't fake its IP with them.
package realip

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// From returns the client IP for r.
func From(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !trustedProxy(peer) {
		return host
	}
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); valid(v) {
		return v
	}
	// X-Forwarded-For: the left-most entry is the original client.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first := strings.TrimSpace(strings.Split(xff, ",")[0]); valid(first) {
			return first
		}
	}
	return host
}

// Country returns the ISO country Cloudflare detected for the client
// (CF-IPCountry), only when the request came through a trusted local proxy.
// It returns "" when unknown.
func Country(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !trustedProxy(peer) {
		return ""
	}
	c := strings.ToUpper(strings.TrimSpace(r.Header.Get("CF-IPCountry")))
	if len(c) != 2 || c == "XX" || c == "T1" {
		return ""
	}
	return c
}

// trustedProxy: loopback or private (Docker bridge, LAN) addresses, where a
// local reverse proxy such as cloudflared would connect from.
func trustedProxy(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLoopback() || a.IsPrivate()
}

func valid(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}
