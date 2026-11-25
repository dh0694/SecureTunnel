package admin

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

// Gateway address ranges are edited on the Gateways page. gateways.json only
// seeds a new gateway's range; after that the admin site owns it.

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT space, often used for VPN pools
}

// homeRanges are what consumer routers commonly hand out.
var homeRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.1.0/24"),
	netip.MustParsePrefix("192.168.0.0/24"), netip.MustParsePrefix("192.168.1.0/24"),
}

// checkPool validates a new range for gateway id against the others. It
// returns an error for anything unusable and warnings for things to know.
func checkPool(id, text string, gws []model.Gateway, capacity int, office []string) (netip.Prefix, []string, error) {
	text = strings.TrimSpace(text)
	p, err := netip.ParsePrefix(text)
	if err != nil {
		return p, nil, fmt.Errorf("%q isn't a range; write it like 10.200.0.0/21", text)
	}
	if !p.Addr().Is4() {
		return p, nil, fmt.Errorf("use an IPv4 range")
	}
	if p != p.Masked() {
		return p, nil, fmt.Errorf("%s isn't the start of the range; did you mean %s?", text, p.Masked())
	}
	if p.Bits() < 16 || p.Bits() > 28 {
		return p, nil, fmt.Errorf("use a range between /16 (65,000 addresses) and /28 (13 addresses)")
	}
	private := false
	for _, r := range privateRanges {
		if r.Contains(p.Addr()) && r.Bits() <= p.Bits() {
			private = true
		}
	}
	if !private {
		return p, nil, fmt.Errorf("use a private range (10.x, 172.16–31.x, 192.168.x or 100.64–127.x)")
	}
	for _, g := range gws {
		if g.ID != id && g.Pool.IsValid() && g.Pool.Overlaps(p) {
			return p, nil, fmt.Errorf("%s overlaps %s's range (%s); each gateway needs its own", p, g.ID, g.Pool)
		}
	}
	var warn []string
	usable := (1 << (32 - p.Bits())) - 3 // network, broadcast and the gateway's own address
	if capacity > 0 && usable < capacity {
		warn = append(warn, fmt.Sprintf("%s has room for %d users, fewer than this gateway's limit of %d; it fills up first.", p, usable, capacity))
	}
	for _, s := range office {
		if o, err := netip.ParsePrefix(s); err == nil && o.Overlaps(p) {
			warn = append(warn, fmt.Sprintf("It overlaps the office subnet %s (Settings → Office networks).", o))
		}
	}
	for _, c := range homeRanges {
		if c.Overlaps(p) {
			warn = append(warn, "It overlaps a range home routers often use ("+c.String()+"); users on such networks may lose access to their local devices.")
			break
		}
	}
	return p, warn, nil
}

type poolRequest struct {
	Pool string `json:"pool"`
	// EndRemaining ends sessions still on the gateway (offline PCs in their
	// grace window, or older apps that can't be moved) so the change can go ahead.
	EndRemaining bool `json:"end_remaining"`
	// Check only validates and reports, without saving.
	Check bool `json:"check"`
}

func (s *Server) setGatewayPool(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	var req poolRequest
	if !readJSON(w, r, &req) {
		return
	}
	gws, err := s.Store.ListGateways(ctx)
	if err != nil {
		s.internal(w, err)
		return
	}
	var gw *model.Gateway
	for i := range gws {
		if gws[i].ID == id {
			gw = &gws[i]
		}
	}
	if gw == nil {
		writeErr(w, http.StatusNotFound, "not_found", "no such gateway")
		return
	}
	office := s.Sessions.OfficePolicy(ctx)
	p, warn, err := checkPool(id, req.Pool, gws, gw.Capacity, office.LocalSubnets)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if p == gw.Pool {
		writeJSON(w, http.StatusOK, map[string]any{"pool": p.String(), "warnings": warn, "unchanged": true})
		return
	}

	if req.Check {
		live, err := s.Store.LivePeers(ctx, id)
		if err != nil {
			s.internal(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"pool": p.String(), "warnings": warn, "connected": len(live)})
		return
	}
	ended, err := s.Store.SetGatewayPool(ctx, id, p, req.EndRemaining, s.now())
	switch {
	case errors.Is(err, store.ErrGatewayInUse):
		verb := "use"
		if ended == 1 {
			verb = "uses"
		}
		writeErr(w, http.StatusConflict, "gateway_in_use", fmt.Sprintf(
			"%d session%s on %s still %s the current range. Drain the gateway first, or end them.",
			ended, plural(ended), id, verb))
		return
	case errors.Is(err, store.ErrGatewayPoolOverlap):
		writeErr(w, http.StatusConflict, "pool_overlap", "the new range overlaps another gateway's range")
		return
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "no such gateway")
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	detail := fmt.Sprintf("%s → %s", gw.Pool, p)
	if ended > 0 {
		detail += fmt.Sprintf(" (ended %d session%s)", ended, plural(ended))
	}
	s.audit(ctx, current(r).Username, "gateway.pool", id, detail)
	writeJSON(w, http.StatusOK, map[string]any{"pool": p.String(), "warnings": warn, "ended": ended})
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
