package model

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"
)

// OfficeNetworkPolicy tells agents how to recognise the corporate network.
// When a PC matches any rule, the agent disconnects the VPN (and won't
// connect): traffic should go out the office network directly.
type OfficeNetworkPolicy struct {
	Enabled      bool     `json:"enabled"`
	DNSSuffixes  []string `json:"dns_suffixes"`  // e.g. "cb-sisco.com": matches the adapter's connection-specific DNS suffix
	LocalSubnets []string `json:"local_subnets"` // e.g. "10.20.0.0/16": matches the PC's own IP on its physical adapter
	PublicIPs    []string `json:"public_ips"`    // e.g. "203.0.113.10" or "203.0.113.0/28": the office's internet IP
}

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Normalize cleans the lists (trim, lower-case, drop blanks and duplicates) and validates them.
func (p *OfficeNetworkPolicy) Normalize() error {
	p.DNSSuffixes = cleanList(p.DNSSuffixes, func(s string) string { return strings.Trim(strings.ToLower(s), ". ") })
	for _, s := range p.DNSSuffixes {
		if !domainRE.MatchString(s) {
			return fmt.Errorf("DNS suffix %q isn't a valid domain", s)
		}
	}
	p.LocalSubnets = cleanList(p.LocalSubnets, strings.TrimSpace)
	for i, s := range p.LocalSubnets {
		pfx, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("local subnet %q: use CIDR like 10.20.0.0/16", s)
		}
		p.LocalSubnets[i] = pfx.String()
	}
	p.LocalSubnets = cleanList(p.LocalSubnets, strings.TrimSpace) // drop duplicates that only matched after canonicalising
	p.PublicIPs = cleanList(p.PublicIPs, strings.TrimSpace)
	for i, s := range p.PublicIPs {
		pfx, err := parsePrefix(s)
		if err != nil {
			return fmt.Errorf("public IP %q: use an IP like 203.0.113.10 or a range like 203.0.113.0/28", s)
		}
		p.PublicIPs[i] = pfx.String()
	}
	p.PublicIPs = cleanList(p.PublicIPs, strings.TrimSpace)
	if p.Enabled && len(p.DNSSuffixes)+len(p.LocalSubnets)+len(p.PublicIPs) == 0 {
		return errors.New("add at least one DNS suffix, subnet or public IP, or turn detection off")
	}
	return nil
}

// Match reports whether the PC is on the office network and why.
func (p OfficeNetworkPolicy) Match(dnsSuffixes, localIPs []string, publicIP string) (bool, string) {
	if !p.Enabled {
		return false, ""
	}
	for _, have := range dnsSuffixes {
		have = strings.Trim(strings.ToLower(have), ". ")
		for _, want := range p.DNSSuffixes {
			if have == want || strings.HasSuffix(have, "."+want) {
				return true, "DNS suffix " + have
			}
		}
	}
	for _, ip := range localIPs {
		if a, err := netip.ParseAddr(ip); err == nil {
			for _, s := range p.LocalSubnets {
				if pfx, err := netip.ParsePrefix(s); err == nil && pfx.Contains(a.Unmap()) {
					return true, "local IP " + ip + " in " + s
				}
			}
		}
	}
	if a, err := netip.ParseAddr(publicIP); err == nil {
		for _, s := range p.PublicIPs {
			if pfx, err := netip.ParsePrefix(s); err == nil && pfx.Contains(a.Unmap()) {
				return true, "public IP " + publicIP
			}
		}
	}
	return false, ""
}

func parsePrefix(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, err
	}
	return p.Masked(), nil
}

// Device approval statuses.
const (
	DevicePending  = "pending"  // seen, waiting for an admin (can't connect while approval is required)
	DeviceApproved = "approved" // may connect
	DeviceBlocked  = "blocked"  // never may connect
)

// Device is a PC that has tried to connect.
type Device struct {
	ID           string    `json:"id"`   // Windows MachineGuid (older agents: computer name)
	Name         string    `json:"name"` // computer name
	Status       string    `json:"status"`
	Platform     string    `json:"platform"`
	LastUser     string    `json:"last_user"`
	AgentVersion string    `json:"agent_version"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	DecidedBy    string    `json:"decided_by"`
	DecidedAt    time.Time `json:"decided_at"`
	Trust        *DeviceTrust `json:"trust,omitempty"` // latest connect-time device trust check
}

// DevicePolicy controls device approval.
type DevicePolicy struct {
	RequireApproval bool `json:"require_approval"` // new devices start pending and can't connect until approved
}

// CountryPolicy restricts where users can connect from. The country comes from
// the client's public IP at sign-in and connect.
type CountryPolicy struct {
	Enabled      bool     `json:"enabled"`
	Default      []string `json:"default"`       // ISO 3166 alpha-2 codes allowed for everyone, e.g. ["US"]
	BlockUnknown bool     `json:"block_unknown"` // block when the country can't be determined
}

// Normalize upper-cases and validates the country codes.
func (p *CountryPolicy) Normalize() error {
	var err error
	p.Default, err = NormalizeCountries(p.Default)
	if err != nil {
		return err
	}
	if p.Enabled && len(p.Default) == 0 {
		return errors.New("allow at least one country for everyone, or turn country restrictions off")
	}
	return nil
}

// NormalizeCountries upper-cases, de-duplicates and validates ISO alpha-2 codes.
func NormalizeCountries(in []string) ([]string, error) {
	out := cleanList(in, func(s string) string { return strings.ToUpper(strings.TrimSpace(s)) })
	for _, c := range out {
		if len(c) != 2 || c[0] < 'A' || c[0] > 'Z' || c[1] < 'A' || c[1] > 'Z' {
			return nil, fmt.Errorf("%q isn't a two-letter country code (like US or GB)", c)
		}
	}
	sort.Strings(out)
	return out, nil
}

// CountryAllowed decides whether a user may connect from country (ISO code,
// or "" when unknown). It returns a reason for the audit log when blocked.
func CountryAllowed(p CountryPolicy, u *User, country string, now time.Time) (bool, string) {
	if !p.Enabled {
		return true, ""
	}
	if country == "" || country == "XX" || country == "T1" {
		if p.BlockUnknown {
			return false, "country unknown"
		}
		return true, ""
	}
	allowed := append([]string(nil), p.Default...)
	if u != nil {
		allowed = append(allowed, u.AllowedCountries...)
		if now.Before(u.TravelUntil) {
			allowed = append(allowed, u.TravelCountries...)
		}
	}
	for _, c := range allowed {
		if c == country {
			return true, ""
		}
	}
	return false, "connecting from " + country + " isn't allowed for this user"
}

func cleanList(in []string, f func(string) string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
			v := f(part)
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

// DeviceTunnelPolicy controls the pre-logon device tunnel: with no user
// signed in to SecureTunnel, the Windows service connects with the PC's
// device certificate so the sign-in screen can reach domain controllers, DNS
// and management servers. The tunnel reaches only Subnets (the gateway
// enforces it too), never the whole network or the internet.
type DeviceTunnelPolicy struct {
	Enabled bool     `json:"enabled"`
	Subnets []string `json:"subnets"` // e.g. "10.0.0.10/32" (a DC) or "10.0.5.0/24"
	DNS     []string `json:"dns"`     // DNS servers for the device tunnel; empty = the normal tunnel DNS
}

// MaxDeviceTunnelSubnets limits the list (each one becomes a firewall rule on every gateway).
const MaxDeviceTunnelSubnets = 64

// Normalize cleans and validates the lists. Default routes are refused: the
// device tunnel is meant for a handful of infrastructure servers.
func (p *DeviceTunnelPolicy) Normalize() error {
	p.Subnets = cleanList(p.Subnets, strings.TrimSpace)
	for i, s := range p.Subnets {
		pfx, err := parsePrefix(s)
		if err != nil || !pfx.Addr().Is4() {
			return fmt.Errorf("subnet %q: use an IPv4 address like 10.0.0.10 or a range like 10.0.5.0/24", s)
		}
		if pfx.Bits() < 8 {
			return fmt.Errorf("subnet %q is too broad: the device tunnel is for specific servers (DCs, DNS, management)", s)
		}
		p.Subnets[i] = pfx.String()
	}
	p.Subnets = cleanList(p.Subnets, strings.TrimSpace)
	if len(p.Subnets) > MaxDeviceTunnelSubnets {
		return fmt.Errorf("at most %d subnets", MaxDeviceTunnelSubnets)
	}
	p.DNS = cleanList(p.DNS, strings.TrimSpace)
	for i, s := range p.DNS {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return fmt.Errorf("DNS server %q: use an IPv4 address", s)
		}
		p.DNS[i] = a.String()
		if !p.Reaches(a) {
			return fmt.Errorf("DNS server %s isn't in any of the device tunnel's subnets, so it couldn't be reached", s)
		}
	}
	if p.Enabled && len(p.Subnets) == 0 {
		return errors.New("add at least one subnet (for example your domain controllers), or turn the device tunnel off")
	}
	return nil
}

// Reaches reports whether a is inside one of the subnets.
func (p DeviceTunnelPolicy) Reaches(a netip.Addr) bool {
	for _, s := range p.Subnets {
		if pfx, err := netip.ParsePrefix(s); err == nil && pfx.Contains(a) {
			return true
		}
	}
	return false
}
