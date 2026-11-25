package model

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Policy groups decide, per connection, how someone must sign in and what
// their PC must prove. Groups are checked in order; the first match wins:
//
//  1. a group picked for the user on the Users page, else
//  2. the first group whose conditions match (Entra group membership and/or
//     platform), else
//  3. the Default group (always last).
type PolicyGroup struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Platforms   []string   `json:"platforms"`    // "windows", "macos"; empty = any
	EntraGroups []EntraRef `json:"entra_groups"` // member of any of these; empty = no group condition

	AllowMicrosoft bool   `json:"allow_microsoft"` // Sign in with Microsoft (Entra MFA via Conditional Access)
	AllowLocal     bool   `json:"allow_local"`     // local accounts (POC/test)
	MFA            string `json:"mfa"`             // extra MFA after sign-in: "none" or "duo"

	// Join type and Intune compliance are left to Conditional Access; the
	// server only shows them. A certificate can still be required here.
	CertMode string `json:"cert_mode"` // off | device | user | either | both

	// Domains optionally restricts the group to PCs joined to these Active
	// Directory domains (DNS like corp.contoso.com, or NetBIOS like CONTOSO).
	Domains []string `json:"domains"`
	// DomainProof is how the domain is checked: "reported" (what the PC says)
	// or "certificate" (a device certificate from a trusted CA, issued to a
	// computer in that domain).
	DomainProof string `json:"domain_proof"`

	// Windows is what happens on Windows sign-out, user switching and lock.
	Windows WindowsSessionPolicy `json:"windows"`
}

// Domain proof options.
const (
	DomainReported    = "reported"
	DomainCertificate = "certificate"
)

// EntraRef is an Entra security group (object ID + name for display).
type EntraRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DefaultGroupID is the catch-all group, always last.
const DefaultGroupID = "default"

// MFA options.
const (
	MFANone = "none"
	MFADuo  = "duo"
)

var groupIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// Automatic reports whether the group can match on its own (not only by
// being picked for a user).
func (g PolicyGroup) Automatic() bool { return len(g.Platforms) > 0 || len(g.EntraGroups) > 0 }

// Requirements are the device trust requirements of the group.
func (g PolicyGroup) Requirements() TrustRequirements {
	return TrustRequirements{CertMode: g.CertMode, Domains: g.Domains, DomainProof: g.DomainProof}
}

// TrustRequirements are what a device must prove for one policy group.
type TrustRequirements struct {
	CertMode    string
	Domains     []string
	DomainProof string
}

// WantsDeviceCert / WantsUserCert say which certificates the agent should
// send (a domain proven by certificate needs the device certificate).
func (r TrustRequirements) WantsDeviceCert() bool {
	return r.CertMode == CertDevice || r.CertMode == CertEither || r.CertMode == CertBoth ||
		(len(r.Domains) > 0 && r.DomainProof == DomainCertificate)
}

// DomainMatches reports whether a DNS name (FQDN or domain) or NetBIOS name
// is one of the allowed domains. DNS subdomains of an allowed domain match.
func DomainMatches(allowed []string, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return false
	}
	for _, d := range allowed {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

var adDomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)
func (r TrustRequirements) WantsUserCert() bool {
	return r.CertMode == CertUser || r.CertMode == CertEither || r.CertMode == CertBoth
}

// DefaultPolicyGroup is used until an admin saves groups.
func DefaultPolicyGroup() PolicyGroup {
	return PolicyGroup{ID: DefaultGroupID, Name: "Default", Description: "Everyone not matched by a group above.",
		Platforms: []string{}, EntraGroups: []EntraRef{}, AllowMicrosoft: true, AllowLocal: true, MFA: MFANone, CertMode: CertOff}
}

// NormalizeGroups validates the list and makes sure Default is last.
func NormalizeGroups(in []PolicyGroup) ([]PolicyGroup, error) {
	seen := map[string]bool{}
	var out []PolicyGroup
	var def *PolicyGroup
	for i := range in {
		g := in[i]
		g.ID = strings.ToLower(strings.TrimSpace(g.ID))
		g.Name = strings.TrimSpace(g.Name)
		g.Description = strings.TrimSpace(g.Description)
		if g.Name == "" {
			return nil, errors.New("every group needs a name")
		}
		if len(g.Name) > 60 || len(g.Description) > 200 {
			return nil, errors.New(g.Name + ": name or description is too long")
		}
		if !groupIDRE.MatchString(g.ID) {
			return nil, fmt.Errorf("%s: bad group ID", g.Name)
		}
		if seen[g.ID] {
			return nil, fmt.Errorf("two groups have the ID %q", g.ID)
		}
		seen[g.ID] = true
		plats := []string{}
		for _, p := range g.Platforms {
			p = strings.ToLower(strings.TrimSpace(p))
			if p != "windows" && p != "macos" {
				return nil, fmt.Errorf("%s: unknown platform %q", g.Name, p)
			}
			if !contains(plats, p) {
				plats = append(plats, p)
			}
		}
		g.Platforms = plats
		groups := []EntraRef{}
		for _, e := range g.EntraGroups {
			e.ID = strings.ToLower(strings.TrimSpace(e.ID))
			if !guidRE.MatchString(e.ID) {
				return nil, fmt.Errorf("%s: Entra group IDs look like 11111111-2222-3333-4444-555555555555", g.Name)
			}
			e.Name = strings.TrimSpace(e.Name)
			groups = append(groups, e)
		}
		g.EntraGroups = groups
		switch g.MFA {
		case "":
			g.MFA = MFANone
		case MFANone, MFADuo:
		default:
			return nil, fmt.Errorf("%s: unknown MFA option", g.Name)
		}
		switch g.CertMode {
		case "":
			g.CertMode = CertOff
		case CertOff, CertDevice, CertUser, CertEither, CertBoth:
		default:
			return nil, fmt.Errorf("%s: unknown certificate option", g.Name)
		}
		doms := []string{}
		for _, d := range g.Domains {
			d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			if d == "" {
				continue
			}
			if len(d) > 253 || !adDomainRE.MatchString(d) {
				return nil, fmt.Errorf("%s: %q isn't a domain name (use corp.contoso.com or CONTOSO)", g.Name, d)
			}
			if !contains(doms, d) {
				doms = append(doms, d)
			}
		}
		g.Domains = doms
		switch g.DomainProof {
		case "", DomainReported:
			g.DomainProof = DomainReported
		case DomainCertificate:
		default:
			return nil, fmt.Errorf("%s: unknown domain check", g.Name)
		}
		if !g.AllowMicrosoft && !g.AllowLocal {
			return nil, fmt.Errorf("%s: allow at least one way to sign in", g.Name)
		}
		if err := g.Windows.Normalize(); err != nil {
			return nil, fmt.Errorf("%s: %w", g.Name, err)
		}
		if g.ID == DefaultGroupID {
			g.Platforms, g.EntraGroups = []string{}, []EntraRef{} // Default matches everyone
			gg := g
			def = &gg
			continue
		}
		out = append(out, g)
	}
	if len(out) > 50 {
		return nil, errors.New("at most 50 groups")
	}
	if def == nil {
		d := DefaultPolicyGroup()
		def = &d
	}
	return append(out, *def), nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ErrGroupsUnknown means the user's Entra groups couldn't be read while a
// group depends on them; connecting is refused rather than guessing.
var ErrGroupsUnknown = errors.New("group membership couldn't be checked")

// ResolveGroup picks the policy group for a connection.
//   - assigned: the group picked for the user ("" = automatic)
//   - memberOf: the user's Entra group IDs; known=false if they couldn't be read
func ResolveGroup(groups []PolicyGroup, assigned, platform string, memberOf []string, known bool) (PolicyGroup, error) {
	if assigned != "" {
		for _, g := range groups {
			if g.ID == assigned {
				return g, nil
			}
		}
	}
	platform = strings.ToLower(platform)
	in := map[string]bool{}
	for _, id := range memberOf {
		in[strings.ToLower(id)] = true
	}
	for _, g := range groups {
		if g.ID == DefaultGroupID || !g.Automatic() {
			continue
		}
		if len(g.Platforms) > 0 && !contains(g.Platforms, platform) {
			continue
		}
		if len(g.EntraGroups) > 0 {
			if !known {
				return PolicyGroup{}, ErrGroupsUnknown
			}
			hit := false
			for _, e := range g.EntraGroups {
				if in[e.ID] {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
		}
		return g, nil
	}
	for _, g := range groups {
		if g.ID == DefaultGroupID {
			return g, nil
		}
	}
	return DefaultPolicyGroup(), nil
}
