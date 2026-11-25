package model

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Groups and policies (admin site → Groups, Policies).
//
// A Group says who or what: users (by Entra group or picked by hand) and/or
// devices (by platform or computer-name pattern). A Policy is a named set of
// settings of one type (sign-in, Windows sessions, app updates) assigned to
// groups. For each type, the first policy in the list with an assigned group
// that matches applies; every type ends with a Default policy assigned to
// All users or All devices, so something always applies.

// Built-in groups.
const (
	GroupAllUsers   = "all-users"
	GroupAllDevices = "all-devices"
)

// Policy types.
const (
	PolicySignIn    = "signin"    // sign-in methods, MFA, certificates (users)
	PolicyWindows   = "windows"   // Windows sign-out / switch / lock (users)
	PolicyUpdates   = "updates"   // app updates (devices)
	PolicyCountries = "countries" // allowed countries (users)
	PolicyApproval  = "approval"  // device approval (devices)
	PolicyOffice    = "office"    // office network detection (devices)
	PolicySpeed     = "speedtest" // speed tests (devices)
)

// PolicyTypes lists the types in the order the admin site shows them.
var PolicyTypes = []string{PolicySignIn, PolicyWindows, PolicyCountries, PolicyUpdates, PolicyApproval, PolicyOffice, PolicySpeed}

// policyForDevices says which types are decided per device (no user needed).
var policyForDevices = map[string]bool{PolicyUpdates: true, PolicyApproval: true, PolicyOffice: true, PolicySpeed: true}

// Group is a set of users and/or devices.
type Group struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Kind        string `json:"kind"` // "users" or "devices" (how the admin site edits it)
	BuiltIn     bool   `json:"built_in,omitempty"`

	// Users: members of any of these Entra groups, or picked by hand.
	EntraGroups []EntraRef `json:"entra_groups"`
	Users       []string   `json:"users"` // usernames / UPNs, lower case
	// Devices (and users, on these devices): platform and computer name.
	Platforms    []string `json:"platforms"`     // "windows", "macos"
	NamePatterns []string `json:"name_patterns"` // e.g. "LT-*", "KIOSK-0?", exact names too
}

// SignInPolicy is how users sign in (type "signin").
type SignInPolicy struct {
	AllowMicrosoft bool   `json:"allow_microsoft"`
	AllowLocal     bool   `json:"allow_local"`
	MFA            string `json:"mfa"`       // "none" or "duo"
	CertMode       string `json:"cert_mode"` // off | device | user | either | both
}

// Policy is a named set of settings of one type, assigned to groups.
type Policy struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type"`
	Groups      []string `json:"groups"` // assigned group IDs
	Default     bool     `json:"default,omitempty"`

	SignIn    *SignInPolicy         `json:"signin,omitempty"`
	Windows   *WindowsSessionPolicy `json:"windows,omitempty"`
	Updates   *UpdatePolicy         `json:"updates,omitempty"`
	Countries *CountryPolicy        `json:"countries,omitempty"`
	Approval  *DevicePolicy         `json:"approval,omitempty"`
	Office    *OfficeNetworkPolicy  `json:"office,omitempty"`
	Speed     *SpeedTestPolicy      `json:"speedtest,omitempty"`
}

// PolicySet is everything saved on the Groups and Policies pages.
type PolicySet struct {
	Groups   []Group  `json:"groups"`
	Policies []Policy `json:"policies"` // per type: in priority order, Default last
}

// Subject is who or what a policy is being picked for.
type Subject struct {
	User        string   // username / UPN, lower case ("" = no user: device-only checks)
	MemberOf    []string // Entra group object IDs (lower case)
	GroupsKnown bool     // MemberOf could be checked (Graph answered, or not needed)
	Platform    string   // "windows" / "macos"
	DeviceName  string   // computer name
}

// match reports whether the group includes the subject. unknown is set when
// the answer depends on Entra groups that couldn't be checked.
func (g Group) match(s Subject) (ok, unknown bool) {
	switch g.ID {
	case GroupAllUsers:
		return s.User != "", false
	case GroupAllDevices:
		return true, false
	}
	if s.User != "" {
		for _, u := range g.Users {
			if u == s.User {
				return true, false
			}
		}
	}
	rules := len(g.EntraGroups) > 0 || len(g.Platforms) > 0 || len(g.NamePatterns) > 0
	if !rules {
		return false, false
	}
	if len(g.Platforms) > 0 && !contains(g.Platforms, strings.ToLower(s.Platform)) {
		return false, false
	}
	if len(g.NamePatterns) > 0 {
		hit := false
		name := strings.ToLower(s.DeviceName)
		for _, p := range g.NamePatterns {
			if ok, _ := path.Match(p, name); ok {
				hit = true
				break
			}
		}
		if !hit {
			return false, false
		}
	}
	if len(g.EntraGroups) > 0 {
		if s.User == "" {
			return false, false // a device-only check can't match a user group
		}
		if !s.GroupsKnown {
			return false, true
		}
		for _, e := range g.EntraGroups {
			if contains(s.MemberOf, e.ID) {
				return true, false
			}
		}
		return false, false
	}
	return true, false
}

// DeviceInGroup reports whether a device (by platform and name) is in a
// group through its device rules (for counts on the admin site).
func DeviceInGroup(g Group, platform, name string) bool {
	if g.ID == GroupAllDevices {
		return true
	}
	if len(g.EntraGroups) > 0 || (len(g.Platforms) == 0 && len(g.NamePatterns) == 0) {
		return false
	}
	ok, _ := g.match(Subject{Platform: platform, DeviceName: name, GroupsKnown: true})
	return ok
}

// NeedsEntraGroups reports whether picking a policy of this type may need
// the user's Entra group membership.
func (ps PolicySet) NeedsEntraGroups(typ string) bool {
	groups := ps.groupMap()
	for _, p := range ps.Policies {
		if p.Type != typ {
			continue
		}
		for _, gid := range p.Groups {
			if g, ok := groups[gid]; ok && len(g.EntraGroups) > 0 {
				return true
			}
		}
	}
	return false
}

func (ps PolicySet) groupMap() map[string]Group {
	m := map[string]Group{}
	for _, g := range ps.Groups {
		m[g.ID] = g
	}
	return m
}

// Pick returns the policy of a type that applies to the subject, and the
// group it applied through.
func (ps PolicySet) Pick(typ string, s Subject) (Policy, Group, error) {
	groups := ps.groupMap()
	for _, p := range ps.Policies {
		if p.Type != typ {
			continue
		}
		for _, gid := range p.Groups {
			g, ok := groups[gid]
			if !ok {
				continue
			}
			hit, unknown := g.match(s)
			if unknown {
				return Policy{}, Group{}, ErrGroupsUnknown
			}
			if hit {
				return p, g, nil
			}
		}
	}
	// Normalize guarantees a Default per type; this is only a safety net.
	d := DefaultPolicies()
	for _, p := range d {
		if p.Type == typ {
			return p, BuiltInGroups()[0], nil
		}
	}
	return Policy{}, Group{}, fmt.Errorf("no %s policy", typ)
}

// BuiltInGroups are always there.
func BuiltInGroups() []Group {
	return []Group{
		{ID: GroupAllUsers, Name: "All users", Kind: "users", BuiltIn: true, Description: "Everyone who signs in."},
		{ID: GroupAllDevices, Name: "All devices", Kind: "devices", BuiltIn: true, Description: "Every PC and Mac."},
	}
}

// DefaultPolicies is one Default policy per type.
func DefaultPolicies() []Policy {
	si := SignInPolicy{AllowMicrosoft: true, AllowLocal: true, MFA: MFANone, CertMode: CertOff}
	ws := DefaultWindowsSessions()
	up := DefaultUpdatePolicy()
	return []Policy{
		{ID: "default-" + PolicySignIn, Name: "Default sign-in", Type: PolicySignIn, Groups: []string{GroupAllUsers}, Default: true, SignIn: &si},
		{ID: "default-" + PolicyWindows, Name: "Default Windows sessions", Type: PolicyWindows, Groups: []string{GroupAllUsers}, Default: true, Windows: &ws},
		{ID: "default-" + PolicyUpdates, Name: "Default app updates", Type: PolicyUpdates, Groups: []string{GroupAllDevices}, Default: true, Updates: &up},
		{ID: "default-" + PolicyCountries, Name: "Default countries", Type: PolicyCountries, Groups: []string{GroupAllUsers}, Default: true, Countries: &CountryPolicy{Default: []string{}}},
		{ID: "default-" + PolicyApproval, Name: "Default device approval", Type: PolicyApproval, Groups: []string{GroupAllDevices}, Default: true, Approval: &DevicePolicy{}},
		{ID: "default-" + PolicyOffice, Name: "Default office networks", Type: PolicyOffice, Groups: []string{GroupAllDevices}, Default: true, Office: &OfficeNetworkPolicy{}},
		{ID: "default-" + PolicySpeed, Name: "Default speed tests", Type: PolicySpeed, Groups: []string{GroupAllDevices}, Default: true, Speed: &SpeedTestPolicy{IntervalHours: DefaultSpeedTestPolicy.IntervalHours, SizeMB: DefaultSpeedTestPolicy.SizeMB, Host: DefaultSpeedTestPolicy.Host}},
	}
}

var idRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,47}$`)

// namePatternRE allows computer names with * and ? wildcards.
var namePatternRE = regexp.MustCompile(`^[a-z0-9.*?_-]+$`)

// Normalize validates the set, adds the built-in groups and any missing
// Default policy, and puts each type's Default last.
func (ps *PolicySet) Normalize() error {
	groups := BuiltInGroups()
	seen := map[string]bool{GroupAllUsers: true, GroupAllDevices: true}
	for _, g := range ps.Groups {
		if g.ID == GroupAllUsers || g.ID == GroupAllDevices || g.BuiltIn {
			continue // built-ins can't be changed
		}
		g.ID = strings.ToLower(strings.TrimSpace(g.ID))
		g.Name = strings.TrimSpace(g.Name)
		g.Description = strings.TrimSpace(g.Description)
		if g.Name == "" {
			return errors.New("every group needs a name")
		}
		if len(g.Name) > 60 || len(g.Description) > 200 {
			return errors.New(g.Name + ": name or description is too long")
		}
		if !idRE.MatchString(g.ID) || seen[g.ID] {
			return fmt.Errorf("%s: bad or duplicate group ID", g.Name)
		}
		seen[g.ID] = true
		if g.Kind != "users" && g.Kind != "devices" {
			g.Kind = "users"
		}
		ents := []EntraRef{}
		for _, e := range g.EntraGroups {
			e.ID = strings.ToLower(strings.TrimSpace(e.ID))
			if !guidRE.MatchString(e.ID) {
				return fmt.Errorf("%s: Entra group IDs look like 11111111-2222-3333-4444-555555555555", g.Name)
			}
			e.Name = strings.TrimSpace(e.Name)
			ents = append(ents, e)
		}
		g.EntraGroups = ents
		users := []string{}
		for _, u := range g.Users {
			u = strings.ToLower(strings.TrimSpace(u))
			if u != "" && !contains(users, u) {
				users = append(users, u)
			}
		}
		g.Users = users
		plats := []string{}
		for _, p := range g.Platforms {
			p = strings.ToLower(strings.TrimSpace(p))
			if p != "windows" && p != "macos" {
				return fmt.Errorf("%s: unknown platform %q", g.Name, p)
			}
			if !contains(plats, p) {
				plats = append(plats, p)
			}
		}
		g.Platforms = plats
		pats := []string{}
		for _, p := range g.NamePatterns {
			p = strings.ToLower(strings.TrimSpace(p))
			if p == "" {
				continue
			}
			if !namePatternRE.MatchString(p) || len(p) > 64 {
				return fmt.Errorf("%s: %q isn't a computer name pattern (letters, digits, - . _ and * ?)", g.Name, p)
			}
			if !contains(pats, p) {
				pats = append(pats, p)
			}
		}
		g.NamePatterns = pats
		if len(g.EntraGroups)+len(g.Users)+len(g.Platforms)+len(g.NamePatterns) == 0 {
			return fmt.Errorf("%s: add at least one member or rule", g.Name)
		}
		groups = append(groups, g)
	}
	if len(groups) > 102 {
		return errors.New("use at most 100 groups")
	}

	defaults := map[string]Policy{}
	for _, p := range DefaultPolicies() {
		defaults[p.Type] = p
	}
	for _, p := range ps.Policies {
		if _, ok := defaults[p.Type]; !ok {
			return fmt.Errorf("%s: unknown policy type %q", p.Name, p.Type)
		}
	}
	var out []Policy
	pseen := map[string]bool{}
	for _, typ := range PolicyTypes {
		var def *Policy
		for _, p := range ps.Policies {
			if p.Type != typ {
				continue
			}
			isDefault := p.Default || p.ID == "default-"+typ
			p.ID = strings.ToLower(strings.TrimSpace(p.ID))
			p.Name = strings.TrimSpace(p.Name)
			p.Description = strings.TrimSpace(p.Description)
			if isDefault {
				p.ID, p.Default = "default-"+typ, true
				if policyForDevices[typ] {
					p.Groups = []string{GroupAllDevices}
				} else {
					p.Groups = []string{GroupAllUsers}
				}
				if p.Name == "" {
					p.Name = defaults[typ].Name
				}
			}
			if p.Name == "" {
				return errors.New("every policy needs a name")
			}
			if !idRE.MatchString(p.ID) || pseen[p.ID] {
				return fmt.Errorf("%s: bad or duplicate policy ID", p.Name)
			}
			pseen[p.ID] = true
			if !isDefault {
				gs := []string{}
				for _, gid := range p.Groups {
					if !seen[gid] {
						return fmt.Errorf("%s: it's assigned to a group that doesn't exist", p.Name)
					}
					if !contains(gs, gid) {
						gs = append(gs, gid)
					}
				}
				p.Groups = gs
			}
			if err := normalizeSettings(&p); err != nil {
				return fmt.Errorf("%s: %w", p.Name, err)
			}
			if isDefault {
				pp := p
				def = &pp
				continue
			}
			out = append(out, p)
		}
		if def == nil {
			d := defaults[typ]
			def = &d
		}
		out = append(out, *def)
	}
	ps.Groups, ps.Policies = groups, out
	return nil
}

// normalizeSettings keeps only the settings for the policy's type and checks them.
func normalizeSettings(p *Policy) error {
	switch p.Type {
	case PolicySignIn:
		p.Windows, p.Updates = nil, nil
		if p.SignIn == nil {
			s := DefaultPolicies()[0].SignIn
			p.SignIn = s
		}
		s := p.SignIn
		if s.MFA == "" {
			s.MFA = MFANone
		}
		if s.MFA != MFANone && s.MFA != MFADuo {
			return errors.New("unknown MFA option")
		}
		switch s.CertMode {
		case "":
			s.CertMode = CertOff
		case CertOff, CertDevice, CertUser, CertEither, CertBoth:
		default:
			return errors.New("unknown certificate option")
		}
		if !s.AllowMicrosoft && !s.AllowLocal {
			return errors.New("allow at least one way to sign in")
		}
	case PolicyWindows:
		p.SignIn, p.Updates = nil, nil
		if p.Windows == nil {
			w := DefaultWindowsSessions()
			p.Windows = &w
		}
		return p.Windows.Normalize()
	case PolicyUpdates:
		p.SignIn, p.Windows = nil, nil
		if p.Updates == nil {
			u := DefaultUpdatePolicy()
			p.Updates = &u
		}
		return p.Updates.Normalize()
	case PolicyCountries:
		if p.Countries == nil {
			p.Countries = &CountryPolicy{Default: []string{}}
		}
		return p.Countries.Normalize()
	case PolicyApproval:
		if p.Approval == nil {
			p.Approval = &DevicePolicy{}
		}
	case PolicyOffice:
		if p.Office == nil {
			p.Office = &OfficeNetworkPolicy{}
		}
		return p.Office.Normalize()
	case PolicySpeed:
		if p.Speed == nil {
			s := DefaultSpeedTestPolicy
			p.Speed = &s
		}
		return p.Speed.Validate()
	default:
		return fmt.Errorf("unknown policy type %q", p.Type)
	}
	return nil
}

// MigratePolicyGroups turns the earlier policy groups (and the users picked
// for them) into groups plus sign-in and Windows sessions policies, and adds
// the earlier global update policy as the Default app updates policy.
func MigratePolicyGroups(old []PolicyGroup, picked map[string][]string, updates *UpdatePolicy) PolicySet {
	var ps PolicySet
	for _, pg := range old {
		si := SignInPolicy{AllowMicrosoft: pg.AllowMicrosoft, AllowLocal: pg.AllowLocal, MFA: pg.MFA, CertMode: pg.CertMode}
		ws := pg.Windows
		if pg.ID == DefaultGroupID {
			ps.Policies = append(ps.Policies,
				Policy{ID: "default-" + PolicySignIn, Name: "Default sign-in", Type: PolicySignIn, Default: true, SignIn: &si},
				Policy{ID: "default-" + PolicyWindows, Name: "Default Windows sessions", Type: PolicyWindows, Default: true, Windows: &ws})
			continue
		}
		// An unassigned manual group could never match under the old format.
		// The new format rejects empty groups, so omit it during migration.
		if !pg.Automatic() && len(picked[pg.ID]) == 0 {
			continue
		}
		kind := "users"
		if len(pg.EntraGroups) == 0 && len(picked[pg.ID]) == 0 && len(pg.Platforms) > 0 {
			kind = "devices"
		}
		ps.Groups = append(ps.Groups, Group{ID: pg.ID, Name: pg.Name, Description: pg.Description, Kind: kind,
			EntraGroups: pg.EntraGroups, Users: picked[pg.ID], Platforms: pg.Platforms, NamePatterns: []string{}})
		ps.Policies = append(ps.Policies,
			Policy{ID: pg.ID + "-signin", Name: pg.Name + " sign-in", Type: PolicySignIn, Groups: []string{pg.ID}, SignIn: &si},
			Policy{ID: pg.ID + "-windows", Name: pg.Name + " Windows sessions", Type: PolicyWindows, Groups: []string{pg.ID}, Windows: &ws})
	}
	if updates != nil {
		u := *updates
		ps.Policies = append(ps.Policies, Policy{ID: "default-" + PolicyUpdates, Name: "Default app updates", Type: PolicyUpdates, Default: true, Updates: &u})
	}
	return ps
}

// TrustRequirementsOf turns a sign-in policy into device trust requirements.
func (s SignInPolicy) TrustRequirements() TrustRequirements {
	return TrustRequirements{CertMode: s.CertMode}
}
