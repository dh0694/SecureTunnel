// Package policies stores the groups and policies (admin site → Groups,
// Policies) and picks the policies that apply to a user or a device.
package policies

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/devicetrust"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

const (
	settingKey    = "policies"
	oldGroupsKey  = "policy_groups" // before groups and policies (migrated)
	oldUpdatesKey = "update_policy" // the earlier single update policy (migrated)
)

// Manager serves the policy set.
type Manager struct {
	Store store.Store
	Trust *devicetrust.Checker // CAs (a certificate requirement needs one)
	Graph *devicetrust.Graph   // Entra group membership; may be nil

	mu       sync.Mutex
	cached   model.PolicySet
	cachedAt time.Time
	saved    bool // the set has been saved in the new form
}

// Set returns the groups and policies (cached a few seconds). Until an admin
// saves, it's built from the earlier policy groups and update policy.
func (m *Manager) Set(ctx context.Context) model.PolicySet {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cachedAt.IsZero() && time.Since(m.cachedAt) < 5*time.Second {
		return m.cached
	}
	var ps model.PolicySet
	ok, err := m.Store.GetSetting(ctx, settingKey, &ps)
	if err != nil && !m.cachedAt.IsZero() {
		return m.cached
	}
	if ok {
		had := typesIn(ps)
		if err := ps.Normalize(); err == nil {
			m.legacyDefaults(ctx, &ps, had)
			m.cached, m.cachedAt, m.saved = ps, time.Now(), true
			return ps
		}
	}
	ps = m.migrate(ctx)
	had := typesIn(ps)
	if err := ps.Normalize(); err != nil {
		ps = model.PolicySet{}
		_ = ps.Normalize()
	}
	m.legacyDefaults(ctx, &ps, had)
	m.cached, m.cachedAt, m.saved = ps, time.Now(), false
	return ps
}

func typesIn(ps model.PolicySet) map[string]bool {
	t := map[string]bool{}
	for _, p := range ps.Policies {
		t[p.Type] = true
	}
	return t
}

// legacyDefaults gives a policy type that hasn't been saved yet the earlier
// system-wide setting as its Default (countries, device approval, office
// networks, speed tests used to be single settings).
func (m *Manager) legacyDefaults(ctx context.Context, ps *model.PolicySet, had map[string]bool) {
	for i := range ps.Policies {
		p := &ps.Policies[i]
		if !p.Default || had[p.Type] {
			continue
		}
		switch p.Type {
		case model.PolicyCountries:
			var v model.CountryPolicy
			if ok, _ := m.Store.GetSetting(ctx, "country_policy", &v); ok && v.Normalize() == nil {
				p.Countries = &v
			}
		case model.PolicyApproval:
			var v model.DevicePolicy
			if ok, _ := m.Store.GetSetting(ctx, "device_policy", &v); ok {
				p.Approval = &v
			}
		case model.PolicyOffice:
			var v model.OfficeNetworkPolicy
			if ok, _ := m.Store.GetSetting(ctx, "office_networks", &v); ok && v.Normalize() == nil {
				p.Office = &v
			}
		case model.PolicySpeed:
			var v model.SpeedTestPolicy
			if ok, _ := m.Store.GetSetting(ctx, "speedtest_policy", &v); ok && v.Validate() == nil {
				p.Speed = &v
			}
		}
	}
}

// ForUser picks a user policy (e.g. countries) without a live Entra lookup
// when it isn't needed.
func (m *Manager) ForUser(ctx context.Context, typ string, id model.Identity, platform, deviceName string) (model.Policy, error) {
	ps := m.Set(ctx)
	p, _, err := ps.Pick(typ, m.userSubject(ctx, ps, id, platform, deviceName, typ))
	return p, err
}

// migrate builds the set from the earlier settings.
func (m *Manager) migrate(ctx context.Context) model.PolicySet {
	var old struct {
		Groups []model.PolicyGroup `json:"groups"`
	}
	ok, _ := m.Store.GetSetting(ctx, oldGroupsKey, &old)
	groups := old.Groups
	if ok {
		if g, err := model.NormalizeGroups(old.Groups); err == nil {
			groups = g
		}
	}
	if !ok || len(groups) == 0 {
		d := model.DefaultPolicyGroup()
		if m.Trust != nil {
			d.CertMode = m.Trust.Policy(ctx).CertMode
		}
		groups = []model.PolicyGroup{d}
	}
	picked := map[string][]string{}
	if users, err := m.Store.ListUsers(ctx); err == nil {
		for _, u := range users {
			if u.PolicyGroup != "" {
				picked[u.PolicyGroup] = append(picked[u.PolicyGroup], strings.ToLower(u.Username))
			}
		}
	}
	var up *model.UpdatePolicy
	var u model.UpdatePolicy
	if ok, _ := m.Store.GetSetting(ctx, oldUpdatesKey, &u); ok && u.Normalize() == nil {
		up = &u
	}
	return model.MigratePolicyGroups(groups, picked, up)
}

// Migrated reports whether the set is still the automatic conversion (not
// saved by an admin yet).
func (m *Manager) Migrated(ctx context.Context) bool {
	m.Set(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.saved
}

// Save validates and stores the set.
func (m *Manager) Save(ctx context.Context, ps model.PolicySet) (model.PolicySet, error) {
	if err := ps.Normalize(); err != nil {
		return ps, err
	}
	for _, p := range ps.Policies {
		if p.SignIn != nil && p.SignIn.CertMode != model.CertOff && m.Trust != nil {
			if cas, _ := model.ParseCAs(m.Trust.Policy(ctx).TrustedCAs); len(cas) == 0 {
				return ps, errors.New(p.Name + " requires a certificate: add your issuing CA under Settings → Certificates first")
			}
		}
	}
	if err := m.Store.SetSetting(ctx, settingKey, ps); err != nil {
		return ps, err
	}
	m.mu.Lock()
	m.cached, m.cachedAt, m.saved = ps, time.Now(), true
	m.mu.Unlock()
	return ps, nil
}

// CertWants reports whether any sign-in policy needs device or user certificates.
func (m *Manager) CertWants(ctx context.Context) (device, user bool) {
	for _, p := range m.Set(ctx).Policies {
		if p.SignIn != nil {
			r := p.SignIn.TrustRequirements()
			device = device || r.WantsDeviceCert()
			user = user || r.WantsUserCert()
		}
	}
	return device, user
}

// userSubject describes a signing-in user, looking up Entra groups only if
// some policy of these types needs them.
func (m *Manager) userSubject(ctx context.Context, ps model.PolicySet, id model.Identity, platform, deviceName string, types ...string) model.Subject {
	s := model.Subject{User: strings.ToLower(id.UPN), Platform: strings.ToLower(platform), DeviceName: deviceName, GroupsKnown: true}
	need := false
	for _, t := range types {
		need = need || ps.NeedsEntraGroups(t)
	}
	if need && id.TenantID != "local" && id.TenantID != "device" {
		s.GroupsKnown = false
		if m.Graph != nil {
			if ids, err := m.Graph.MemberGroups(ctx, id.UserOID); err == nil {
				for _, g := range ids {
					s.MemberOf = append(s.MemberOf, strings.ToLower(g))
				}
				s.GroupsKnown = true
			}
		}
	}
	return s
}

// Resolve picks the sign-in and Windows sessions policies for a connection
// and returns them as one PolicyGroup (what the connect checks use). Its
// Name is the sign-in policy's name.
func (m *Manager) Resolve(ctx context.Context, id model.Identity, platform, deviceName string) (model.PolicyGroup, error) {
	ps := m.Set(ctx)
	s := m.userSubject(ctx, ps, id, platform, deviceName, model.PolicySignIn, model.PolicyWindows)
	si, _, err := ps.Pick(model.PolicySignIn, s)
	if err != nil {
		return model.PolicyGroup{}, err
	}
	ws, _, err := ps.Pick(model.PolicyWindows, s)
	if err != nil {
		return model.PolicyGroup{}, err
	}
	g := model.PolicyGroup{ID: si.ID, Name: si.Name, AllowMicrosoft: si.SignIn.AllowMicrosoft, AllowLocal: si.SignIn.AllowLocal,
		MFA: si.SignIn.MFA, CertMode: si.SignIn.CertMode, Windows: *ws.Windows, DomainProof: model.DomainReported}
	return g, nil
}

// ForDevice picks a device policy (e.g. app updates) by platform and name.
func (m *Manager) ForDevice(ctx context.Context, typ, platform, deviceName string) (model.Policy, model.Group) {
	p, g, err := m.Set(ctx).Pick(typ, model.Subject{Platform: strings.ToLower(platform), DeviceName: deviceName, GroupsKnown: true})
	if err != nil {
		for _, d := range model.DefaultPolicies() {
			if d.Type == typ {
				return d, model.BuiltInGroups()[1]
			}
		}
	}
	return p, g
}

// Explain lists, for a user and/or device, which policy of each type applies
// and through which group (for the Users and Devices pages).
func (m *Manager) Explain(ctx context.Context, user, platform, deviceName string) []Applied {
	ps := m.Set(ctx)
	var out []Applied
	for _, typ := range model.PolicyTypes {
		s := model.Subject{Platform: strings.ToLower(platform), DeviceName: deviceName, GroupsKnown: true}
		if user != "" {
			s = m.userSubject(ctx, ps, model.Identity{UPN: user, TenantID: "local"}, platform, deviceName)
			s.GroupsKnown = !ps.NeedsEntraGroups(typ) // no live Entra lookup here
		}
		p, g, err := ps.Pick(typ, s)
		a := Applied{Type: typ, Policy: p.Name, PolicyID: p.ID, Group: g.Name}
		if err != nil {
			a.Policy, a.PolicyID, a.Group = "", "", ""
			a.Note = "depends on Entra group membership, checked at sign-in"
		}
		out = append(out, a)
	}
	return out
}

// Applied is one row of Explain.
type Applied struct {
	Type     string `json:"type"`
	Policy   string `json:"policy"`
	PolicyID string `json:"policy_id"`
	Group    string `json:"group"`
	Note     string `json:"note,omitempty"`
}
