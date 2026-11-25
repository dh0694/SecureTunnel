package model

import (
	"errors"
	"regexp"
	"strings"
)

// SignInSettings choose how users sign in. They are edited on the admin site
// (Policies → Sign-in) and fall back to the ST_* environment settings.
//
// One Entra app registration serves everything: it exposes the VPN API scope
// "access_as_user" (the agent signs in as a public client with PKCE), and it
// has a client secret plus app roles for the admin site.
type SignInSettings struct {
	LocalEnabled bool `json:"local_enabled"` // local accounts may connect to the VPN
	EntraEnabled bool `json:"entra_enabled"`

	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"` // for the admin site sign-in; never returned to browsers

	// PromptLogin asks for credentials on every VPN connect (prompt=login),
	// matching "sign in each time you connect". Conditional Access still
	// decides MFA.
	PromptLogin bool `json:"prompt_login"`
}

var guidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Normalize trims and validates the settings.
func (s *SignInSettings) Normalize() error {
	s.TenantID = strings.ToLower(strings.TrimSpace(s.TenantID))
	s.ClientID = strings.ToLower(strings.TrimSpace(s.ClientID))
	s.ClientSecret = strings.TrimSpace(s.ClientSecret)
	if s.EntraEnabled {
		if !guidRE.MatchString(s.TenantID) {
			return errors.New("the tenant ID should look like 11111111-2222-3333-4444-555555555555")
		}
		if !guidRE.MatchString(s.ClientID) {
			return errors.New("the client (application) ID should look like 11111111-2222-3333-4444-555555555555")
		}
	}
	if !s.LocalEnabled && !s.EntraEnabled {
		return errors.New("turn on at least one way to sign in")
	}
	return nil
}

// EntraReady reports whether Entra sign-in is configured.
func (s SignInSettings) EntraReady() bool {
	return s.EntraEnabled && s.TenantID != "" && s.ClientID != ""
}

// APIScope is the scope the agent requests for the VPN.
func (s SignInSettings) APIScope() string { return "api://" + s.ClientID + "/access_as_user" }

// Audiences are the accepted "aud" values of VPN access tokens.
func (s SignInSettings) Audiences() []string { return []string{"api://" + s.ClientID, s.ClientID} }

// Entra app roles that grant admin site access.
const (
	EntraRoleAdmin    = "SecureTunnel.Admin"
	EntraRoleHelpdesk = "SecureTunnel.Helpdesk"
)

// RoleFromEntra maps Entra app roles to an admin site role ("" = no access).
func RoleFromEntra(roles []string) string {
	role := ""
	for _, r := range roles {
		switch r {
		case EntraRoleAdmin:
			return RoleAdmin
		case EntraRoleHelpdesk:
			role = RoleHelpdesk
		}
	}
	return role
}
