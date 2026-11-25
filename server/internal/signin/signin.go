// Package signin holds the live sign-in settings (local accounts and/or Entra)
// and validates connect tokens against them. Settings are edited on the admin
// site and stored in the database, so every control server follows changes
// within a few seconds without a restart.
package signin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/auth"
	"securetunnel/server/internal/localauth"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

const settingKey = "sign_in"

// Manager serves the current sign-in settings.
type Manager struct {
	Store    store.Store
	Defaults model.SignInSettings // from the environment, used until an admin saves settings
	Local    *localauth.Authenticator
	// Entra access-token checks beyond tenant/audience/scope (see auth.Config).
	RequireMFA      bool
	MaxAuthAge      time.Duration
	RequireAuthTime bool
	Log             *slog.Logger

	mu       sync.Mutex
	cached   model.SignInSettings
	cachedAt time.Time
	keys     map[string]*auth.JWKSSource // per tenant
}

// Get returns the current settings (cached for a few seconds).
func (m *Manager) Get(ctx context.Context) model.SignInSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.cachedAt.IsZero() && time.Since(m.cachedAt) < 5*time.Second {
		return m.cached
	}
	s := m.Defaults
	if ok, err := m.Store.GetSetting(ctx, settingKey, &s); err != nil {
		if m.Log != nil {
			m.Log.Warn("load sign-in settings", "err", err)
		}
		if !m.cachedAt.IsZero() {
			return m.cached
		}
		s = m.Defaults
	} else if !ok {
		s = m.Defaults
	}
	m.cached, m.cachedAt = s, time.Now()
	return s
}

// Save validates and stores new settings. An empty client secret keeps the
// saved one.
func (m *Manager) Save(ctx context.Context, s model.SignInSettings) error {
	if err := s.Normalize(); err != nil {
		return err
	}
	if s.ClientSecret == "" {
		s.ClientSecret = m.Get(ctx).ClientSecret
	}
	if err := m.Store.SetSetting(ctx, settingKey, s); err != nil {
		return err
	}
	m.mu.Lock()
	m.cached, m.cachedAt = s, time.Now()
	m.mu.Unlock()
	return nil
}

// LocalEnabled reports whether local accounts may connect to the VPN.
func (m *Manager) LocalEnabled(ctx context.Context) bool {
	return m.Local != nil && m.Get(ctx).LocalEnabled
}

// Keys returns the (shared, cached) signing-key source for an Entra tenant.
func (m *Manager) Keys(tenantID string) *auth.JWKSSource {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.keys == nil {
		m.keys = map[string]*auth.JWKSSource{}
	}
	k, ok := m.keys[tenantID]
	if !ok {
		k = auth.NewJWKSSource(tenantID)
		m.keys[tenantID] = k
	}
	return k
}

// Validate implements api.TokenValidator: local connect tokens go to the
// local authenticator, everything else to Entra, each only while enabled.
func (m *Manager) Validate(ctx context.Context, raw string) (model.Identity, error) {
	s := m.Get(ctx)
	if localauth.IsLocalToken(raw) {
		if !s.LocalEnabled || m.Local == nil {
			return model.Identity{}, fmt.Errorf("%w: local accounts are turned off", auth.ErrInvalidToken)
		}
		return m.Local.Validate(ctx, raw)
	}
	if !s.EntraReady() {
		return model.Identity{}, fmt.Errorf("%w: Entra sign-in is turned off", auth.ErrInvalidToken)
	}
	v := auth.NewValidator(auth.Config{
		TenantID:        s.TenantID,
		Audiences:       s.Audiences(),
		RequiredScope:   "access_as_user",
		RequireMFA:      m.RequireMFA,
		MaxAuthAge:      m.MaxAuthAge,
		RequireAuthTime: m.RequireAuthTime,
	}, m.Keys(s.TenantID), nil)
	id, err := v.Validate(ctx, raw)
	if err != nil {
		return id, err
	}
	id.UPN = strings.ToLower(id.UPN)
	// An Entra user's settings row can disable them here too.
	u, err := m.Store.GetUser(ctx, id.UPN)
	switch {
	case err == nil && u.Disabled:
		return model.Identity{}, fmt.Errorf("%w: account disabled on the admin site", auth.ErrInvalidToken)
	case err == nil:
		if u.Source == "entra" {
			u.LastLogin = time.Now()
			if u.DisplayName == "" {
				u.DisplayName = id.Name
			}
			_ = m.Store.UpdateUser(ctx, u)
		}
	case errors.Is(err, store.ErrNotFound) && id.UPN != "":
		// List Entra users on the Users page the first time they connect, so
		// admins can set their countries.
		_ = m.Store.CreateUser(ctx, model.User{Username: id.UPN, DisplayName: id.Name, Role: model.RoleUser,
			Source: "entra", CreatedAt: time.Now(), LastLogin: time.Now()})
	}
	return id, nil
}

// ClientConfig is what the agent needs to sign in (GET /v1/client/auth-config).
type ClientConfig struct {
	Local bool          `json:"local"`
	Entra *EntraClient  `json:"entra,omitempty"`
}

// EntraClient is the public (non-secret) Entra configuration for the agent.
type EntraClient struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	Scope       string `json:"scope"`
	Authority   string `json:"authority"`
	PromptLogin bool   `json:"prompt_login"`
}

// Client returns the agent's sign-in configuration.
func (m *Manager) Client(ctx context.Context) ClientConfig {
	s := m.Get(ctx)
	out := ClientConfig{Local: s.LocalEnabled && m.Local != nil}
	if s.EntraReady() {
		out.Entra = &EntraClient{
			TenantID: s.TenantID, ClientID: s.ClientID, Scope: s.APIScope(),
			Authority: "https://login.microsoftonline.com/" + s.TenantID, PromptLogin: s.PromptLogin,
		}
	}
	return out
}

// DefaultsFromEnv builds the fallback settings from the ST_* environment.
func DefaultsFromEnv(localAuth bool, tenantID string, audiences []string, secret string) model.SignInSettings {
	s := model.SignInSettings{LocalEnabled: localAuth, TenantID: strings.ToLower(tenantID), ClientSecret: secret, PromptLogin: true}
	for _, a := range audiences {
		id := strings.TrimPrefix(strings.ToLower(a), "api://")
		if !strings.Contains(id, "/") && id != "" {
			s.ClientID = id
			break
		}
	}
	s.EntraEnabled = s.TenantID != "" && s.ClientID != ""
	return s
}
