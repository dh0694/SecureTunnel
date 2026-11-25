package signin

import (
	"context"
	"testing"
	"time"

	"securetunnel/server/internal/localauth"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

func TestSettingsAndLocalRouting(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	hash, _ := localauth.HashPassword("correct horse battery")
	u := model.User{Username: "testuser", PasswordHash: hash, Role: model.RoleUser, CreatedAt: time.Now()}
	if err := st.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	la := &localauth.Authenticator{Store: st, TokenKey: []byte("0123456789abcdef0123456789abcdef"), TokenTTL: time.Minute}
	m := &Manager{Store: st, Local: la, Defaults: DefaultsFromEnv(true, "", nil, "")}

	tok, _, err := la.IssueToken(u, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(ctx, tok); err != nil {
		t.Fatalf("local token with local on: %v", err)
	}
	if cfg := m.Client(ctx); !cfg.Local || cfg.Entra != nil {
		t.Fatalf("client config = %+v", cfg)
	}

	// Turning on Entra needs valid IDs.
	bad := model.SignInSettings{EntraEnabled: true, TenantID: "nope", ClientID: "x"}
	if err := m.Save(ctx, bad); err == nil {
		t.Fatal("bad tenant ID accepted")
	}
	if err := m.Save(ctx, model.SignInSettings{}); err == nil {
		t.Fatal("no sign-in method accepted")
	}
	s := model.SignInSettings{EntraEnabled: true, TenantID: " 11111111-2222-3333-4444-555555555555 ",
		ClientID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", ClientSecret: "s3cret", PromptLogin: true}
	if err := m.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(ctx, tok); err == nil {
		t.Fatal("local token accepted with local accounts off")
	}
	cfg := m.Client(ctx)
	if cfg.Local || cfg.Entra == nil || cfg.Entra.Scope != "api://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/access_as_user" {
		t.Fatalf("client config = %+v / %+v", cfg, cfg.Entra)
	}
	// An empty secret keeps the saved one.
	s.ClientSecret = ""
	s.LocalEnabled = true
	if err := m.Save(ctx, s); err != nil {
		t.Fatal(err)
	}
	if got := m.Get(ctx); got.ClientSecret != "s3cret" || !got.LocalEnabled {
		t.Fatalf("settings = %+v", got)
	}
}

func TestDefaultsFromEnv(t *testing.T) {
	s := DefaultsFromEnv(true, "T-ID", []string{"api://ABC", "abc"}, "")
	if !s.EntraEnabled || s.ClientID != "abc" || s.TenantID != "t-id" {
		t.Fatalf("%+v", s)
	}
	if s := DefaultsFromEnv(true, "", nil, ""); s.EntraEnabled {
		t.Fatalf("%+v", s)
	}
}

func TestRoleFromEntra(t *testing.T) {
	cases := map[string][]string{
		model.RoleAdmin:    {"SecureTunnel.Helpdesk", "SecureTunnel.Admin"},
		model.RoleHelpdesk: {"Other", "SecureTunnel.Helpdesk"},
		"":                 {"Other"},
	}
	for want, roles := range cases {
		if got := model.RoleFromEntra(roles); got != want {
			t.Errorf("RoleFromEntra(%v) = %q, want %q", roles, got, want)
		}
	}
}

func TestEntraUserCantUsePassword(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.CreateUser(ctx, model.User{Username: "jane@contoso.com", Role: model.RoleUser, Source: "entra"})
	la := &localauth.Authenticator{Store: st, TokenKey: []byte("0123456789abcdef0123456789abcdef")}
	if _, _, err := la.Login(ctx, "jane@contoso.com", "", "", "1.2.3.4"); err == nil {
		t.Fatal("Entra user signed in with a password")
	}
}
