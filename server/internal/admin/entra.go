package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"securetunnel/server/internal/auth"
	"securetunnel/server/internal/model"
)

// Admin site sign-in with Microsoft: OpenID Connect authorization code flow
// with PKCE and the app's client secret. Access comes from the Entra app
// roles SecureTunnel.Admin / SecureTunnel.Helpdesk in the ID token. The local
// admin account keeps working as break-glass.

const oidcCookie = "st_oidc"

type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Exp      int64  `json:"e"`
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) redirectURI(r *http.Request) string {
	base := strings.TrimRight(s.PublicURL, "/")
	if base == "" {
		base = "https://" + r.Host
	}
	return base + "/admin/auth/entra/callback"
}

// authConfig tells the sign-in page which buttons to show.
func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	entra := false
	if s.SignIn != nil {
		cur := s.SignIn.Get(r.Context())
		entra = cur.EntraReady() && cur.ClientSecret != ""
	}
	writeJSON(w, http.StatusOK, map[string]bool{"local": true, "entra": entra})
}

func ssoFail(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/admin/?sso_error="+url.QueryEscape(msg), http.StatusFound)
}

func (s *Server) entraStart(w http.ResponseWriter, r *http.Request) {
	if s.SignIn == nil {
		ssoFail(w, r, "Microsoft sign-in isn't set up.")
		return
	}
	cur := s.SignIn.Get(r.Context())
	if !cur.EntraReady() || cur.ClientSecret == "" {
		ssoFail(w, r, "Microsoft sign-in isn't set up. Sign in with the local admin account and finish Settings → Sign-in.")
		return
	}
	st := oidcState{State: randToken(), Nonce: randToken(), Verifier: randToken(), Exp: s.now().Add(10 * time.Minute).Unix()}
	b, _ := json.Marshal(st)
	// SameSite=Lax: the cookie must come back on the top-level redirect from Microsoft.
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: s.signRaw(b), Path: "/admin/auth/", HttpOnly: true,
		Secure: s.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	sum := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"client_id":             {cur.ClientID},
		"response_type":         {"code"},
		"redirect_uri":          {s.redirectURI(r)},
		"response_mode":         {"query"},
		"scope":                 {"openid profile email"},
		"state":                 {st.State},
		"nonce":                 {st.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
		"prompt":                {"select_account"},
	}
	http.Redirect(w, r, "https://login.microsoftonline.com/"+cur.TenantID+"/oauth2/v2.0/authorize?"+q.Encode(), http.StatusFound)
}

func (s *Server) entraCallback(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/admin/auth/", MaxAge: -1, HttpOnly: true,
		Secure: s.SecureCookie, SameSite: http.SameSiteLaxMode})
	if s.SignIn == nil {
		ssoFail(w, r, "Microsoft sign-in isn't set up.")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		desc := q.Get("error_description")
		if i := strings.Index(desc, "\r"); i > 0 {
			desc = desc[:i]
		}
		if len(desc) > 300 {
			desc = desc[:300]
		}
		s.Log.Warn("admin entra sign-in error", "error", e, "desc", desc)
		ssoFail(w, r, "Microsoft sign-in failed: "+e+" "+desc)
		return
	}
	ck, err := r.Cookie(oidcCookie)
	var st oidcState
	if err == nil {
		if b, ok := s.verifyRaw(ck.Value); ok {
			_ = json.Unmarshal(b, &st)
		}
	}
	if st.State == "" || s.now().Unix() > st.Exp || q.Get("state") != st.State {
		ssoFail(w, r, "That sign-in link expired. Try again.")
		return
	}
	cur := s.SignIn.Get(r.Context())
	if !cur.EntraReady() || cur.ClientSecret == "" {
		ssoFail(w, r, "Microsoft sign-in isn't set up.")
		return
	}
	idToken, err := s.exchangeCode(r.Context(), cur, q.Get("code"), st.Verifier, s.redirectURI(r))
	if err != nil {
		s.Log.Warn("admin entra code exchange", "err", err)
		ssoFail(w, r, "Couldn't finish Microsoft sign-in: "+err.Error())
		return
	}
	c, err := auth.ValidateIDToken(r.Context(), s.SignIn.Keys(cur.TenantID), idToken, cur.TenantID, cur.ClientID, st.Nonce, s.now())
	if err != nil {
		s.Log.Warn("admin entra id token", "err", err)
		ssoFail(w, r, "Microsoft sign-in couldn't be verified.")
		return
	}
	role := model.RoleFromEntra(c.Roles)
	if role == "" {
		s.audit(r.Context(), c.UPN, "admin.login_failed", "", "Entra user has no SecureTunnel admin role, from "+clientIP(r))
		ssoFail(w, r, c.UPN+" doesn't have access to the admin site. Ask an admin to assign you the SecureTunnel Admin or Helpdesk role in Entra.")
		return
	}
	if u, err := s.Store.GetUser(r.Context(), c.UPN); err == nil && u.Disabled {
		ssoFail(w, r, c.UPN+" is disabled on the admin site.")
		return
	}
	ttl := s.CookieTTL
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	name := c.Name
	if name == "" {
		name = c.UPN
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.sign(cookieClaims{User: c.UPN, Exp: s.now().Add(ttl).Unix(), Src: "entra", Role: role, Name: name}),
		Path: "/admin", HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode,
		MaxAge: int(ttl / time.Second),
	})
	s.audit(r.Context(), c.UPN, "admin.login", "", "Microsoft sign-in ("+role+") from "+clientIP(r))
	// A page rather than a redirect: the browser then loads /admin/ as a
	// same-site navigation and sends the SameSite=Strict cookie.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `<!doctype html><meta http-equiv="refresh" content="0;url=/admin/"><title>Signing in…</title><p>Signing in… <a href="/admin/">Continue</a></p>`)
}

var tokenClient = &http.Client{Timeout: 15 * time.Second}

func (s *Server) exchangeCode(ctx context.Context, cur model.SignInSettings, code, verifier, redirect string) (string, error) {
	if code == "" {
		return "", errors.New("no code")
	}
	form := url.Values{
		"client_id":     {cur.ClientID},
		"client_secret": {cur.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
		"scope":         {"openid profile email"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://login.microsoftonline.com/"+cur.TenantID+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := tokenClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
		Desc    string `json:"error_description"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("token response: %w", err)
	}
	if out.Error != "" {
		d := out.Desc
		if i := strings.IndexAny(d, "\r\n"); i > 0 {
			d = d[:i]
		}
		return "", fmt.Errorf("%s: %s", out.Error, d)
	}
	if out.IDToken == "" {
		return "", errors.New("no id_token in response")
	}
	return out.IDToken, nil
}

// ---- Sign-in settings (Policies page) ----

type signInView struct {
	LocalEnabled  bool     `json:"local_enabled"`
	EntraEnabled  bool     `json:"entra_enabled"`
	TenantID      string   `json:"tenant_id"`
	ClientID      string   `json:"client_id"`
	HasSecret     bool     `json:"has_secret"`
	PromptLogin   bool     `json:"prompt_login"`
	AdminRedirect string   `json:"admin_redirect_uri"`
	AgentRedirect string   `json:"agent_redirect_uri"`
	Scope         string   `json:"scope"`
	Roles         []string `json:"roles"`
}

func (s *Server) getSignIn(w http.ResponseWriter, r *http.Request) {
	if s.SignIn == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	cur := s.SignIn.Get(r.Context())
	v := signInView{LocalEnabled: cur.LocalEnabled, EntraEnabled: cur.EntraEnabled, TenantID: cur.TenantID,
		ClientID: cur.ClientID, HasSecret: cur.ClientSecret != "", PromptLogin: cur.PromptLogin,
		AdminRedirect: s.redirectURI(r), AgentRedirect: "http://localhost",
		Roles: []string{model.EntraRoleAdmin, model.EntraRoleHelpdesk}}
	if cur.ClientID != "" {
		v.Scope = cur.APIScope()
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) setSignIn(w http.ResponseWriter, r *http.Request) {
	if s.SignIn == nil {
		writeErr(w, http.StatusNotFound, "not_found", "not available")
		return
	}
	var body model.SignInSettings
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.SignIn.Save(r.Context(), body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	detail := fmt.Sprintf("local=%t entra=%t tenant=%s client=%s prompt_login=%t", body.LocalEnabled, body.EntraEnabled,
		body.TenantID, body.ClientID, body.PromptLogin)
	if body.ClientSecret != "" {
		detail += " secret=changed"
	}
	s.audit(r.Context(), current(r).Username, "settings.signin", "", detail)
	s.getSignIn(w, r)
}
