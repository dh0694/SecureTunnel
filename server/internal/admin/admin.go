// Package admin serves the admin website (/admin/) and its JSON API (/admin/api/).
//
// Sign-in uses local accounts with the admin or helpdesk role. The session is a
// signed, HttpOnly, SameSite=Strict cookie; state-changing requests also need
// the X-ST-Admin header, which a cross-site page cannot send without CORS.
package admin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/skip2/go-qrcode"

	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/devicetrust"
	"securetunnel/server/internal/duo"
	"securetunnel/server/internal/hostmetrics"
	"securetunnel/server/internal/localauth"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/policies"
	"securetunnel/server/internal/realip"
	"securetunnel/server/internal/session"
	"securetunnel/server/internal/signin"
	"securetunnel/server/internal/store"
)

//go:embed web
var webFS embed.FS

const cookieName = "st_admin"

// Server is the admin site.
type Server struct {
	Store        store.Store
	Sessions     *session.Service
	Auth         *localauth.Authenticator
	CookieKey    []byte
	CookieTTL    time.Duration // default 8h
	SecureCookie bool          // false only for plain-HTTP dev
	HealthTTL    time.Duration // gateway health freshness
	History      *hostmetrics.History
	DBSize       func(context.Context) (int64, error) // may be nil (in-memory store)
	LatestClient func() string                        // current Windows agent version; may be nil
	SignIn       *signin.Manager                      // sign-in settings + Entra; may be nil
	Trust        *devicetrust.Checker                 // device trust policy; may be nil
	Groups       *policies.Manager                    // groups and policies; may be nil
	HostLabel    string                               // this control server's name (HA view)
	DBStats      func(context.Context) (any, error)   // may be nil (in-memory store)
	LBStats      func(context.Context) (any, error)   // may be nil (no load balancer)
	Duo          *duo.Service                         // Duo settings; may be nil
	PublicURL    string                               // e.g. https://vpn.example.com (for the Entra redirect URI)
	Log          *slog.Logger
	Now          func() time.Time
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Register adds the admin routes to mux.
func (s *Server) Register(mux *http.ServeMux) {
	static, _ := fs.Sub(webFS, "web")
	files := http.FileServer(http.FS(static))
	mux.Handle("GET /admin/", http.StripPrefix("/admin/", noCache(files)))
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	})

	mux.HandleFunc("POST /admin/api/login", s.csrf(s.login))
	mux.HandleFunc("GET /admin/api/auth-config", s.authConfig)
	mux.HandleFunc("GET /admin/auth/entra/start", s.entraStart)
	mux.HandleFunc("GET /admin/auth/entra/callback", s.entraCallback)
	mux.HandleFunc("GET /admin/api/settings/servers", s.need(model.RoleHelpdesk, s.getServers))
	mux.HandleFunc("POST /admin/api/settings/servers", s.csrf(s.need(model.RoleAdmin, s.setServers)))
	mux.HandleFunc("GET /admin/api/policies", s.need(model.RoleHelpdesk, s.getPolicies))
	mux.HandleFunc("POST /admin/api/policies", s.csrf(s.need(model.RoleAdmin, s.setPolicies)))
	mux.HandleFunc("GET /admin/api/policies/explain", s.need(model.RoleHelpdesk, s.explainPolicies))
	mux.HandleFunc("GET /admin/api/entra/groups", s.need(model.RoleAdmin, s.searchEntraGroups))
	mux.HandleFunc("GET /admin/api/settings/duo", s.need(model.RoleHelpdesk, s.getDuo))
	mux.HandleFunc("POST /admin/api/settings/duo", s.csrf(s.need(model.RoleAdmin, s.setDuo)))
	mux.HandleFunc("POST /admin/api/settings/duo/test", s.csrf(s.need(model.RoleAdmin, s.testDuo)))
	mux.HandleFunc("GET /admin/api/settings/devicetrust", s.need(model.RoleHelpdesk, s.getDeviceTrust))
	mux.HandleFunc("POST /admin/api/settings/devicetrust", s.csrf(s.need(model.RoleAdmin, s.setDeviceTrust)))
	mux.HandleFunc("GET /admin/api/settings/signin", s.need(model.RoleHelpdesk, s.getSignIn))
	mux.HandleFunc("POST /admin/api/settings/signin", s.csrf(s.need(model.RoleAdmin, s.setSignIn)))
	mux.HandleFunc("POST /admin/api/logout", s.csrf(s.logout))
	mux.HandleFunc("GET /admin/api/me", s.need(model.RoleHelpdesk, s.me))
	mux.HandleFunc("GET /admin/api/summary", s.need(model.RoleHelpdesk, s.summary))
	mux.HandleFunc("GET /admin/api/sessions", s.need(model.RoleHelpdesk, s.listSessions))
	mux.HandleFunc("POST /admin/api/sessions/{id}/disconnect", s.csrf(s.need(model.RoleHelpdesk, s.disconnect)))
	mux.HandleFunc("POST /admin/api/sessions/{id}/command", s.csrf(s.need(model.RoleHelpdesk, s.sendCommand)))
	mux.HandleFunc("GET /admin/api/logs", s.need(model.RoleHelpdesk, s.listLogs))
	mux.HandleFunc("GET /admin/api/logs/{id}/download", s.need(model.RoleHelpdesk, s.downloadLogs))
	mux.HandleFunc("POST /admin/api/sessions/{id}/move", s.csrf(s.need(model.RoleHelpdesk, s.moveSession)))
	mux.HandleFunc("POST /admin/api/gateways/{id}/drain", s.csrf(s.need(model.RoleAdmin, s.drainGateway)))
	mux.HandleFunc("GET /admin/api/gateways", s.need(model.RoleHelpdesk, s.listGateways))
	mux.HandleFunc("POST /admin/api/gateways/{id}/enabled", s.csrf(s.need(model.RoleAdmin, s.setGatewayEnabled)))
	mux.HandleFunc("POST /admin/api/gateways/{id}/pool", s.csrf(s.need(model.RoleAdmin, s.setGatewayPool)))
	mux.HandleFunc("GET /admin/api/updates", s.need(model.RoleHelpdesk, s.getUpdates))
	mux.HandleFunc("POST /admin/api/updates/push", s.csrf(s.need(model.RoleAdmin, s.pushUpdate)))
	mux.HandleFunc("GET /admin/api/audit", s.need(model.RoleHelpdesk, s.listAudit))
	mux.HandleFunc("GET /admin/api/system", s.need(model.RoleHelpdesk, s.system))
	mux.HandleFunc("GET /admin/api/settings/placement", s.need(model.RoleHelpdesk, s.getPlacement))
	mux.HandleFunc("POST /admin/api/settings/placement", s.csrf(s.need(model.RoleAdmin, s.setPlacement)))
	mux.HandleFunc("GET /admin/api/settings/speedtest", s.need(model.RoleHelpdesk, s.getSpeedPolicy))
	mux.HandleFunc("POST /admin/api/settings/speedtest", s.csrf(s.need(model.RoleAdmin, s.setSpeedPolicy)))
	mux.HandleFunc("GET /admin/api/speedtests", s.need(model.RoleHelpdesk, s.listSpeedTests))
	mux.HandleFunc("GET /admin/api/devices", s.need(model.RoleHelpdesk, s.listDevices))
	mux.HandleFunc("POST /admin/api/devices/{id}/status", s.csrf(s.need(model.RoleHelpdesk, s.setDeviceStatus)))
	mux.HandleFunc("DELETE /admin/api/devices/{id}", s.csrf(s.need(model.RoleAdmin, s.deleteDevice)))
	mux.HandleFunc("POST /admin/api/devices/approve-pending", s.csrf(s.need(model.RoleAdmin, s.approvePending)))
	mux.HandleFunc("GET /admin/api/settings/devices", s.need(model.RoleHelpdesk, s.getDevicePolicy))
	mux.HandleFunc("POST /admin/api/settings/devices", s.csrf(s.need(model.RoleAdmin, s.setDevicePolicy)))
	mux.HandleFunc("GET /admin/api/settings/device-tunnel", s.need(model.RoleHelpdesk, s.getDeviceTunnel))
	mux.HandleFunc("POST /admin/api/settings/device-tunnel", s.csrf(s.need(model.RoleAdmin, s.setDeviceTunnel)))
	mux.HandleFunc("GET /admin/api/settings/office", s.need(model.RoleHelpdesk, s.getOffice))
	mux.HandleFunc("POST /admin/api/settings/office", s.csrf(s.need(model.RoleAdmin, s.setOffice)))
	mux.HandleFunc("GET /admin/api/settings/countries", s.need(model.RoleHelpdesk, s.getCountries))
	mux.HandleFunc("POST /admin/api/settings/countries", s.csrf(s.need(model.RoleAdmin, s.setCountries)))
	mux.HandleFunc("GET /admin/api/users", s.need(model.RoleHelpdesk, s.listUsers))
	mux.HandleFunc("POST /admin/api/users", s.csrf(s.need(model.RoleAdmin, s.createUser)))
	mux.HandleFunc("POST /admin/api/users/{name}", s.csrf(s.need(model.RoleAdmin, s.updateUser)))
	mux.HandleFunc("DELETE /admin/api/users/{name}", s.csrf(s.need(model.RoleAdmin, s.deleteUser)))
	mux.HandleFunc("POST /admin/api/users/{name}/totp", s.csrf(s.need(model.RoleAdmin, s.enrollTOTP)))
	mux.HandleFunc("DELETE /admin/api/users/{name}/totp", s.csrf(s.need(model.RoleAdmin, s.removeTOTP)))
}

// ---- auth plumbing ----

type cookieClaims struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
	// Microsoft sign-ins: the role comes from Entra app roles at sign-in.
	Src  string `json:"s,omitempty"` // "" (local) or "entra"
	Role string `json:"r,omitempty"`
	Name string `json:"n,omitempty"`
}

func (s *Server) sign(c cookieClaims) string {
	b, _ := json.Marshal(c)
	return s.signRaw(b)
}

func (s *Server) signRaw(b []byte) string {
	payload := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, s.CookieKey)
	m.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) verifyRaw(v string) ([]byte, bool) {
	payload, sig, ok := strings.Cut(v, ".")
	if !ok {
		return nil, false
	}
	m := hmac.New(sha256.New, s.CookieKey)
	m.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	return b, err == nil
}

func (s *Server) verify(v string) (cookieClaims, bool) {
	b, ok := s.verifyRaw(v)
	if !ok {
		return cookieClaims{}, false
	}
	var c cookieClaims
	if json.Unmarshal(b, &c) != nil || s.now().Unix() > c.Exp {
		return cookieClaims{}, false
	}
	return c, true
}

type ctxKey struct{}

func rank(role string) int {
	switch role {
	case model.RoleAdmin:
		return 2
	case model.RoleHelpdesk:
		return 1
	}
	return 0
}

// need requires a signed-in admin-site user with at least the given role. The
// account is re-read on every request, so disabling it or changing its role
// takes effect immediately.
func (s *Server) need(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(cookieName)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "signed_out", "sign in")
			return
		}
		c, ok := s.verify(ck.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "signed_out", "sign in")
			return
		}
		var u model.User
		if c.Src == "entra" {
			// Microsoft sign-in: trust the signed cookie while Entra stays on;
			// a disabled settings row still locks the user out.
			if s.SignIn == nil || !s.SignIn.Get(r.Context()).EntraReady() {
				err = errors.New("entra off")
			} else if row, gerr := s.Store.GetUser(r.Context(), c.User); gerr == nil && row.Disabled {
				err = errors.New("disabled")
			}
			u = model.User{Username: c.User, DisplayName: c.Name, Role: c.Role, Source: "entra"}
		} else {
			u, err = s.Store.GetUser(r.Context(), c.User)
		}
		if err != nil || u.Disabled || rank(u.Role) == 0 {
			writeErr(w, http.StatusUnauthorized, "signed_out", "sign in")
			return
		}
		if rank(u.Role) < rank(role) {
			writeErr(w, http.StatusForbidden, "forbidden", "your role can't do that")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	}
}

func current(r *http.Request) model.User {
	u, _ := r.Context().Value(ctxKey{}).(model.User)
	return u
}

func (s *Server) csrf(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ST-Admin") != "1" {
			writeErr(w, http.StatusForbidden, "csrf", "missing X-ST-Admin header")
			return
		}
		h(w, r)
	}
}

func (s *Server) audit(ctx context.Context, actor, action, target, detail string) {
	if err := s.Store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		s.Log.Error("write audit log", "action", action, "err", err)
	}
}

// ---- handlers ----

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, _, err := s.Auth.Login(r.Context(), body.Username, body.Password, body.Code, clientIP(r))
	if err == nil && rank(u.Role) == 0 {
		err = errors.New("this account can't use the admin site")
	}
	if err != nil {
		code := "bad_credentials"
		if errors.Is(err, localauth.ErrTOTPRequired) {
			code = "code_required"
		}
		s.Log.Warn("admin sign-in failed", "user", body.Username, "client_ip", clientIP(r), "err", err)
		if !errors.Is(err, localauth.ErrTOTPRequired) {
			s.audit(r.Context(), strings.ToLower(body.Username), "admin.login_failed", "", err.Error()+" from "+clientIP(r))
		}
		writeErr(w, http.StatusUnauthorized, code, err.Error())
		return
	}
	ttl := s.CookieTTL
	if ttl <= 0 {
		ttl = 8 * time.Hour
	}
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: s.sign(cookieClaims{User: u.Username, Exp: s.now().Add(ttl).Unix()}),
		Path: "/admin", HttpOnly: true, Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode,
		MaxAge: int(ttl / time.Second),
	})
	s.audit(r.Context(), u.Username, "admin.login", "", "from "+clientIP(r))
	writeJSON(w, http.StatusOK, userView(u))
}

func (s *Server) logout(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/admin", MaxAge: -1, HttpOnly: true,
		Secure: s.SecureCookie, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, userView(current(r)))
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	live, err := s.Store.ListSessions(ctx, model.SessionFilter{State: "live", Limit: 100000})
	if err != nil {
		s.internal(w, err)
		return
	}
	var active, suspended int
	versions := map[string]int{}
	for _, se := range live {
		if se.State == model.StateActive {
			active++
		} else {
			suspended++
		}
		v := se.ClientVersion
		if v == "" {
			v = se.Platform // e.g. "stclient"
		}
		versions[v]++
	}
	gws, err := s.Store.ListGateways(ctx)
	if err != nil {
		s.internal(w, err)
		return
	}
	healthy := 0
	for _, g := range gws {
		if g.Enabled && s.now().Sub(g.LastHealth) <= s.HealthTTL {
			healthy++
		}
	}
	// Connects per hour for the last 24 hours, oldest first; the last bucket is the current hour.
	now := s.now()
	thisHour := now.Truncate(time.Hour)
	starts, err := s.Store.SessionStartsSince(ctx, thisHour.Add(-23*time.Hour))
	if err != nil {
		s.internal(w, err)
		return
	}
	hourly := make([]int, 24)
	for _, t := range starts {
		i := 23 - int(thisHour.Sub(t.Truncate(time.Hour))/time.Hour)
		if i >= 0 && i < 24 {
			hourly[i]++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active": active, "suspended": suspended, "connects_24h": len(starts),
		"gateways": len(gws), "gateways_healthy": healthy,
		"hourly": hourly, "hourly_end": thisHour.Add(time.Hour).UTC(),
		"client_versions": versions, "latest_client": s.latestClient(),
		"pending_devices": s.pendingDevices(ctx),
	})
}

func (s *Server) pendingDevices(ctx context.Context) int {
	list, err := s.Store.ListDevices(ctx, model.DevicePending)
	if err != nil {
		return 0
	}
	return len(list)
}

func (s *Server) latestClient() string {
	if s.LatestClient == nil {
		return ""
	}
	return s.LatestClient()
}

type sessionView struct {
	ID        string    `json:"id"`
	UPN       string    `json:"upn"`
	DeviceID  string    `json:"device_id"`
	Platform  string    `json:"platform"`
	GatewayID string    `json:"gateway_id"`
	TunnelIP  string    `json:"tunnel_ip"`
	ClientIP  string    `json:"client_ip"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	ExpiresAt time.Time `json:"expires_at"`
	EndedAt   time.Time `json:"ended_at"`
	EndReason string    `json:"end_reason"`
	Version   string    `json:"client_version"`
	Outdated  bool      `json:"outdated"`
	// Latest diagnostics reported by the agent (raw JSON, see clientapi.Diagnostics).
	Diag       json.RawMessage `json:"diag,omitempty"`
	DiagAt     time.Time       `json:"diag_at"`
	Country    string          `json:"country"`
	DeviceName string          `json:"device_name"`
	Kind       string          `json:"kind"` // "user" or "device" (pre-logon device tunnel)
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	list, err := s.Store.ListSessions(r.Context(), model.SessionFilter{
		State: r.URL.Query().Get("state"), Query: r.URL.Query().Get("q"), Limit: limit,
	})
	if err != nil {
		s.internal(w, err)
		return
	}
	latest := s.latestClient()
	out := make([]sessionView, 0, len(list))
	for _, se := range list {
		out = append(out, sessionView{
			ID: se.ID, UPN: se.UPN, DeviceID: se.DeviceID, Platform: se.Platform, GatewayID: se.GatewayID,
			TunnelIP: se.TunnelIP.String(), ClientIP: se.ClientIP, State: string(se.State),
			CreatedAt: se.CreatedAt, LastSeen: se.LastSeen, ExpiresAt: se.ExpiresAt, EndedAt: se.EndedAt, EndReason: se.EndReason,
			Version: se.ClientVersion, Outdated: se.ClientVersion != "" && clientapi.NewerVersion(latest, se.ClientVersion),
			DiagAt: se.DiagAt, Country: se.Country, DeviceName: se.DeviceName, Kind: model.SessionUser,
		})
		if se.IsDevice() {
			out[len(out)-1].Kind = model.SessionDevice
		}
		if se.Diag != "" && json.Valid([]byte(se.Diag)) {
			out[len(out)-1].Diag = json.RawMessage(se.Diag)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	err := s.Sessions.AdminDisconnect(r.Context(), r.PathValue("id"), current(r).Username)
	if errors.Is(err, session.ErrReauthRequired) {
		writeErr(w, http.StatusNotFound, "not_found", "session already ended")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type hostView struct {
	ID      string              `json:"id"`
	Kind    string              `json:"kind"` // "control" or "gateway"
	Label   string              `json:"label"`
	Site    string              `json:"site,omitempty"`
	Online  bool                `json:"online"`
	Current *model.HostMetrics  `json:"current"`
	History []model.HostMetrics `json:"history"`
	Serving bool                `json:"serving,omitempty"` // the control server answering this request
}

// system returns host metrics for this control server and every gateway, with
// the recent history this control server has seen (about 15 minutes).
func (s *Server) system(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var hosts []hostView
	// Every control server reports to the database; this one also has history.
	controls, _ := s.Store.ListControlHosts(ctx)
	seenSelf := false
	for _, c := range controls {
		self := c.Label == s.HostLabel
		v := hostView{ID: "control:" + c.Label, Kind: "control", Label: c.Label, Online: s.now().Sub(c.SeenAt) <= s.HealthTTL,
			History: []model.HostMetrics{}, Serving: self}
		m := c.Metrics
		v.Current = &m
		if self && s.History != nil {
			v.History = s.History.Get("control")
			v.Online = true
			seenSelf = true
		}
		hosts = append(hosts, v)
	}
	if !seenSelf && s.History != nil {
		h := s.History.Get("control")
		v := hostView{ID: "control:" + s.HostLabel, Kind: "control", Label: firstNonEmptyStr(s.HostLabel, "Control server"), Online: true, History: h, Serving: true}
		if len(h) > 0 {
			v.Current = &h[len(h)-1]
		}
		hosts = append([]hostView{v}, hosts...)
	}
	gws, err := s.Store.ListGateways(ctx)
	if err != nil {
		s.internal(w, err)
		return
	}
	for _, g := range gws {
		v := hostView{ID: g.ID, Kind: "gateway", Label: g.ID, Site: g.Site,
			Online: s.now().Sub(g.LastHealth) <= s.HealthTTL, History: []model.HostMetrics{}}
		if s.History != nil {
			v.History = s.History.Get("gw:" + g.ID)
		}
		if !g.Metrics.At.IsZero() {
			m := g.Metrics
			v.Current = &m
		}
		hosts = append(hosts, v)
	}
	resp := map[string]any{"hosts": hosts}
	if s.DBStats != nil {
		if st, err := s.DBStats(ctx); err == nil {
			resp["db"] = st
		} else {
			resp["db_error"] = err.Error()
		}
	}
	if s.LBStats != nil {
		if st, err := s.LBStats(ctx); err == nil {
			resp["lb"] = st
		} else {
			resp["lb_error"] = "Can't read the load balancer's stats: " + err.Error()
		}
	}
	if s.DBSize != nil {
		if n, err := s.DBSize(ctx); err == nil {
			resp["db_size"] = n
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getPlacement(w http.ResponseWriter, r *http.Request) {
	_, saved, _ := s.Store.GetPlacementPolicy(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"policy":   s.Sessions.Policy(r.Context()),
		"defaults": s.Sessions.Config().DefaultPolicy,
		"custom":   saved,
	})
}

func (s *Server) setPlacement(w http.ResponseWriter, r *http.Request) {
	var p model.PlacementPolicy
	if !readJSON(w, r, &p) {
		return
	}
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Store.SetPlacementPolicy(r.Context(), p); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.placement", "",
		fmt.Sprintf("max_cpu=%.0f%% max_mem=%.0f%% min_free_disk=%.0fGB", p.MaxCPUPercent, p.MaxMemPercent, p.MinFreeDiskGB))
	s.getPlacement(w, r)
}

func (s *Server) getSpeedPolicy(w http.ResponseWriter, r *http.Request) {
	var saved model.SpeedTestPolicy
	custom, _ := s.Store.GetSetting(r.Context(), "speedtest_policy", &saved)
	writeJSON(w, http.StatusOK, map[string]any{
		"policy": s.Sessions.SpeedTestPolicy(r.Context()), "defaults": model.DefaultSpeedTestPolicy, "custom": custom,
	})
}

func (s *Server) setSpeedPolicy(w http.ResponseWriter, r *http.Request) {
	var p model.SpeedTestPolicy
	if !readJSON(w, r, &p) {
		return
	}
	p.Host = strings.ToLower(strings.TrimSpace(p.Host))
	if err := p.Validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Store.SetSetting(r.Context(), "speedtest_policy", p); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.speedtest", "",
		fmt.Sprintf("every=%dh size=%dMB host=%s", p.IntervalHours, p.SizeMB, p.Host))
	s.getSpeedPolicy(w, r)
}

// sendCommand asks a connected agent to run a speed test, send fresh
// diagnostics, or show a message to the user.
func (s *Server) sendCommand(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Text = strings.TrimSpace(body.Text)
	switch body.Type {
	case "speedtest", "diagnostics", "logs":
		body.Text = ""
	case "message":
		if body.Text == "" || len(body.Text) > 500 {
			writeErr(w, http.StatusBadRequest, "bad_request", "write a message of up to 500 characters")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "unknown command")
		return
	}
	c, err := s.Sessions.SendCommand(r.Context(), r.PathValue("id"), current(r).Username, body.Type, body.Text)
	if errors.Is(err, session.ErrReauthRequired) {
		writeErr(w, http.StatusNotFound, "not_found", "that session has ended")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// deviceView is a device plus whether it's connected right now.
type deviceView struct {
	model.Device
	Connected bool `json:"connected"` // has an active (not reconnecting) session
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListDevices(r.Context(), r.URL.Query().Get("status"))
	if err != nil {
		s.internal(w, err)
		return
	}
	live := map[string]bool{}
	if sess, err := s.Store.ListSessions(r.Context(), model.SessionFilter{State: "live", Limit: 100000}); err == nil {
		for _, se := range sess {
			if se.State == model.StateActive {
				live[se.DeviceID] = true
			}
		}
	}
	out := make([]deviceView, 0, len(list))
	for _, d := range list {
		out = append(out, deviceView{Device: d, Connected: live[d.ID]})
	}
	writeJSON(w, http.StatusOK, out)
}

// setDeviceStatus approves or blocks a device. Helpdesk may approve; only
// admins may block or un-block.
func (s *Server) setDeviceStatus(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Status string `json:"status"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	switch body.Status {
	case model.DeviceApproved, model.DevicePending:
	case model.DeviceBlocked:
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "status must be approved, pending or blocked")
		return
	}
	me := current(r)
	id := r.PathValue("id")
	if err := s.Store.SetDeviceStatus(r.Context(), id, body.Status, me.Username, me.Role == model.RoleAdmin, s.now()); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such device")
		return
	} else if errors.Is(err, store.ErrDeviceBlocked) {
		writeErr(w, http.StatusForbidden, "forbidden", "only admins can block, unblock or reset devices")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), me.Username, "device."+map[string]string{
		model.DeviceApproved: "approve", model.DevicePending: "reset", model.DeviceBlocked: "block",
	}[body.Status], id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeleteDevice(r.Context(), id); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such device")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "device.remove", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) approvePending(w http.ResponseWriter, r *http.Request) {
	n, err := s.Store.ApprovePending(r.Context(), current(r).Username, s.now())
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "device.approve_all", "", fmt.Sprintf("%d devices", n))
	writeJSON(w, http.StatusOK, map[string]int{"approved": n})
}

func (s *Server) getDevicePolicy(w http.ResponseWriter, r *http.Request) {
	// The Devices page switch shows and edits the Default device approval policy.
	for _, p := range s.Groups.Set(r.Context()).Policies {
		if p.Default && p.Type == model.PolicyApproval && p.Approval != nil {
			writeJSON(w, http.StatusOK, *p.Approval)
			return
		}
	}
	writeJSON(w, http.StatusOK, s.Sessions.DevicePolicy(r.Context()))
}

func (s *Server) setDevicePolicy(w http.ResponseWriter, r *http.Request) {
	var p model.DevicePolicy
	if !readJSON(w, r, &p) {
		return
	}
	if err := s.Store.SetSetting(r.Context(), "device_policy", p); err != nil {
		s.internal(w, err)
		return
	}
	ps := s.Groups.Set(r.Context())
	ps.Policies = append([]model.Policy{}, ps.Policies...)
	for i := range ps.Policies {
		if ps.Policies[i].Default && ps.Policies[i].Type == model.PolicyApproval {
			v := p
			ps.Policies[i].Approval = &v
		}
	}
	if _, err := s.Groups.Save(r.Context(), ps); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.devices", "", fmt.Sprintf("require_approval=%v", p.RequireApproval))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) getDeviceTunnel(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Sessions.DeviceTunnelPolicy(r.Context()))
}

func (s *Server) setDeviceTunnel(w http.ResponseWriter, r *http.Request) {
	var p model.DeviceTunnelPolicy
	if !readJSON(w, r, &p) {
		return
	}
	if err := p.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Store.SetSetting(r.Context(), session.DeviceTunnelKey, p); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.device_tunnel", "",
		fmt.Sprintf("enabled=%v subnets=%s dns=%s", p.Enabled, strings.Join(p.Subnets, ","), strings.Join(p.DNS, ",")))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) getOffice(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Sessions.OfficePolicy(r.Context()))
}

func (s *Server) setOffice(w http.ResponseWriter, r *http.Request) {
	var p model.OfficeNetworkPolicy
	if !readJSON(w, r, &p) {
		return
	}
	if err := p.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Store.SetSetting(r.Context(), "office_networks", p); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.office_networks", "",
		fmt.Sprintf("enabled=%v suffixes=%s subnets=%s public_ips=%s", p.Enabled,
			strings.Join(p.DNSSuffixes, ","), strings.Join(p.LocalSubnets, ","), strings.Join(p.PublicIPs, ",")))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) getCountries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Sessions.CountryPolicy(r.Context()))
}

func (s *Server) setCountries(w http.ResponseWriter, r *http.Request) {
	var p model.CountryPolicy
	if !readJSON(w, r, &p) {
		return
	}
	if err := p.Normalize(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Store.SetSetting(r.Context(), "country_policy", p); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "settings.countries", "",
		fmt.Sprintf("enabled=%v default=%s block_unknown=%v", p.Enabled, strings.Join(p.Default, ","), p.BlockUnknown))
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) listSpeedTests(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	list, err := s.Store.ListSpeedTests(r.Context(), r.URL.Query().Get("device"), limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	if list == nil {
		list = []model.SpeedTest{}
	}
	writeJSON(w, http.StatusOK, list)
}

type gatewayView struct {
	Accepting   bool               `json:"accepting"`   // takes new sessions under the placement policy
	OverLimits  string             `json:"over_limits"` // which limits it breaks, if any
	Metrics     *model.HostMetrics `json:"metrics,omitempty"`
	ID          string             `json:"id"`
	Site        string             `json:"site"`
	Endpoint    string             `json:"endpoint"`
	PublicKey   string             `json:"public_key"`
	Pool        string             `json:"pool"`
	Capacity    int                `json:"capacity"`
	Enabled     bool               `json:"enabled"`
	Healthy     bool               `json:"healthy"`
	LastHealth  time.Time          `json:"last_health"`
	ActivePeers int                `json:"active_peers"`
	Sessions    int                `json:"sessions"` // live sessions placed here (database)
}

func (s *Server) listGateways(w http.ResponseWriter, r *http.Request) {
	gws, err := s.Store.ListGateways(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	counts, err := s.Store.LiveCounts(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	policy := s.Sessions.Policy(r.Context())
	out := make([]gatewayView, 0, len(gws))
	for _, g := range gws {
		v := gatewayView{
			ID: g.ID, Site: g.Site, Endpoint: g.Endpoint, PublicKey: g.PublicKey, Pool: g.Pool.String(),
			Capacity: g.Capacity, Enabled: g.Enabled, Healthy: g.Enabled && s.now().Sub(g.LastHealth) <= s.HealthTTL,
			LastHealth: g.LastHealth, ActivePeers: g.ActivePeers, Sessions: counts[g.ID],
		}
		within, why := session.CheckResources(g.Metrics, policy, s.now(), s.HealthTTL)
		v.OverLimits = why
		v.Accepting = v.Healthy && within && counts[g.ID] < g.Capacity
		if !g.Metrics.At.IsZero() {
			m := g.Metrics
			v.Metrics = &m
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setGatewayEnabled(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if err := s.Store.SetGatewayEnabled(r.Context(), id, body.Enabled); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such gateway")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	action := "gateway.disable"
	if body.Enabled {
		action = "gateway.enable"
	}
	s.audit(r.Context(), current(r).Username, action, id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	list, err := s.Store.ListAudit(r.Context(), limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	if list == nil {
		list = []model.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, list)
}

type userOut struct {
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	Role        string    `json:"role"`
	Source      string    `json:"source"`
	PolicyGroup string    `json:"policy_group"`
	Disabled    bool      `json:"disabled"`
	MFA         bool      `json:"mfa"`
	CreatedAt   time.Time `json:"created_at"`
	LastLogin   time.Time `json:"last_login"`

	AllowedCountries []string  `json:"allowed_countries"`
	TravelCountries  []string  `json:"travel_countries"`
	TravelUntil      time.Time `json:"travel_until"`
}

func userView(u model.User) userOut {
	src := u.Source
	if src == "" {
		src = "local"
	}
	o := userOut{Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Source: src, PolicyGroup: u.PolicyGroup, Disabled: u.Disabled,
		MFA: u.TOTPSecret != "", CreatedAt: u.CreatedAt, LastLogin: u.LastLogin,
		AllowedCountries: u.AllowedCountries, TravelCountries: u.TravelCountries, TravelUntil: u.TravelUntil}
	if o.AllowedCountries == nil {
		o.AllowedCountries = []string{}
	}
	if o.TravelCountries == nil {
		o.TravelCountries = []string{}
	}
	return o
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListUsers(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]userOut, 0, len(list))
	for _, u := range list {
		out = append(out, userView(u))
	}
	writeJSON(w, http.StatusOK, out)
}

func validUsername(n string) bool {
	if len(n) < 2 || len(n) > 64 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' || c == '@') {
			return false
		}
	}
	return true
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		Source      string `json:"source"` // "local" (default) or "entra"
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Username = strings.ToLower(strings.TrimSpace(body.Username))
	if !validUsername(body.Username) {
		writeErr(w, http.StatusBadRequest, "bad_request", "username: 2-64 characters, letters, digits, . - _ @")
		return
	}
	if body.Source == "entra" {
		// Settings for an Entra user (countries, disable). They sign in with
		// Microsoft; admin site access comes from Entra app roles.
		if !strings.Contains(body.Username, "@") {
			writeErr(w, http.StatusBadRequest, "bad_request", "enter the user's Entra sign-in name, like jsmith@contoso.com")
			return
		}
		u := model.User{Username: body.Username, DisplayName: strings.TrimSpace(body.DisplayName), Role: model.RoleUser,
			Source: "entra", CreatedAt: s.now()}
		if err := s.Store.CreateUser(r.Context(), u); errors.Is(err, store.ErrExists) {
			writeErr(w, http.StatusConflict, "exists", "that user is already listed")
			return
		} else if err != nil {
			s.internal(w, err)
			return
		}
		s.audit(r.Context(), current(r).Username, "user.create", u.Username, "entra user")
		writeJSON(w, http.StatusCreated, userView(u))
		return
	}
	if !model.ValidRole(body.Role) {
		writeErr(w, http.StatusBadRequest, "bad_request", "role must be admin, helpdesk or user")
		return
	}
	hash, err := localauth.HashPassword(body.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	u := model.User{Username: body.Username, DisplayName: strings.TrimSpace(body.DisplayName), PasswordHash: hash,
		Role: body.Role, CreatedAt: s.now()}
	if err := s.Store.CreateUser(r.Context(), u); errors.Is(err, store.ErrExists) {
		writeErr(w, http.StatusConflict, "exists", "that username is taken")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "user.create", u.Username, "role="+u.Role)
	writeJSON(w, http.StatusCreated, userView(u))
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisplayName      *string   `json:"display_name"`
		Password         *string   `json:"password"`
		Role             *string   `json:"role"`
		Disabled         *bool     `json:"disabled"`
		AllowedCountries *[]string `json:"allowed_countries"`
		TravelCountries  *[]string `json:"travel_countries"`
		TravelUntil      *string   `json:"travel_until"` // YYYY-MM-DD (end of that day UTC), or "" to clear
		PolicyGroup      *string   `json:"policy_group"` // group ID, or "" for automatic
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, err := s.Store.GetUser(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such user")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	me := current(r)
	if u.Source == "entra" && (body.Password != nil || body.Role != nil) {
		writeErr(w, http.StatusBadRequest, "bad_request", "Entra users sign in with Microsoft; manage their password and admin roles in Entra")
		return
	}
	var changes []string
	if body.DisplayName != nil {
		u.DisplayName = strings.TrimSpace(*body.DisplayName)
		changes = append(changes, "display_name")
	}
	if body.Password != nil {
		hash, err := localauth.HashPassword(*body.Password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		u.PasswordHash = hash
		changes = append(changes, "password")
	}
	if body.Role != nil {
		if !model.ValidRole(*body.Role) {
			writeErr(w, http.StatusBadRequest, "bad_request", "role must be admin, helpdesk or user")
			return
		}
		if u.Username == me.Username && *body.Role != model.RoleAdmin {
			writeErr(w, http.StatusBadRequest, "bad_request", "you can't remove your own admin role")
			return
		}
		u.Role = *body.Role
		changes = append(changes, "role="+u.Role)
	}
	if body.Disabled != nil {
		if u.Username == me.Username && *body.Disabled {
			writeErr(w, http.StatusBadRequest, "bad_request", "you can't disable your own account")
			return
		}
		u.Disabled = *body.Disabled
		changes = append(changes, "disabled="+strconv.FormatBool(u.Disabled))
	}
	if body.AllowedCountries != nil {
		list, err := model.NormalizeCountries(*body.AllowedCountries)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		u.AllowedCountries = list
		changes = append(changes, "countries="+strings.Join(list, ","))
	}
	if body.TravelCountries != nil {
		list, err := model.NormalizeCountries(*body.TravelCountries)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		u.TravelCountries = list
		changes = append(changes, "travel="+strings.Join(list, ","))
	}
	if body.TravelUntil != nil {
		if *body.TravelUntil == "" {
			u.TravelUntil = time.Time{}
		} else {
			d, err := time.Parse("2006-01-02", *body.TravelUntil)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "bad_request", "travel end date must be YYYY-MM-DD")
				return
			}
			u.TravelUntil = d.Add(24*time.Hour - time.Second) // through the end of that day (UTC)
		}
		changes = append(changes, "travel_until="+*body.TravelUntil)
	}
	// body.PolicyGroup is ignored: users are put in groups on the Groups page
	// now (the old per-user pick was migrated into those groups).
	if err := s.Store.UpdateUser(r.Context(), u); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), me.Username, "user.update", u.Username, strings.Join(changes, " "))
	writeJSON(w, http.StatusOK, userView(u))
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(r.PathValue("name"))
	if name == current(r).Username {
		writeErr(w, http.StatusBadRequest, "bad_request", "you can't delete your own account")
		return
	}
	if err := s.Store.DeleteUser(r.Context(), name); errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such user")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "user.delete", name, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enrollTOTP(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such user")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	secret, err := localauth.NewTOTPSecret()
	if err != nil {
		s.internal(w, err)
		return
	}
	u.TOTPSecret = secret
	if err := s.Store.UpdateUser(r.Context(), u); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "user.mfa_enroll", u.Username, "")
	uri := localauth.TOTPURI("SecureTunnel", u.Username, secret)
	resp := map[string]string{"secret": secret, "uri": uri}
	if png, err := qrcode.Encode(uri, qrcode.Medium, 240); err == nil {
		resp["qr"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) removeTOTP(w http.ResponseWriter, r *http.Request) {
	u, err := s.Store.GetUser(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such user")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	u.TOTPSecret = ""
	if err := s.Store.UpdateUser(r.Context(), u); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r.Context(), current(r).Username, "user.mfa_remove", u.Username, "")
	w.WriteHeader(http.StatusNoContent)
}

// ---- helpers ----

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.Log.Error("admin request failed", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal", "internal error")
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string { return realip.From(r) }

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
