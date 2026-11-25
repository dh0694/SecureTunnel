// Package api is the control server's HTTP interface for clients and gateways.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"securetunnel/server/internal/auth"
	"securetunnel/server/internal/hostmetrics"
	"securetunnel/server/internal/ipam"
	"securetunnel/server/internal/devicetrust"
	"securetunnel/server/internal/duo"
	"securetunnel/server/internal/policies"
	"securetunnel/server/internal/localauth"
	"securetunnel/server/internal/signin"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/realip"
	"securetunnel/server/internal/session"
	"securetunnel/server/internal/store"
)

// TunnelDefaults are pushed to every client with its tunnel config.
type TunnelDefaults struct {
	DNS        []string
	AllowedIPs []string
	MTU        int
	Keepalive  int // seconds
}

// TokenValidator verifies an Entra access token.
type TokenValidator interface {
	Validate(ctx context.Context, raw string) (model.Identity, error)
}

// Server wires HTTP handlers to the session service.
type Server struct {
	Tokens    TokenValidator
	LocalAuth *localauth.Authenticator // nil disables POST /v1/auth/local
	SignIn    *signin.Manager          // live sign-in settings; may be nil (tests)
	Trust     *devicetrust.Checker     // device trust checks; may be nil (tests)
	Groups    *policies.Manager        // groups and policies; nil = the defaults (tests)
	Duo       *duo.Service             // Duo push for groups that require it; may be nil
	Sessions *session.Service
	Store    store.Store
	Tunnel   TunnelDefaults
	Ping     func(context.Context) error // database health for /healthz; may be nil
	History  *hostmetrics.History        // recent gateway metrics for the admin site; may be nil
	Log      *slog.Logger
	Now      func() time.Time
}

// Register adds the client and gateway routes to mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("POST /v1/auth/local", s.localLogin)
	mux.HandleFunc("GET /v1/client/auth-config", s.authConfig)
	mux.HandleFunc("GET /v1/auth/challenge", s.challenge)
	mux.HandleFunc("GET /v1/auth/duo/status", s.duoStatus)
	mux.HandleFunc("POST /v1/client/logs", s.uploadLogs)

	mux.HandleFunc("POST /v1/sessions", s.connect)
	mux.HandleFunc("POST /v1/sessions/device", s.connectDevice)
	mux.HandleFunc("POST /v1/sessions/{id}/heartbeat", s.heartbeat)
	mux.HandleFunc("POST /v1/sessions/{id}/resume", s.heartbeat) // same rules; separate path for logs/metrics
	mux.HandleFunc("POST /v1/sessions/{id}/failover", s.failover)
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.disconnect)
	mux.HandleFunc("GET /v1/sessions/{id}/watch", s.watch)
	mux.HandleFunc("GET /v1/sessions/{id}/speedtest/down", s.speedDown)
	mux.HandleFunc("POST /v1/sessions/{id}/speedtest/up", s.speedUp)
	mux.HandleFunc("POST /v1/sessions/{id}/speedtest/result", s.speedReport)

	mux.HandleFunc("GET /v1/gateway/peers", s.gatewayPeers)
	mux.HandleFunc("POST /v1/gateway/health", s.gatewayHealth)
}

// localLogin signs a local account in and returns a short-lived connect token,
// which the client then presents to POST /v1/sessions like an Entra token.
func (s *Server) localLogin(w http.ResponseWriter, r *http.Request) {
	if s.LocalAuth == nil || (s.SignIn != nil && !s.SignIn.LocalEnabled(r.Context())) {
		writeErr(w, http.StatusNotFound, "not_enabled", "Local accounts are turned off. Use Sign in with Microsoft.")
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, usedTOTP, err := s.LocalAuth.Login(r.Context(), body.Username, body.Password, body.Code, clientIP(r))
	if err != nil {
		code := "bad_credentials"
		switch {
		case errors.Is(err, localauth.ErrTOTPRequired):
			code = "code_required"
		case errors.Is(err, localauth.ErrBadTOTP):
			code = "bad_code"
		case errors.Is(err, localauth.ErrLocked):
			code = "locked"
		case errors.Is(err, localauth.ErrTOTPNotEnrolled):
			code = "mfa_not_enrolled"
		}
		if code != "code_required" {
			s.Log.Warn("vpn sign-in failed", "user", body.Username, "client_ip", clientIP(r), "err", err)
			_ = s.Store.AddAudit(r.Context(), model.AuditEntry{At: s.now(), Actor: strings.ToLower(body.Username),
				Action: "vpn.login_failed", Detail: err.Error() + " from " + clientIP(r)})
		}
		writeErr(w, http.StatusUnauthorized, code, err.Error())
		return
	}
	tok, exp, err := s.LocalAuth.IssueToken(u, usedTOTP)
	if err != nil {
		s.Log.Error("issue token", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires_at": exp.UTC()})
}

// authConfig tells the agent how users sign in (public: no secrets).
func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.SignIn == nil {
		writeJSON(w, http.StatusOK, signin.ClientConfig{Local: s.LocalAuth != nil})
		return
	}
	writeJSON(w, http.StatusOK, s.SignIn.Client(r.Context()))
}

// challenge returns a nonce for device proofs and says which proofs to send.
func (s *Server) challenge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Trust == nil {
		writeErr(w, http.StatusNotFound, "not_enabled", "device trust is not enabled")
		return
	}
	writeJSON(w, http.StatusOK, s.Trust.NewChallenge(r.Context()))
}

// groupOK picks the policy group and enforces its sign-in methods.
func (s *Server) groupOK(w http.ResponseWriter, r *http.Request, id model.Identity, b connectBody) (model.PolicyGroup, bool) {
	group := model.DefaultPolicyGroup()
	if s.Groups != nil {
		g, err := s.Groups.Resolve(r.Context(), id, b.Platform, deviceName(b))
		if err != nil {
			s.Log.Warn("policy group", "user", id.UPN, "err", err)
			_ = s.Store.AddAudit(r.Context(), model.AuditEntry{At: s.now(), Actor: strings.ToLower(id.UPN),
				Action: "vpn.policy_error", Detail: err.Error()})
			writeErr(w, http.StatusServiceUnavailable, "policy_error",
				"Your access rules couldn't be checked right now (group membership). Try again in a few minutes, or contact IT.")
			return group, false
		}
		group = g
	}
	local := id.TenantID == "local"
	msg := ""
	switch {
	case local && !group.AllowLocal:
		msg = "Your access policy (" + group.Name + ") requires Sign in with Microsoft."
	case !local && !group.AllowMicrosoft:
		msg = "Your access policy (" + group.Name + ") doesn't allow Sign in with Microsoft. Contact IT."
	}
	if msg != "" {
		_ = s.Store.AddAudit(r.Context(), model.AuditEntry{At: s.now(), Actor: strings.ToLower(id.UPN),
			Action: "vpn.signin_method_blocked", Detail: msg})
		writeErr(w, http.StatusForbidden, "signin_method_blocked", msg)
		return group, false
	}
	return group, true
}

// duoOK requires an approved Duo Push. The first connect starts the push
// and answers "duo_pending" with a token; the agent polls
// /v1/auth/duo/status, then connects again with the token.
func (s *Server) duoOK(w http.ResponseWriter, r *http.Request, upn string, b connectBody) bool {
	ctx := r.Context()
	if s.Duo == nil || !s.Duo.Settings(ctx).Ready() {
		writeErr(w, http.StatusForbidden, "duo_unavailable", "Your access policy requires Duo, but Duo isn't set up yet. Contact IT.")
		return false
	}
	if b.DuoTx != "" {
		if txid, user, ok := s.Duo.ParseToken(b.DuoTx); ok && user == strings.ToLower(upn) {
			res, err := s.Duo.Status(ctx, txid)
			switch {
			case err == nil && res.Status == "allow" && s.Duo.Use(txid):
				_ = s.Store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn), Action: "vpn.duo_approved",
					Detail: "Duo approved on " + deviceName(b)})
				return true
			case err == nil && res.Status == "deny":
				_ = s.Store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn), Action: "vpn.duo_denied", Detail: res.Message})
				writeErr(w, http.StatusForbidden, "duo_denied", res.Message)
				return false
			}
		}
	}
	res, err := s.Duo.Start(ctx, upn, clientIP(r), deviceName(b))
	if err != nil {
		s.Log.Warn("duo start", "user", upn, "err", err)
		writeErr(w, http.StatusServiceUnavailable, "duo_unavailable", "Couldn't reach Duo to approve this sign-in. Try again in a minute.")
		return false
	}
	switch res.Status {
	case "allow":
		return true
	case "deny":
		_ = s.Store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn), Action: "vpn.duo_denied", Detail: res.Message})
		writeErr(w, http.StatusForbidden, "duo_denied", res.Message)
		return false
	}
	writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "duo_pending", "message": res.Message,
		"duo_tx": s.Duo.Token(res.TxID, upn)})
	return false
}

// duoStatus lets the agent poll a pending Duo Push.
func (s *Server) duoStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.Duo == nil {
		writeErr(w, http.StatusNotFound, "not_enabled", "Duo is not enabled")
		return
	}
	txid, _, ok := s.Duo.ParseToken(r.URL.Query().Get("tx"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "That Duo request expired. Connect again.")
		return
	}
	res, err := s.Duo.Status(r.Context(), txid)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "duo_unavailable", "Couldn't reach Duo.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": res.Status, "message": res.Message})
}

// trustOK runs the device trust check, stores the result on the device and,
// when the policy blocks it, writes a 403 the agent shows to the user.
func (s *Server) trustOK(w http.ResponseWriter, r *http.Request, upn string, b connectBody, group model.PolicyGroup) (*model.DeviceTrust, bool) {
	if s.Trust == nil || b.DeviceID == "" || len(b.DeviceID) > 128 {
		return nil, true
	}
	ctx := r.Context()
	t, err := s.Trust.Evaluate(ctx, devicetrust.Input{DeviceID: b.DeviceID, DeviceName: deviceName(b), UPN: upn,
		Nonce: b.Nonce, Proofs: b.Proofs, Join: b.Join, Group: group.Name}, group.Requirements())
	if serr := s.Store.SetDeviceTrust(ctx, b.DeviceID, t); serr != nil {
		s.Log.Warn("store device trust", "device", b.DeviceID, "err", serr)
	}
	var ue *devicetrust.ErrUntrusted
	if errors.As(err, &ue) {
		s.Log.Warn("connection blocked by device trust", "user", upn, "device", deviceName(b), "problems", ue.Error())
		_ = s.Store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn),
			Action: "vpn.device_untrusted", Target: b.DeviceID, Detail: deviceName(b) + ": " + ue.Error()})
		writeErr(w, http.StatusForbidden, "device_untrusted", strings.Join(ue.Problems, " "))
		return &t, false
	}
	return &t, true
}

func deviceName(b connectBody) string {
	n := strings.TrimSpace(b.DeviceName)
	if n == "" {
		n = b.DeviceID
	}
	if len(n) > 64 {
		n = n[:64]
	}
	return n
}

// deviceOK records the device and enforces device approval; on a block it
// writes a 403 the agent shows to the user.
func (s *Server) deviceOK(w http.ResponseWriter, r *http.Request, upn string, b connectBody) bool {
	if b.DeviceID == "" || len(b.DeviceID) > 128 {
		return true // Connect rejects it with a clearer error
	}
	d, err := s.Sessions.CheckDevice(r.Context(), model.Device{
		ID: b.DeviceID, Name: deviceName(b), Platform: b.Platform, LastUser: strings.ToLower(upn),
		AgentVersion: agentVersion(r.UserAgent()),
	})
	switch {
	case err == nil:
		return true
	case errors.Is(err, session.ErrDevicePending):
		writeErr(w, http.StatusForbidden, "device_pending",
			"This PC ("+d.Name+") is new and waiting for IT to approve it. Ask IT to approve it, then connect again.")
	case errors.Is(err, session.ErrDeviceBlocked):
		_ = s.Store.AddAudit(r.Context(), model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn),
			Action: "vpn.device_blocked", Target: d.ID, Detail: "blocked device " + d.Name + " tried to connect from " + clientIP(r)})
		writeErr(w, http.StatusForbidden, "device_blocked", "This PC ("+d.Name+") isn't allowed to connect. Contact IT.")
	default:
		s.Log.Error("device check", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
	return false
}

// countryOK enforces the country policy; on a block it writes a 403 and audits it.
func (s *Server) countryOK(w http.ResponseWriter, r *http.Request, id model.Identity, platform, deviceName, country string) bool {
	ok, why, err := s.Sessions.CheckCountry(r.Context(), id, platform, deviceName, country)
	if err != nil {
		s.Log.Warn("country policy check failed", "user", id.UPN, "err", err)
		writeErr(w, http.StatusServiceUnavailable, "policy_error", "Your country access rules couldn't be checked right now. Try again in a few minutes, or contact IT.")
		return false
	}
	if ok {
		return true
	}
	upn := id.UPN
	s.Log.Warn("connection blocked by country policy", "user", upn, "country", country, "client_ip", clientIP(r))
	_ = s.Store.AddAudit(r.Context(), model.AuditEntry{At: s.now(), Actor: strings.ToLower(upn),
		Action: "vpn.country_blocked", Detail: why + " (from " + clientIP(r) + ")"})
	msg := "Connecting from this country isn't allowed for your account. Contact IT if you're traveling."
	if country != "" {
		msg = "Connecting from " + country + " isn't allowed for your account. Contact IT if you're traveling."
	}
	writeErr(w, http.StatusForbidden, "country_blocked", msg)
	return false
}

// ---- client endpoints ----

type connectBody struct {
	WGPublicKey string `json:"wg_public_key"`
	DeviceID    string `json:"device_id"`
	BootID      string `json:"boot_id"`
	Platform    string `json:"platform"`
	DeviceName  string `json:"device_name,omitempty"`

	// Device trust (see GET /v1/auth/challenge).
	Nonce  string              `json:"nonce,omitempty"`
	Proofs []model.DeviceProof `json:"proofs,omitempty"`
	Join   *model.JoinInfo     `json:"join,omitempty"`

	// DuoTx is the token from a "duo_pending" answer, sent again once the
	// push is approved.
	DuoTx string `json:"duo_tx,omitempty"`

	// WindowsUser is the Windows account the app runs under (UPN or DOMAIN\user).
	WindowsUser string `json:"windows_user,omitempty"`
}

type sessionBody struct {
	BootID string          `json:"boot_id"`
	Target string          `json:"target,omitempty"` // failover: preferred gateway (admin move)
	Diag   json.RawMessage `json:"diag,omitempty"` // agent diagnostics, stored for the admin site
}

type gatewayView struct {
	ID          string `json:"id"`
	Site        string `json:"site"`
	Endpoint    string `json:"endpoint"`
	TCPEndpoint string `json:"tcp_endpoint,omitempty"`
	PublicKey   string `json:"public_key"`
	InsideIP    string `json:"inside_ip,omitempty"` // the gateway's own tunnel address; apps ping it to measure latency
}

type tunnelView struct {
	Address    string   `json:"address"`
	DNS        []string `json:"dns"`
	AllowedIPs []string `json:"allowed_ips"`
	MTU        int      `json:"mtu"`
	Keepalive  int      `json:"persistent_keepalive"`
}

type placementView struct {
	SessionID        string        `json:"session_id"`
	ResumeToken      string        `json:"resume_token,omitempty"`
	Tunnel           tunnelView    `json:"tunnel"`
	Gateway          gatewayView   `json:"gateway"`
	Alternates       []gatewayView `json:"alternates"`
	HeartbeatSeconds int           `json:"heartbeat_seconds"`
	GraceSeconds     int           `json:"grace_seconds"`
	SpeedTest        model.SpeedTestPolicy `json:"speed_test"`
	OfficeNetworks   model.OfficeNetworkPolicy `json:"office_networks"`
	Commands         []model.Command           `json:"commands,omitempty"`
	DeviceTrust      *model.DeviceTrust        `json:"device_trust,omitempty"` // on connect only
	BackupServers    []string                  `json:"backup_servers,omitempty"` // other addresses of the control servers
	ExpiresAt        time.Time     `json:"expires_at"`
	Kind             string        `json:"kind,omitempty"` // "device" for a pre-logon device tunnel
	// WindowsSessions is the policy group's sign-out / switch / lock behavior
	// (connect only; the app keeps it for the session).
	WindowsSessions *model.WindowsSessionPolicy `json:"windows_sessions,omitempty"`
}

// deviceConnectBody is POST /v1/sessions/device: a device certificate proof
// and no user token.
type deviceConnectBody struct {
	WGPublicKey string              `json:"wg_public_key"`
	DeviceID    string              `json:"device_id"`
	BootID      string              `json:"boot_id"`
	Platform    string              `json:"platform"`
	DeviceName  string              `json:"device_name,omitempty"`
	Nonce       string              `json:"nonce"`
	Proofs      []model.DeviceProof `json:"proofs"`
	Join        *model.JoinInfo     `json:"join,omitempty"`
}

// connectDevice opens a pre-logon device tunnel. No user is signed in, so
// the PC proves itself with its device certificate (signed challenge from
// GET /v1/auth/challenge). The device tunnel must be on, the device approved
// on the Devices page, and the certificate issued by a trusted CA for this
// computer's name as recorded when the device was approved. The tunnel
// reaches only the device tunnel's subnets.
func (s *Server) connectDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.Trust == nil {
		writeErr(w, http.StatusNotFound, "not_enabled", "device certificates are not enabled on this server")
		return
	}
	pol := s.Sessions.DeviceTunnelPolicy(ctx)
	if !pol.Enabled || len(pol.Subnets) == 0 {
		writeErr(w, http.StatusForbidden, "device_tunnel_off", "The device tunnel is turned off.")
		return
	}
	var b deviceConnectBody
	if !readJSON(w, r, &b) {
		return
	}
	if b.DeviceID == "" || len(b.DeviceID) > 128 || b.Nonce == "" || len(b.Proofs) == 0 || len(b.Proofs) > 8 {
		writeErr(w, http.StatusBadRequest, "bad_request", "device_id, nonce and a device certificate proof are required")
		return
	}
	claimed := deviceName(connectBody{DeviceID: b.DeviceID, DeviceName: b.DeviceName})
	fail := func(status int, code, action, detail, msg string) {
		s.Log.Warn("device tunnel refused", "device", b.DeviceID, "name", claimed, "client_ip", clientIP(r), "why", detail)
		_ = s.Store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: session.DeviceUPN(claimed), Action: action,
			Target: b.DeviceID, Detail: detail + " (from " + clientIP(r) + ")"})
		writeErr(w, status, code, msg)
	}

	// Only devices an admin approved, by their recorded name: the device ID
	// is the client's claim, so the certificate must match the approved record.
	dev, found, err := s.findDevice(ctx, b.DeviceID)
	if err != nil {
		s.Log.Error("device lookup", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	switch {
	case !found:
		fail(http.StatusForbidden, "device_not_approved", "device_tunnel.refused", "unknown device "+claimed,
			"This PC isn't known yet. Sign in once with a user account and have IT approve it.")
		return
	case dev.Status != model.DeviceApproved:
		fail(http.StatusForbidden, "device_not_approved", "device_tunnel.refused", "device "+dev.Name+" is "+dev.Status+", not approved",
			"This PC isn't approved for the device tunnel.")
		return
	}

	t, err := s.Trust.Evaluate(ctx, devicetrust.Input{DeviceID: dev.ID, DeviceName: dev.Name, Nonce: b.Nonce,
		Proofs: b.Proofs, Join: b.Join, Group: "Device tunnel", RequireName: true},
		model.TrustRequirements{CertMode: model.CertDevice})
	if err != nil {
		fail(http.StatusForbidden, "device_untrusted", "device_tunnel.refused", dev.Name+": "+err.Error(), strings.Join(t.Problems, " "))
		return
	}
	if !s.countryOK(w, r, model.Identity{UPN: session.DeviceUPN(dev.Name), TenantID: "device"}, dev.Platform, dev.Name, realip.Country(r)) {
		return
	}

	// Record that the device was seen, keeping its last user.
	_, _ = s.Store.SeeDevice(ctx, model.Device{ID: dev.ID, Name: dev.Name, Platform: dev.Platform, LastUser: dev.LastUser,
		AgentVersion: orKeep(agentVersion(r.UserAgent()), dev.AgentVersion), LastSeen: s.now()}, model.DeviceApproved)

	p, err := s.Sessions.ConnectDevice(ctx, dev, session.ConnectRequest{
		WGPublicKey:   b.WGPublicKey,
		DeviceID:      dev.ID,
		BootID:        b.BootID,
		Platform:      b.Platform,
		ClientIP:      clientIP(r),
		ClientVersion: agentVersion(r.UserAgent()),
		Country:       realip.Country(r),
	})
	if errors.Is(err, session.ErrUserSessionActive) {
		writeErr(w, http.StatusConflict, "user_session_active", "A user is connected on this PC; the device tunnel isn't needed.")
		return
	}
	if err != nil {
		s.sessionErr(w, err)
		return
	}
	v := s.view(ctx, p)
	v.DeviceTrust = &t
	writeJSON(w, http.StatusCreated, v)
}

// findDevice looks a device up by ID.
func (s *Server) findDevice(ctx context.Context, id string) (model.Device, bool, error) {
	list, err := s.Store.ListDevices(ctx, "")
	if err != nil {
		return model.Device{}, false, err
	}
	for _, d := range list {
		if d.ID == id {
			return d, true, nil
		}
	}
	return model.Device{}, false, nil
}

// deviceSessionOK ends a device session whose device tunnel was turned off
// or whose device is no longer approved (checked on every heartbeat).
func (s *Server) deviceSessionOK(ctx context.Context, se model.Session) bool {
	why := ""
	if pol := s.Sessions.DeviceTunnelPolicy(ctx); !pol.Enabled || len(pol.Subnets) == 0 {
		why = "the device tunnel was turned off"
	} else if d, found, err := s.findDevice(ctx, se.DeviceID); err != nil {
		return true // can't tell; don't drop anyone over a database blip
	} else if !found || d.Status != model.DeviceApproved {
		why = "the device is no longer approved"
	}
	if why == "" {
		return true
	}
	if err := s.Sessions.EndSession(ctx, se.ID, "device_tunnel_off", why); err != nil {
		s.Log.Warn("end device session", "session", se.ID, "err", err)
	}
	return false
}

func orKeep(v, old string) string {
	if v == "" {
		return old
	}
	return v
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	raw, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "reauth_required", "missing bearer token")
		return
	}
	id, err := s.Tokens.Validate(r.Context(), raw)
	if err != nil {
		code := "invalid_token"
		switch {
		case errors.Is(err, auth.ErrMFARequired):
			code = "mfa_required"
		case errors.Is(err, auth.ErrStaleAuth):
			code = "fresh_signin_required"
		}
		s.Log.Warn("connect rejected", "reason", err.Error(), "client_ip", clientIP(r))
		writeErr(w, http.StatusUnauthorized, code, "sign in again")
		return
	}
	var body connectBody
	if !readJSON(w, r, &body) {
		return
	}
	country := realip.Country(r)
	if !s.countryOK(w, r, id, body.Platform, deviceName(body), country) {
		return
	}
	if !s.deviceOK(w, r, id.UPN, body) {
		return
	}
	group, ok := s.groupOK(w, r, id, body)
	if !ok {
		return
	}
	trust, ok := s.trustOK(w, r, id.UPN, body, group)
	if !ok {
		return
	}
	if !s.windowsUserOK(w, r, id.UPN, body, group) {
		return
	}
	if group.MFA == model.MFADuo && !s.duoOK(w, r, id.UPN, body) {
		return
	}
	p, err := s.Sessions.Connect(r.Context(), id, session.ConnectRequest{
		WGPublicKey:   body.WGPublicKey,
		DeviceID:      body.DeviceID,
		BootID:        body.BootID,
		Platform:      body.Platform,
		ClientIP:      clientIP(r),
		ClientVersion: agentVersion(r.UserAgent()),
		Country:       country,
		DeviceName:    deviceName(body),
	})
	if err != nil {
		s.sessionErr(w, err)
		return
	}
	v := s.view(r.Context(), p)
	v.DeviceTrust = trust
	wp := windowsPolicy(group)
	v.WindowsSessions = &wp
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	token, body, ok := s.sessionAuth(w, r)
	if !ok {
		return
	}
	p, err := s.Sessions.Heartbeat(r.Context(), r.PathValue("id"), token, body.BootID)
	if err != nil {
		s.sessionErr(w, err)
		return
	}
	if p.Session.IsDevice() && !s.deviceSessionOK(r.Context(), p.Session) {
		s.sessionErr(w, session.ErrReauthRequired)
		return
	}
	if len(body.Diag) > 0 && len(body.Diag) <= 16<<10 && json.Valid(body.Diag) {
		if err := s.Store.SetSessionDiag(r.Context(), p.Session.ID, string(body.Diag), s.now()); err != nil {
			s.Log.Warn("store diagnostics", "session", p.Session.ID, "err", err)
		}
	}
	v := s.view(r.Context(), p)
	if ack := r.Header.Get(model.CommandAckHeader); ack != "" {
		var ids []string
		if ack != "-" {
			ids = strings.Split(ack, ",")
		}
		cmds, err := s.Store.PendingCommands(r.Context(), p.Session.ID, ids)
		if err != nil {
			s.sessionErr(w, err)
			return
		}
		v.Commands = cmds
	} else if cmds, err := s.Store.TakeCommands(r.Context(), p.Session.ID); err == nil {
		v.Commands = cmds
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) failover(w http.ResponseWriter, r *http.Request) {
	token, body, ok := s.sessionAuth(w, r)
	if !ok {
		return
	}
	p, err := s.Sessions.FailoverTo(r.Context(), r.PathValue("id"), token, body.BootID, body.Target)
	if err != nil {
		s.sessionErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.view(r.Context(), p))
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "reauth_required", "missing resume token")
		return
	}
	if err := s.Sessions.Disconnect(r.Context(), r.PathValue("id"), token); err != nil {
		s.sessionErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// watch is a long poll: it returns 200 after ~25 s if the session is still
// live, or 401 reauth_required as soon as it ends.
func (s *Server) watch(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "reauth_required", "missing resume token")
		return
	}
	pending, err := s.Sessions.Watch(r.Context(), r.PathValue("id"), token, 25*time.Second)
	if err != nil {
		s.sessionErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": "live", "commands": pending})
}

func (s *Server) sessionAuth(w http.ResponseWriter, r *http.Request) (string, sessionBody, bool) {
	var body sessionBody
	token, ok := bearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "reauth_required", "missing resume token")
		return "", body, false
	}
	if !readJSON(w, r, &body) {
		return "", body, false
	}
	return token, body, true
}

func (s *Server) sessionErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrReauthRequired):
		writeErr(w, http.StatusUnauthorized, "reauth_required", "session ended; sign in again")
	case errors.Is(err, session.ErrBadRequest):
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, store.ErrDeviceBlocked):
		writeErr(w, http.StatusForbidden, "device_blocked", "This PC isn't allowed to connect. Contact IT.")
	case errors.Is(err, session.ErrNoGateway), errors.Is(err, ipam.ErrPoolExhausted):
		writeErr(w, http.StatusServiceUnavailable, "no_gateway", "no gateway available")
	default:
		s.Log.Error("session request failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func (s *Server) view(ctx context.Context, p session.Placement) placementView {
	cfg := s.Sessions.Config()
	v := placementView{
		SessionID:   p.Session.ID,
		ResumeToken: p.ResumeToken,
		Tunnel: tunnelView{
			Address:    p.Session.TunnelIP.String() + "/32",
			DNS:        s.Tunnel.DNS,
			AllowedIPs: s.Tunnel.AllowedIPs,
			MTU:        s.Tunnel.MTU,
			Keepalive:  s.Tunnel.Keepalive,
		},
		Gateway:          gwView(p.Gateway),
		Alternates:       []gatewayView{},
		HeartbeatSeconds: int(cfg.Heartbeat / time.Second),
		GraceSeconds:     int(cfg.Grace / time.Second),
		ExpiresAt:        p.Session.ExpiresAt.UTC(),
		SpeedTest:        s.Sessions.SpeedTestPolicy(ctx),
		OfficeNetworks:   s.Sessions.OfficePolicy(ctx),
	}
	if s.Groups != nil {
		if sp, _ := s.Groups.ForDevice(ctx, model.PolicySpeed, p.Session.Platform, p.Session.DeviceName); sp.Speed != nil {
			v.SpeedTest = *sp.Speed
		}
		if op, _ := s.Groups.ForDevice(ctx, model.PolicyOffice, p.Session.Platform, p.Session.DeviceName); op.Office != nil {
			v.OfficeNetworks = *op.Office
		}
	}
	if p.Session.IsDevice() {
		// Only the device tunnel's subnets (plus the gateway's own address,
		// for latency checks) go through the tunnel; the rest stays local.
		pol := s.Sessions.DeviceTunnelPolicy(ctx)
		v.Kind = model.SessionDevice
		v.Tunnel.AllowedIPs = append([]string{}, pol.Subnets...)
		if v.Gateway.InsideIP != "" {
			v.Tunnel.AllowedIPs = append(v.Tunnel.AllowedIPs, v.Gateway.InsideIP+"/32")
		}
		if len(pol.DNS) > 0 {
			v.Tunnel.DNS = pol.DNS
		}
		v.SpeedTest.IntervalHours = 0 // no automatic speed tests before anyone signs in
	}
	var backups []string
	if ok, _ := s.Store.GetSetting(ctx, "backup_servers", &backups); ok {
		v.BackupServers = backups
	}
	for _, g := range p.Alternates {
		v.Alternates = append(v.Alternates, gwView(g))
	}
	return v
}

func gwView(g model.Gateway) gatewayView {
	v := gatewayView{ID: g.ID, Site: g.Site, Endpoint: g.Endpoint, TCPEndpoint: g.TCPEndpoint, PublicKey: g.PublicKey}
	if g.Pool.IsValid() {
		v.InsideIP = ipam.GatewayAddr(g.Pool).String()
	}
	return v
}

// ---- gateway endpoints ----

type peerView struct {
	SessionID  string    `json:"session_id"`
	PublicKey  string    `json:"public_key"`
	AllowedIPs []string  `json:"allowed_ips"`
	ExpiresAt  time.Time `json:"expires_at"`
	UPN        string    `json:"upn"`
	// Device tunnels: the gateway forwards this peer's traffic only to
	// RestrictTo (empty = nothing). The client's AllowedIPs aren't a control.
	Device     bool     `json:"device,omitempty"`
	RestrictTo []string `json:"restrict_to,omitempty"`
}

type peersResponse struct {
	GatewayID   string     `json:"gateway_id"`
	GatewayAddr string     `json:"gateway_address"`
	GeneratedAt time.Time  `json:"generated_at"`
	Peers       []peerView `json:"peers"`
}

// gatewayPeers returns the full desired peer set. The gateway agent reconciles
// WireGuard to match it. If the control plane is unreachable, the agent keeps
// its last set and drops each peer only at expires_at.
func (s *Server) gatewayPeers(w http.ResponseWriter, r *http.Request) {
	gw, ok := s.gatewayAuth(w, r)
	if !ok {
		return
	}
	sessions, err := s.Store.LivePeers(r.Context(), gw.ID)
	if err != nil {
		s.Log.Error("list peers", "gateway", gw.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	resp := peersResponse{
		GatewayID:   gw.ID,
		GatewayAddr: ipam.GatewayAddr(gw.Pool).String() + "/" + strconv.Itoa(gw.Pool.Bits()),
		GeneratedAt: s.now().UTC(),
		Peers:       []peerView{},
	}
	var devPol *model.DeviceTunnelPolicy
	for _, se := range sessions {
		pv := peerView{
			SessionID:  se.ID,
			PublicKey:  se.WGPublicKey,
			AllowedIPs: []string{se.TunnelIP.String() + "/32"},
			ExpiresAt:  se.ExpiresAt.UTC(),
			UPN:        se.UPN,
		}
		if se.IsDevice() {
			if devPol == nil {
				p := s.Sessions.DeviceTunnelPolicy(r.Context())
				devPol = &p
			}
			pv.Device = true
			if devPol.Enabled {
				pv.RestrictTo = devPol.Subnets
			}
		}
		resp.Peers = append(resp.Peers, pv)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) gatewayHealth(w http.ResponseWriter, r *http.Request) {
	gw, ok := s.gatewayAuth(w, r)
	if !ok {
		return
	}
	var body struct {
		ActivePeers int                `json:"active_peers"`
		Metrics     *model.HostMetrics `json:"metrics"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := s.Store.RecordGatewayHealth(r.Context(), gw.ID, body.ActivePeers, s.now()); err != nil {
		s.Log.Error("record health", "gateway", gw.ID, "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if body.Metrics != nil {
		m := *body.Metrics
		m.At = s.now().UTC() // trust our clock, not the gateway's
		if err := s.Store.SetGatewayMetrics(r.Context(), gw.ID, m); err != nil {
			s.Log.Warn("store gateway metrics", "gateway", gw.ID, "err", err)
		}
		if s.History != nil {
			s.History.Add("gw:"+gw.ID, m)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// gatewayAuth identifies the gateway by its API token. (mTLS is planned on top.)
func (s *Server) gatewayAuth(w http.ResponseWriter, r *http.Request) (model.Gateway, bool) {
	token, ok := bearer(r)
	if ok {
		hash := session.HashGatewayToken(token)
		gws, err := s.Store.ListGateways(r.Context())
		if err == nil {
			for _, g := range gws {
				// Disabled gateways still sync peers and report health (so a drained
				// gateway drops moved peers promptly); disabled only stops new sessions.
				if subtle.ConstantTimeCompare([]byte(hash), []byte(g.TokenHash)) == 1 {
					return g, true
				}
			}
		}
	}
	writeErr(w, http.StatusUnauthorized, "unauthorized", "unknown gateway")
	return model.Gateway{}, false
}

// ---- misc ----

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if s.Ping != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := s.Ping(ctx); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "db_unavailable", "database unreachable")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "Bearer ") {
		return "", false
	}
	t := strings.TrimSpace(h[7:])
	return t, t != ""
}

// agentVersion extracts the version from "SecureTunnel-Agent/1.326.469".
func agentVersion(ua string) string {
	const prefix = "SecureTunnel-Agent/"
	if !strings.HasPrefix(ua, prefix) {
		return ""
	}
	v := strings.TrimPrefix(ua, prefix)
	if i := strings.IndexAny(v, " ;("); i >= 0 {
		v = v[:i]
	}
	if len(v) > 32 {
		v = v[:32]
	}
	return v
}

// clientIP is the TCP peer address. If a load balancer sits in front, it should
// pass the client address via PROXY protocol rather than a spoofable header.
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

