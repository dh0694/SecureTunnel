// Package session implements the connect / heartbeat / resume / failover /
// disconnect lifecycle, including the 15-minute no-MFA grace window.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"securetunnel/server/internal/ipam"
	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

var (
	// ErrReauthRequired: the session is over; the client must do a fresh MFA connect.
	ErrReauthRequired = errors.New("reauthentication required")
	// ErrNoGateway: no healthy gateway has capacity.
	ErrNoGateway = errors.New("no gateway available")
	// ErrDevicePending: the device hasn't been approved yet.
	ErrDevicePending = errors.New("device waiting for approval")
	// ErrDeviceBlocked: an admin blocked the device.
	ErrDeviceBlocked = errors.New("device blocked")
	// ErrBadRequest: the request was malformed.
	ErrBadRequest = errors.New("bad request")
)

// Config holds session policy.
type Config struct {
	Grace            time.Duration         // no-MFA resume window after the last heartbeat (15m)
	SuspendAfter     time.Duration         // missed-heartbeat time before a session shows as suspended
	Heartbeat        time.Duration         // how often clients should heartbeat
	MaxLifetime      time.Duration         // absolute session lifetime; fresh MFA after this
	GatewayHealthTTL time.Duration         // a gateway with no health report this recent is skipped
	DefaultPolicy    model.PlacementPolicy // used until an admin saves one
}

// ConnectRequest is what a client sends with its Entra token.
type ConnectRequest struct {
	WGPublicKey   string
	DeviceID      string
	BootID        string
	Platform      string
	ClientIP      string
	ClientVersion string
	Country       string
	DeviceName    string
}

// Placement is a session's current gateway assignment, returned to the client.
type Placement struct {
	Session     model.Session
	ResumeToken string // only set on connect
	Gateway     model.Gateway
	Alternates  []model.Gateway // failover order
}

// Service runs the session lifecycle on top of a Store.
type Service struct {
	store store.Store
	cfg   Config
	now   func() time.Time
	log   *slog.Logger

	// Policy hooks (set by main from the Policies page; nil = the earlier
	// system-wide settings): device approval per device, countries per user.
	ApprovalFor func(ctx context.Context, d model.Device) (model.DevicePolicy, bool)
	CountryFor  func(ctx context.Context, id model.Identity, platform, deviceName string) (model.CountryPolicy, error)
}

// New returns a Service. now may be nil (uses time.Now).
func New(st store.Store, cfg Config, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: st, cfg: cfg, now: now, log: log}
}

// Config returns the service's session policy.
func (s *Service) Config() Config { return s.cfg }

// ErrUserSessionActive: a device tunnel was asked for while a user's session
// on the same PC (same boot) is still live; the user tunnel wins.
var ErrUserSessionActive = errors.New("a user session is active on this device")

// DeviceUPN is the name device sessions carry in place of a user, e.g.
// "device:laptop-042". It shows in the admin site and audit log.
func DeviceUPN(computer string) string {
	return "device:" + strings.ToLower(strings.TrimSpace(computer))
}

// DeviceTunnelPolicy returns the saved device tunnel policy (off if none).
func (s *Service) DeviceTunnelPolicy(ctx context.Context) model.DeviceTunnelPolicy {
	p := model.DeviceTunnelPolicy{Subnets: []string{}, DNS: []string{}}
	_, _ = s.store.GetSetting(ctx, DeviceTunnelKey, &p)
	return p
}

// DeviceTunnelKey is the settings key of model.DeviceTunnelPolicy.
const DeviceTunnelKey = "device_tunnel_policy"

// ConnectDevice starts a pre-logon device session. The caller has already
// checked the device certificate, that the device is approved and that the
// device tunnel is on. A live user session from the same boot is never
// replaced (ErrUserSessionActive); one from before a reboot is.
func (s *Service) ConnectDevice(ctx context.Context, d model.Device, req ConnectRequest) (Placement, error) {
	live, err := s.store.ListSessions(ctx, model.SessionFilter{State: "live", Query: req.DeviceID, Limit: 50})
	if err != nil {
		return Placement{}, err
	}
	for _, se := range live {
		if se.DeviceID == req.DeviceID && !se.IsDevice() && se.BootID == req.BootID && se.State.Live() {
			return Placement{}, ErrUserSessionActive
		}
	}
	req.DeviceName = d.Name
	id := model.Identity{UPN: DeviceUPN(d.Name), TenantID: "device", AuthTime: s.now()}
	return s.connect(ctx, id, req, model.SessionDevice)
}

// EndSession ends a live session for a server-side reason (for example the
// device tunnel was turned off) and audits it.
func (s *Service) EndSession(ctx context.Context, sessionID, reason, detail string) error {
	sess, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return s.endedOr(err)
	}
	if err := s.store.EndSession(ctx, sessionID, model.StateTerminated, reason, s.now()); err != nil {
		return s.endedOr(err)
	}
	action := "session.end"
	if sess.IsDevice() {
		action = "device_tunnel.end"
	}
	s.log.Info("session ended by the server", "session", sessionID, "upn", sess.UPN, "reason", reason)
	s.audit(ctx, sess.UPN, action, sessionID, detail)
	return nil
}

// Connect starts a new session for a user who has just completed MFA.
func (s *Service) Connect(ctx context.Context, id model.Identity, req ConnectRequest) (Placement, error) {
	return s.connect(ctx, id, req, model.SessionUser)
}

func (s *Service) connect(ctx context.Context, id model.Identity, req ConnectRequest, kind string) (Placement, error) {
	if err := validWGKey(req.WGPublicKey); err != nil {
		return Placement{}, err
	}
	if req.DeviceID == "" || req.BootID == "" || len(req.DeviceID) > 128 || len(req.BootID) > 128 {
		return Placement{}, fmt.Errorf("%w: device_id and boot_id are required", ErrBadRequest)
	}

	now := s.now()
	gws, err := s.rankGateways(ctx, "")
	if err != nil {
		return Placement{}, err
	}

	token, tokenHash, err := newResumeToken()
	if err != nil {
		return Placement{}, err
	}
	sess := model.Session{
		ID:              newID(),
		UserOID:         id.UserOID,
		UPN:             id.UPN,
		TenantID:        id.TenantID,
		DeviceID:        req.DeviceID,
		BootID:          req.BootID,
		Platform:        req.Platform,
		WGPublicKey:     req.WGPublicKey,
		State:           model.StateActive,
		ResumeTokenHash: tokenHash,
		AuthTime:        id.AuthTime,
		CreatedAt:       now,
		LastSeen:        now,
		ExpiresAt:       now.Add(s.cfg.MaxLifetime),
		ClientIP:        req.ClientIP,
		ClientVersion:   req.ClientVersion,
		Country:         req.Country,
		DeviceName:      req.DeviceName,
		Kind:            kind,
	}
	action := "session.connect"
	if kind == model.SessionDevice {
		action = "device_tunnel.connect"
	} else if live, err := s.store.ListSessions(ctx, model.SessionFilter{State: "live", Query: req.DeviceID, Limit: 50}); err == nil {
		// CreateSession replaces the device's live sessions; say so when a
		// user's sign-in takes over from the pre-logon device tunnel.
		for _, se := range live {
			if se.DeviceID == req.DeviceID && se.IsDevice() {
				s.audit(ctx, id.UPN, "device_tunnel.handover", se.ID,
					"user signed in on "+orDash(se.DeviceName)+"; the device tunnel was replaced by the user's tunnel")
			}
		}
	}

	// Try gateways in rank order until one has a free address.
	for _, gw := range gws {
		sess.GatewayID = gw.ID
		err = s.store.CreateSession(ctx, &sess, gw.Pool)
		if errors.Is(err, ipam.ErrPoolExhausted) || errors.Is(err, store.ErrGatewayUnavailable) {
			continue
		}
		if err != nil {
			return Placement{}, err
		}
		s.log.Info("session connected", "session", sess.ID, "kind", kind, "upn", sess.UPN, "device", sess.DeviceID,
			"gateway", gw.ID, "tunnel_ip", sess.TunnelIP, "client_ip", req.ClientIP)
		s.audit(ctx, sess.UPN, action, sess.ID,
			fmt.Sprintf("device=%s platform=%s version=%s gateway=%s tunnel_ip=%s client_ip=%s country=%s",
				sess.DeviceID, sess.Platform, orDash(sess.ClientVersion), gw.ID, sess.TunnelIP, req.ClientIP, orDash(req.Country)))
		return Placement{Session: sess, ResumeToken: token, Gateway: gw, Alternates: without(gws, gw.ID)}, nil
	}
	return Placement{}, ErrNoGateway
}

// Heartbeat keeps a session alive. It is also how a client resumes after a
// network drop: if it arrives within the grace window, the session continues
// with no MFA prompt.
func (s *Service) Heartbeat(ctx context.Context, sessionID, resumeToken, bootID string) (Placement, error) {
	sess, err := s.checkResumable(ctx, sessionID, resumeToken, bootID)
	if err != nil {
		return Placement{}, err
	}
	resumed := sess.State == model.StateSuspended
	if err := s.store.Touch(ctx, sess.ID, s.now()); err != nil {
		return Placement{}, s.endedOr(err)
	}
	if resumed {
		s.log.Info("session resumed", "session", sess.ID, "upn", sess.UPN, "offline_for", s.now().Sub(sess.LastSeen).Round(time.Second))
	}
	return s.placement(ctx, sess.ID)
}

// Failover moves a session to another gateway after its gateway stopped
// answering. The session (and its MFA) stays valid; the tunnel IP changes.
func (s *Service) Failover(ctx context.Context, sessionID, resumeToken, bootID string) (Placement, error) {
	return s.FailoverTo(ctx, sessionID, resumeToken, bootID, "")
}

// FailoverTo moves a session to another gateway, trying prefer first when
// it's healthy and enabled (an admin "move to" request); "" picks the best.
func (s *Service) FailoverTo(ctx context.Context, sessionID, resumeToken, bootID, prefer string) (Placement, error) {
	sess, err := s.checkResumable(ctx, sessionID, resumeToken, bootID)
	if err != nil {
		return Placement{}, err
	}
	gws, err := s.rankGateways(ctx, sess.GatewayID)
	if err != nil {
		return Placement{}, err
	}
	if prefer != "" {
		for i, g := range gws {
			if g.ID == prefer {
				gws[0], gws[i] = gws[i], gws[0]
				break
			}
		}
	}
	for _, gw := range gws {
		ip, err := s.store.MoveSession(ctx, sess.ID, gw.ID, gw.Pool, s.now())
		if errors.Is(err, ipam.ErrPoolExhausted) || errors.Is(err, store.ErrGatewayUnavailable) {
			continue
		}
		if err != nil {
			return Placement{}, s.endedOr(err)
		}
		s.log.Warn("session failed over", "session", sess.ID, "upn", sess.UPN, "from", sess.GatewayID, "to", gw.ID, "tunnel_ip", ip)
		s.audit(ctx, sess.UPN, "session.failover", sess.ID, fmt.Sprintf("from=%s to=%s tunnel_ip=%s", sess.GatewayID, gw.ID, ip))
		return s.placement(ctx, sess.ID)
	}
	return Placement{}, ErrNoGateway
}

// Disconnect ends a session because the user chose to. The next connect needs MFA.
func (s *Service) Disconnect(ctx context.Context, sessionID, resumeToken string) error {
	sess, err := s.authSession(ctx, sessionID, resumeToken)
	if err != nil {
		return err
	}
	if err := s.store.EndSession(ctx, sess.ID, model.StateTerminated, model.ReasonUserDisconnect, s.now()); err != nil {
		return s.endedOr(err)
	}
	s.log.Info("session disconnected by user", "session", sess.ID, "upn", sess.UPN)
	if sess.IsDevice() {
		s.audit(ctx, sess.UPN, "device_tunnel.disconnect", sess.ID, "device tunnel closed by the PC")
		return nil
	}
	s.audit(ctx, sess.UPN, "session.disconnect", sess.ID, "user disconnected")
	return nil
}

// CheckSession authenticates a resume token and returns the live session.
func (s *Service) CheckSession(ctx context.Context, sessionID, resumeToken string) (model.Session, error) {
	return s.authSession(ctx, sessionID, resumeToken)
}

// SpeedTestPolicy returns the saved speed-test policy or the default.
func (s *Service) SpeedTestPolicy(ctx context.Context) model.SpeedTestPolicy {
	var p model.SpeedTestPolicy
	if ok, err := s.store.GetSetting(ctx, "speedtest_policy", &p); err == nil && ok {
		return p
	}
	return model.DefaultSpeedTestPolicy
}

// OfficePolicy returns the saved office-network policy (disabled if none).
func (s *Service) OfficePolicy(ctx context.Context) model.OfficeNetworkPolicy {
	p := model.OfficeNetworkPolicy{DNSSuffixes: []string{}, LocalSubnets: []string{}, PublicIPs: []string{}}
	_, _ = s.store.GetSetting(ctx, "office_networks", &p)
	return p
}

// DevicePolicy returns the saved device approval policy (off if none).
func (s *Service) DevicePolicy(ctx context.Context) model.DevicePolicy {
	var p model.DevicePolicy
	_, _ = s.store.GetSetting(ctx, "device_policy", &p)
	return p
}

// CheckDevice records a connect attempt from a device and decides whether it
// may connect: blocked devices never may; with approval required, only
// approved ones may (a new device starts pending).
func (s *Service) CheckDevice(ctx context.Context, d model.Device) (model.Device, error) {
	pol := s.DevicePolicy(ctx)
	if s.ApprovalFor != nil {
		if p, ok := s.ApprovalFor(ctx, d); ok {
			pol = p
		}
	}
	initial := model.DeviceApproved
	if pol.RequireApproval {
		initial = model.DevicePending
	}
	d.FirstSeen, d.LastSeen = s.now(), s.now()
	stored, err := s.store.SeeDevice(ctx, d, initial)
	if err != nil {
		return stored, err
	}
	if stored.FirstSeen.Equal(d.FirstSeen) && stored.Status == model.DevicePending {
		s.audit(ctx, d.LastUser, "device.new_pending", d.ID, "new device "+d.Name+" is waiting for approval")
	}
	switch {
	case stored.Status == model.DeviceBlocked:
		return stored, ErrDeviceBlocked
	case pol.RequireApproval && stored.Status != model.DeviceApproved:
		return stored, ErrDevicePending
	}
	return stored, nil
}

// CountryPolicy returns the saved country policy (disabled if none).
func (s *Service) CountryPolicy(ctx context.Context) model.CountryPolicy {
	p := model.CountryPolicy{Default: []string{}}
	_, _ = s.store.GetSetting(ctx, "country_policy", &p)
	return p
}

// CheckCountry applies the connection's country policy and any per-user exceptions.
func (s *Service) CheckCountry(ctx context.Context, id model.Identity, platform, deviceName, country string) (bool, string, error) {
	p := s.CountryPolicy(ctx)
	if s.CountryFor != nil {
		cp, err := s.CountryFor(ctx, id, platform, deviceName)
		if err != nil {
			return false, "", err
		}
		p = cp
	}
	if !p.Enabled {
		return true, "", nil
	}
	var up *model.User
	if u, err := s.store.GetUser(ctx, id.UPN); err == nil {
		up = &u
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, "", err
	}
	allowed, reason := model.CountryAllowed(p, up, country, s.now())
	return allowed, reason, nil
}

// Watch holds a client's request open for up to maxWait and returns as soon as
// the session ends (ErrReauthRequired), so an admin disconnect reaches the PC
// within seconds instead of at its next heartbeat. It returns nil when maxWait
// passes with the session still live; the client then calls again. It checks
// the database every couple of seconds, so it works across control servers.
func (s *Service) Watch(ctx context.Context, sessionID, resumeToken string, maxWait time.Duration) (commands bool, err error) {
	deadline := time.Now().Add(maxWait)
	for {
		if _, err := s.authSession(ctx, sessionID, resumeToken); err != nil {
			return false, err
		}
		// An admin queued a command (speed test, message, ...): tell the agent
		// to heartbeat now, which delivers it.
		if has, _ := s.store.HasCommands(ctx, sessionID); has {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		t := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return false, nil
		case <-t.C:
		}
	}
}

// SendCommand queues an admin command for a live session.
func (s *Service) SendCommand(ctx context.Context, sessionID, admin, kind, text string) (model.Command, error) {
	c := model.Command{ID: newID(), Type: kind, Text: text, From: admin, At: s.now()}
	if err := s.store.AddCommand(ctx, sessionID, c); err != nil {
		return c, s.endedOr(err)
	}
	detail := kind
	if text != "" {
		detail += ": " + text
	}
	s.audit(ctx, admin, "admin.command", sessionID, detail)
	return c, nil
}

// RequestMove asks a connected agent to move to another gateway (target ""
// = the best other one). The agent gets it with its next heartbeat, which
// the watch long-poll triggers within seconds.
func (s *Service) RequestMove(ctx context.Context, sessionID, admin, target string) error {
	sess, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return s.endedOr(err)
	}
	if !sess.State.Live() {
		return ErrReauthRequired
	}
	if target != "" {
		if target == sess.GatewayID {
			return fmt.Errorf("%w: the session is already on %s", ErrBadRequest, target)
		}
		gws, err := s.store.ListGateways(ctx)
		if err != nil {
			return err
		}
		ok := false
		for _, g := range gws {
			if g.ID == target && g.Enabled {
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%w: gateway %s isn't available", ErrBadRequest, target)
		}
	}
	c := model.Command{ID: newID(), Type: "move", Text: target, From: admin, At: s.now()}
	if err := s.store.AddCommand(ctx, sessionID, c); err != nil {
		return s.endedOr(err)
	}
	dest := target
	if dest == "" {
		dest = "best available"
	}
	s.audit(ctx, admin, "admin.move", sessionID, "moving "+sess.UPN+" from "+sess.GatewayID+" to "+dest)
	return nil
}

// AdminDisconnect ends a session from the admin site. The client's next
// heartbeat gets reauth_required and the gateway drops the peer on its next poll.
func (s *Service) AdminDisconnect(ctx context.Context, sessionID, admin string) error {
	sess, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return s.endedOr(err)
	}
	if err := s.store.EndSession(ctx, sessionID, model.StateTerminated, model.ReasonAdminDisconnect, s.now()); err != nil {
		return s.endedOr(err)
	}
	s.log.Warn("session disconnected by admin", "session", sessionID, "upn", sess.UPN, "admin", admin)
	s.audit(ctx, admin, "admin.disconnect", sessionID, "disconnected "+sess.UPN)
	return nil
}

func (s *Service) audit(ctx context.Context, actor, action, target, detail string) {
	if err := s.store.AddAudit(ctx, model.AuditEntry{At: s.now(), Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		s.log.Error("write audit log", "action", action, "err", err)
	}
}

// Sweep applies time-based transitions. Safe to run on every control server.
func (s *Service) Sweep(ctx context.Context) (store.SweepResult, error) {
	now := s.now()
	return s.store.Sweep(ctx, now, now.Add(-s.cfg.SuspendAfter), now.Add(-s.cfg.Grace))
}

// checkResumable authenticates the resume token and enforces the grace window,
// reboot detection and absolute lifetime.
func (s *Service) checkResumable(ctx context.Context, sessionID, resumeToken, bootID string) (model.Session, error) {
	sess, err := s.authSession(ctx, sessionID, resumeToken)
	if err != nil {
		return model.Session{}, err
	}
	now := s.now()
	switch {
	case bootID != sess.BootID:
		_ = s.store.EndSession(ctx, sess.ID, model.StateExpired, model.ReasonReboot, now)
		s.log.Info("session ended: device rebooted", "session", sess.ID, "upn", sess.UPN)
		s.audit(ctx, sess.UPN, "session.reboot", sess.ID, "device rebooted; fresh sign-in required")
		return model.Session{}, ErrReauthRequired
	case now.After(sess.ExpiresAt):
		_ = s.store.EndSession(ctx, sess.ID, model.StateTerminated, model.ReasonMaxLifetime, now)
		return model.Session{}, ErrReauthRequired
	case now.Sub(sess.LastSeen) > s.cfg.Grace:
		_ = s.store.EndSession(ctx, sess.ID, model.StateExpired, model.ReasonGraceExpired, now)
		return model.Session{}, ErrReauthRequired
	}
	return sess, nil
}

// authSession loads a live session and checks its resume token.
func (s *Service) authSession(ctx context.Context, sessionID, resumeToken string) (model.Session, error) {
	sess, err := s.store.GetSession(ctx, sessionID)
	if errors.Is(err, store.ErrNotFound) {
		return model.Session{}, ErrReauthRequired
	}
	if err != nil {
		return model.Session{}, err
	}
	h := sha256.Sum256([]byte(resumeToken))
	if subtle.ConstantTimeCompare(h[:], sess.ResumeTokenHash) != 1 {
		return model.Session{}, ErrReauthRequired
	}
	if !sess.State.Live() {
		return model.Session{}, ErrReauthRequired
	}
	return sess, nil
}

func (s *Service) placement(ctx context.Context, sessionID string) (Placement, error) {
	sess, err := s.store.GetSession(ctx, sessionID)
	if err != nil {
		return Placement{}, s.endedOr(err)
	}
	all, err := s.store.ListGateways(ctx)
	if err != nil {
		return Placement{}, err
	}
	var p Placement
	p.Session = sess
	for _, g := range all {
		if g.ID == sess.GatewayID {
			p.Gateway = g
		}
	}
	if ranked, err := s.rankGateways(ctx, sess.GatewayID); err == nil {
		p.Alternates = ranked
	}
	return p, nil
}

// Policy returns the placement policy an admin saved, or the configured default.
func (s *Service) Policy(ctx context.Context) model.PlacementPolicy {
	if p, ok, err := s.store.GetPlacementPolicy(ctx); err == nil && ok {
		return p
	}
	return s.cfg.DefaultPolicy
}

// CheckResources reports whether a gateway's host is within the placement
// limits, and if not, which limit it breaks. Missing or stale metrics count
// as within limits: a lack of data never blocks connections.
func CheckResources(m model.HostMetrics, p model.PlacementPolicy, now time.Time, maxAge time.Duration) (bool, string) {
	if m.At.IsZero() || now.Sub(m.At) > maxAge {
		return true, ""
	}
	var over []string
	if p.MaxCPUPercent > 0 && m.CPUPercent >= p.MaxCPUPercent {
		over = append(over, fmt.Sprintf("CPU %.0f%% (limit %.0f%%)", m.CPUPercent, p.MaxCPUPercent))
	}
	if p.MaxMemPercent > 0 && m.MemTotal > 0 {
		if pct := float64(m.MemUsed) / float64(m.MemTotal) * 100; pct >= p.MaxMemPercent {
			over = append(over, fmt.Sprintf("memory %.0f%% (limit %.0f%%)", pct, p.MaxMemPercent))
		}
	}
	if p.MinFreeDiskGB > 0 && m.DiskTotal > 0 {
		if free := float64(m.DiskTotal-m.DiskUsed) / (1 << 30); free < p.MinFreeDiskGB {
			over = append(over, fmt.Sprintf("free disk %.1f GB (minimum %.0f GB)", free, p.MinFreeDiskGB))
		}
	}
	if len(over) > 0 {
		return false, strings.Join(over, ", ")
	}
	return true, ""
}

// rankGateways returns the gateways new sessions may use, best first, leaving
// out the one named in exclude.
//
//  1. A gateway must be enabled, reporting, and below its capacity ceiling.
//  2. Gateways whose host is within the resource limits (CPU, memory, free
//     disk) come first. Only if every gateway is over its limits are the
//     over-limit ones used, so people can still connect.
//  3. Within each group, gateways are balanced by live session count (from the
//     database, so a burst of connects spreads evenly), ties going to the one
//     with lower CPU. Capacity size doesn't weight the balance.
func (s *Service) rankGateways(ctx context.Context, exclude string) ([]model.Gateway, error) {
	all, err := s.store.ListGateways(ctx)
	if err != nil {
		return nil, err
	}
	counts, err := s.store.LiveCounts(ctx)
	if err != nil {
		return nil, err
	}
	policy := s.Policy(ctx)
	now := s.now()
	var within, over []model.Gateway
	for _, g := range all {
		if g.ID == exclude || !g.Enabled || g.Capacity <= 0 {
			continue
		}
		if now.Sub(g.LastHealth) > s.cfg.GatewayHealthTTL || counts[g.ID] >= g.Capacity {
			continue
		}
		if ok, _ := CheckResources(g.Metrics, policy, now, s.cfg.GatewayHealthTTL); ok {
			within = append(within, g)
		} else {
			over = append(over, g)
		}
	}
	byLoad := func(l []model.Gateway) {
		sort.SliceStable(l, func(i, j int) bool {
			if counts[l[i].ID] != counts[l[j].ID] {
				return counts[l[i].ID] < counts[l[j].ID]
			}
			return l[i].Metrics.CPUPercent < l[j].Metrics.CPUPercent
		})
	}
	byLoad(within)
	byLoad(over)
	if len(within) == 0 && len(over) > 0 {
		s.log.Warn("every available gateway is over its resource limits; placing on the least busy anyway",
			"max_cpu", policy.MaxCPUPercent, "max_mem", policy.MaxMemPercent, "min_free_disk_gb", policy.MinFreeDiskGB)
	}
	ranked := append(within, over...)
	if len(ranked) == 0 {
		return nil, ErrNoGateway
	}
	return ranked, nil
}

func (s *Service) endedOr(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrReauthRequired
	}
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func without(gws []model.Gateway, id string) []model.Gateway {
	out := make([]model.Gateway, 0, len(gws))
	for _, g := range gws {
		if g.ID != id {
			out = append(out, g)
		}
	}
	return out
}

func validWGKey(k string) error {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("%w: wg_public_key must be a base64 WireGuard key", ErrBadRequest)
	}
	return nil
}

func newResumeToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(token))
	return token, h[:], nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// HashGatewayToken returns the hex SHA-256 stored for a gateway API token.
func HashGatewayToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
