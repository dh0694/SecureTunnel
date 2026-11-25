// Package agentcore is the platform-independent heart of the client agent: it
// signs in, opens the session, keeps it alive with heartbeats, rides out
// network drops within the grace window, fails over to another gateway when
// the current one stops answering, and tears everything down when the session
// ends. The OS-specific parts (the WireGuard tunnel, persistence, boot ID) are
// interfaces, so this logic is tested on any platform.
package agentcore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/clientapi"
)

// State is the agent's connection state, shown in the GUI.
type State string

const (
	StateDisconnected  State = "disconnected"
	StateSigningIn     State = "signing_in"
	StateConnecting    State = "connecting"
	StateConnected     State = "connected"
	StateReconnecting  State = "reconnecting"
	StateDisconnecting State = "disconnecting"
)

// API is the subset of the control-server client the engine uses.
type API interface {
	LocalLogin(ctx context.Context, user, password, code string) (string, error)
	Connect(ctx context.Context, token string, r clientapi.ConnectRequest) (clientapi.Placement, error)
	Heartbeat(ctx context.Context, sessionID, resumeToken, bootID string, diag *clientapi.Diagnostics) (clientapi.Placement, time.Duration, error)
	Failover(ctx context.Context, sessionID, resumeToken, bootID string) (clientapi.Placement, error)
	Disconnect(ctx context.Context, sessionID, resumeToken string) error
	Watch(ctx context.Context, sessionID, resumeToken string) (commands bool, err error)
}

// NetInfo describes the physical network the PC is using.
type NetInfo struct {
	Adapter   string `json:"adapter"`
	Kind      string `json:"kind"` // "Wi-Fi", "Ethernet", "Cellular", ...
	SSID      string `json:"ssid,omitempty"`
	SignalPct int    `json:"signal_pct,omitempty"`
	LinkMbps  int    `json:"link_mbps,omitempty"`
}

// RatePoint is one second of tunnel throughput.
type RatePoint struct {
	Rx         float64   `json:"rx"` // bits per second
	Tx         float64   `json:"tx"`
	start, end time.Time // sampling interval for this rate
}

// TunnelConfig is everything needed to bring up the WireGuard tunnel.
type TunnelConfig struct {
	PrivateKey    string
	Address       string
	DNS           []string
	MTU           int
	PeerPublicKey string
	Endpoint      string
	AllowedIPs    []string
	Keepalive     int
}

// WGQuick renders the config in wg-quick / WireGuard-for-Windows format.
func (c TunnelConfig) WGQuick() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", c.PrivateKey, c.Address)
	if len(c.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(c.DNS, ", "))
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n", c.PeerPublicKey, c.Endpoint, strings.Join(c.AllowedIPs, ", "))
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	return b.String()
}

// Tunnel controls the local WireGuard tunnel (and with it the kill switch).
type Tunnel interface {
	Up(TunnelConfig) error
	Down() error
	Running() bool
}

// Session is what the agent persists so it can recover after a service
// restart (but not a reboot: the boot ID check discards it).
type Session struct {
	Server         string                 `json:"server"`
	User           string                 `json:"user"`
	ID             string                 `json:"id"`
	ResumeToken    string                 `json:"resume_token"`
	BootID         string                 `json:"boot_id"`
	PrivateKey     string                 `json:"private_key"`
	Placement      clientapi.Placement    `json:"placement"`
	ConnectedSince time.Time              `json:"connected_since"`
	LastOK         time.Time              `json:"last_ok"`
	TunnelPending  bool                   `json:"tunnel_pending,omitempty"`
	DeviceTrust    *clientapi.DeviceTrust `json:"device_trust,omitempty"` // server's check at connect
	Device         bool                   `json:"device,omitempty"`       // pre-logon device tunnel (no user)
}

// Store persists the session.
type Store interface {
	Load() (*Session, error)
	Save(*Session) error
	Clear() error
}

// LatencySample is a timestamped reply, or a failed probe when MS is negative.
type LatencySample struct {
	At time.Time `json:"at"`
	MS int       `json:"ms"`
}

// Status is the snapshot the GUI shows.
type Status struct {
	State            State     `json:"state"`
	Message          string    `json:"message"`
	VPNPhase         string    `json:"vpn_phase,omitempty"`
	Server           string    `json:"server"`
	ServerInUse      string    `json:"server_in_use,omitempty"` // the address answering (a backup when the main one is down)
	ServerLocked     bool      `json:"server_locked"`
	User             string    `json:"user"`
	Gateway          string    `json:"gateway"`
	GatewayEndpoint  string    `json:"gateway_endpoint"`
	TunnelIP         string    `json:"tunnel_ip"`
	ConnectedSince   time.Time `json:"connected_since"`
	LastHeartbeat    time.Time `json:"last_heartbeat"`
	LatencyMs        int       `json:"latency_ms"`
	GraceLeftSec     int       `json:"grace_left_sec"`
	SessionExpires   time.Time `json:"session_expires"`
	OnTrustedNetwork bool      `json:"on_trusted_network"`
	TrustedReason    string    `json:"trusted_reason,omitempty"`
	OfficeMode       bool      `json:"office_mode"` // connected, but the tunnel is on standby on the office network
	TrustMode        string    `json:"trust_mode"`
	Version          string    `json:"version"`

	// Connection quality (latency of -1 means a failed check). With a gateway
	// that has an inside address, these come from pinging it through the
	// tunnel every few seconds; otherwise from heartbeats to the control server.
	LatencyHistory        []int           `json:"latency_history"` // up to 60 plotted points
	LatencyHistorySeconds int             `json:"latency_history_seconds"`
	LatencyLatestSeconds  int             `json:"latency_latest_seconds"`
	LossWindowSeconds     int             `json:"loss_window_seconds"`
	JitterMs              int             `json:"jitter_ms"`
	JitterMeasured        bool            `json:"jitter_measured"`
	LossPct               float64         `json:"loss_pct"`
	LatencySource         string          `json:"latency_source"`    // "gateway" or "control"
	ControlMs             int             `json:"control_ms"`        // last heartbeat round trip to the control server
	ControlHealthMs       int             `json:"control_health_ms"` // latest successful health probe, 0 when unavailable
	GatewayMs             int             `json:"gateway_ms"`        // last successful recent ping through the tunnel
	GatewayLatencyHistory []LatencySample `json:"gateway_latency_history"`
	ControlLatencyHistory []LatencySample `json:"control_latency_history"`

	// Tunnel traffic.
	RxBps              float64     `json:"rx_bps"`
	TxBps              float64     `json:"tx_bps"`
	RxBytes            uint64      `json:"rx_bytes"`
	TxBytes            uint64      `json:"tx_bytes"`
	RateHistory        []RatePoint `json:"rate_history"`
	RateHistorySeconds int         `json:"rate_history_seconds"`
	RateLatestSeconds  int         `json:"rate_latest_seconds"`

	Network NetInfo `json:"network"`

	// Connection drops in the last 15 minutes (for the "unstable" warning).
	DropsRecent int `json:"drops_recent"`

	// Device trust as the server saw it at connect (join, compliance, certificates).
	DeviceTrust *clientapi.DeviceTrust `json:"device_trust,omitempty"`

	// DeviceTunnel is set while only the pre-logon device tunnel is up (State
	// then reads "disconnected": no user is connected).
	DeviceTunnel *DeviceTunnelStatus `json:"device_tunnel,omitempty"`
}

// Options configure an Engine.
type Options struct {
	NewAPI       func(server string) API // builds a client for a server URL
	Tunnel       Tunnel
	Store        Store
	BootID       func() string
	DeviceID     string
	DeviceName   string // computer name shown to admins
	Platform     string
	KeyGen       func() (priv, pub string, err error)
	TrustedProbe func(ctx context.Context) (bool, string) // office detection and why; nil: none
	// Network change detection: a cheap fingerprint of the PC's own network
	// (addresses, DNS suffixes; not the tunnel). When it changes and settles,
	// OnNetworkChange runs (e.g. recheck the public IP), then the office check
	// and a heartbeat run at once. nil: timers only.
	NetFingerprint         func() string
	PhysicalRouteAvailable func() (available, known bool)
	OnNetworkChange        func(ctx context.Context, st State)
	TrustMode              func() string // how the server's certificate is trusted, for display
	Now                    func() time.Time
	Log                    *slog.Logger
	Version                string
	FailoverAfter          time.Duration // heartbeat outage before trying another gateway (default 60s)
	RetryEvery             time.Duration // heartbeat retry while reconnecting (default 5s)
	// ReconnectingAfter is how long without a successful heartbeat before the
	// GUI shows "Reconnecting", so a single slow check doesn't alarm anyone (default 20s).
	ReconnectingAfter time.Duration

	// OnTunnelChange runs after the tunnel goes up or down, so the HTTP client
	// can drop connections that were opened over the previous route.
	OnTunnelChange func()
	// TrafficStats returns the tunnel adapter's byte counters (nil: not shown).
	TrafficStats func() (rx, tx uint64, ok bool)
	// NetworkInfo describes the physical network (nil: not shown).
	NetworkInfo func() NetInfo
	// DiagExtra adds platform details (OS, public IPs, ...) to the heartbeat report.
	DiagExtra func(*clientapi.Diagnostics)
	// OnCommands handles admin commands delivered with a heartbeat.
	OnCommands func([]clientapi.Command)
	// DeviceProof signs a connect challenge with the PC's certificates and
	// reports its join state (nil: no device proofs).
	DeviceProof func(ctx context.Context, ch clientapi.Challenge) ([]clientapi.DeviceProof, *clientapi.JoinInfo)
	// DeviceTunnel says whether this PC may open the pre-logon device tunnel
	// while no user session is up (nil: never). See devicetunnel.go.
	DeviceTunnel func() bool
	// Ping sends one ICMP echo and returns the round trip (nil: latency comes
	// from heartbeats to the control server instead).
	Ping func(ctx context.Context, source, ip netip.Addr, timeout time.Duration) (time.Duration, error)
}

// Gateway pings: jitter and packet loss use the last 30 seconds, and the
// graph keeps up to 30 minutes.
const (
	pingEvery     = 5 * time.Second
	qualityWindow = 30 * time.Second
	pingKeep      = 360
	pingTimeout   = 2 * time.Second
	// statsWarmup is how long after connecting (or changing gateway) before
	// latency, jitter and loss are measured.
	statsWarmup = 5 * time.Second
)

// ConnectExtra carries a challenge the GUI already fetched and the proofs it
// signed with the user's certificate (the service can't reach the user's keys).
type ConnectExtra struct {
	Challenge *clientapi.Challenge
	Proofs    []clientapi.DeviceProof
	// WindowsUser is the Windows account that asked to connect, checked by
	// the server against the VPN user when the policy group says so.
	WindowsUser string
}

// Engine runs the connection lifecycle. All methods are safe for concurrent use.
type Engine struct {
	o Options

	tickMu         sync.Mutex // prevents overlapping heartbeats
	lifecycleMu    sync.Mutex // serializes tunnel and session-store changes
	mu             sync.Mutex
	server         string
	serverLocked   bool
	api            API
	sess           *Session
	state          State
	message        string
	vpnPhase       string
	latency        time.Duration
	lastHB         time.Time
	lastRecover    time.Time
	onTrusted      bool
	trustedWhy     string
	tunnelPending  bool // the desired tunnel configuration still needs applying
	commandSession *Session
	commandAcks    map[string]bool // false while dispatch is in progress
	standby        bool            // office mode: the session stays, the tunnel is down
	netKick        bool            // a settled physical network change needs a path check
	netChangedAt   time.Time
	pathConfirmed  bool // this gateway has answered a data probe
	pathMisses     int
	pathRepairedAt time.Time
	busy           bool        // a connect or disconnect is in progress
	forceHB        bool        // heartbeat now (the watch saw the session end)
	moveTo         *string     // admin asked to move to this gateway ("" = best other)
	drops          []time.Time // when the connection went from connected to reconnecting

	devBusy    bool      // a device tunnel connect is in progress
	devNext    time.Time // don't try the device tunnel again before this
	devFails   int
	devLastLog string

	hbHist             []int         // last 60 heartbeat latencies in ms, -1 = failed
	pingHist           []int         // gateway pings in ms, -1 = no reply (up to pingKeep)
	hbTimes, pingTimes []time.Time   // sample times, kept aligned with their histories
	ctrlRTT            time.Duration // last heartbeat round trip
	controlHealth      controlHealth
	rateHist           []RatePoint
	trafT              time.Time
	trafRx             uint64
	trafTx             uint64
	rxBps              float64
	txBps              float64

	wake chan struct{}
}

const histLen = 60

// ErrBusy means a connect or disconnect is already in progress.
var ErrBusy = errors.New("already working on it")

// New returns an Engine. Call Restore, then Run.
func New(o Options) *Engine {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.FailoverAfter <= 0 {
		o.FailoverAfter = 20 * time.Second // rebuilding on a new gateway/IP is fine; waiting isn't
	}
	if o.RetryEvery <= 0 {
		o.RetryEvery = 5 * time.Second
	}
	if o.Platform == "" {
		o.Platform = "windows"
	}
	if o.ReconnectingAfter <= 0 {
		o.ReconnectingAfter = 20 * time.Second
	}
	return &Engine{o: o, state: StateDisconnected, wake: make(chan struct{}, 1),
		controlHealth: controlHealth{wake: make(chan struct{}, 1)}}
}

// tunnelUp and tunnelDown wrap the Tunnel and reset HTTP connections after.
func (e *Engine) tunnelUp(c TunnelConfig) error {
	e.mu.Lock()
	sb := e.standby
	e.mu.Unlock()
	if sb {
		return nil // office mode: the tunnel comes up when the PC leaves the office
	}
	err := e.o.Tunnel.Up(c)
	if e.o.OnTunnelChange != nil {
		e.o.OnTunnelChange()
	}
	return err
}

func (e *Engine) tunnelDown() error {
	err := e.o.Tunnel.Down()
	if e.o.OnTunnelChange != nil {
		e.o.OnTunnelChange()
	}
	return err
}

func (e *Engine) recordHB(ms int, now time.Time) {
	e.hbTimes = append(e.hbTimes, now)
	e.hbHist = append(e.hbHist, ms)
	if len(e.hbHist) > histLen {
		e.hbHist = e.hbHist[len(e.hbHist)-histLen:]
		e.hbTimes = e.hbTimes[len(e.hbTimes)-histLen:]
	}
}

func (e *Engine) recordControlCheck(now time.Time, rtt time.Duration, err error) {
	sample := -1
	if err == nil {
		sample = max(1, int(rtt/time.Millisecond))
	}
	e.recordHB(sample, now)
}

// sampleTraffic updates throughput from the adapter counters (called with mu held).
func (e *Engine) sampleTraffic(now time.Time) {
	if e.o.TrafficStats == nil || e.sess == nil {
		return
	}
	rx, tx, ok := e.o.TrafficStats()
	if !ok {
		return
	}
	if !e.trafT.IsZero() && rx >= e.trafRx && tx >= e.trafTx {
		dt := now.Sub(e.trafT).Seconds()
		if dt < 0.5 {
			return // sampled very recently; keep the last rate
		}
		e.rxBps = float64(rx-e.trafRx) * 8 / dt
		e.txBps = float64(tx-e.trafTx) * 8 / dt
		e.rateHist = append(e.rateHist, RatePoint{Rx: e.rxBps, Tx: e.txBps, start: e.trafT, end: now})
		if len(e.rateHist) > histLen {
			e.rateHist = e.rateHist[len(e.rateHist)-histLen:]
		}
	}
	e.trafT, e.trafRx, e.trafTx = now, rx, tx
}

// pinging reports whether latency comes from gateway pings for this session
// (called with mu held).
func (e *Engine) pinging(s *Session) bool {
	return e.o.Ping != nil && s != nil && s.Placement.Gateway.InsideIP != "" && !e.standby
}

// pingLoop pings the gateway's inside address through the tunnel while
// connected. That's the path the user's traffic takes, so it's the latency
// they feel; heartbeats also cross Cloudflare and the control server.
func (e *Engine) pingLoop(ctx context.Context) {
	t := time.NewTicker(pingEvery)
	defer t.Stop()
	var lastGW string
	var warmUntil time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.mu.Lock()
		s, st := e.sess, e.state
		ok := e.pinging(s) && (st == StateConnected || st == StateReconnecting)
		var source, ip netip.Addr
		if ok {
			now := e.o.Now()
			source, ip = tunnelProbeAddresses(s)
			if gw := s.Placement.Gateway.ID; gw != lastGW { // moved: start the figures fresh
				e.pingHist, e.pingTimes, lastGW = nil, nil, gw
				warmUntil = now.Add(statsWarmup)
			}
			// Right after connecting (or moving gateway) routes and the
			// handshake are still settling: those pings would show false
			// spikes and loss, so they aren't counted.
			if now.Sub(s.ConnectedSince) < statsWarmup || now.Before(warmUntil) {
				ok = false
			}
		}
		e.mu.Unlock()
		if !ok || !source.IsValid() || !ip.IsValid() {
			continue
		}
		rtt, err := e.o.Ping(ctx, source, ip, pingTimeout)
		e.mu.Lock()
		checkPath := false
		if e.sess == s && s.Placement.Gateway.InsideIP == ip.String() && !e.standby {
			checkPath = e.observePath(err == nil)
			ms := -1
			if err == nil {
				ms, e.latency = int(rtt/time.Millisecond), rtt
				if ms == 0 && rtt > 0 {
					ms = 1 // show sub-millisecond as 1 ms, not "–"
				}
			}
			e.pingHist = append(e.pingHist, ms)
			e.pingTimes = append(e.pingTimes, e.o.Now())
			if len(e.pingHist) > pingKeep {
				e.pingHist = e.pingHist[len(e.pingHist)-pingKeep:]
				e.pingTimes = e.pingTimes[len(e.pingTimes)-pingKeep:]
			}
		}
		e.mu.Unlock()
		if checkPath {
			e.Kick()
		}
	}
}

// pingGraph shrinks the ping history to histLen points for the graph: each
// point is the average of its pings, or -1 if none got a reply.
func pingGraph(h []int) []int {
	if len(h) <= histLen {
		return append([]int(nil), h...)
	}
	per := (len(h) + histLen - 1) / histLen
	h = h[pingGraphOffset(len(h)):] // drop the oldest partial bucket
	out := make([]int, 0, histLen)
	for i := 0; i < len(h); i += per {
		sum, n := 0, 0
		for _, v := range h[i : i+per] {
			if v >= 0 {
				sum += v
				n++
			}
		}
		if n == 0 {
			out = append(out, -1)
		} else {
			out = append(out, sum/n)
		}
	}
	return out
}

// pingGraphOffset is the number of oldest samples dropped by pingGraph.
func pingGraphOffset(count int) int {
	return count % max(1, (count+histLen-1)/histLen)
}

func secondsSince(now, then time.Time) int {
	if then.IsZero() {
		return 0
	}
	return max(0, int(now.Sub(then).Round(time.Second)/time.Second))
}

func (e *Engine) resetStats() {
	e.hbHist, e.rateHist, e.pingHist, e.ctrlRTT = nil, nil, nil, 0
	e.hbTimes, e.pingTimes = nil, nil
	e.trafT, e.trafRx, e.trafTx, e.rxBps, e.txBps = time.Time{}, 0, 0, 0, 0
}

// recentSampleStart excludes checks at or before the rolling window cutoff.
func recentSampleStart(times []time.Time, cutoff time.Time) int {
	start := len(times)
	for start > 0 && times[start-1].After(cutoff) {
		start--
	}
	return start
}

func latencySamples(values []int, times []time.Time, cutoff time.Time) []LatencySample {
	start := recentSampleStart(times, cutoff)
	out := make([]LatencySample, 0, len(times)-start)
	for i := start; i < len(times); i++ {
		out = append(out, LatencySample{At: times[i], MS: values[i]})
	}
	return out
}

// quality computes jitter from consecutive replies and loss from all checks.
func quality(h []int) (jitter int, loss float64, jitterMeasured bool) {
	if len(h) == 0 {
		return 0, 0, false
	}
	var fails, n, sum int
	prev := -1
	for _, v := range h {
		if v < 0 {
			fails++
			prev = -1
			continue
		}
		if prev >= 0 {
			d := v - prev
			if d < 0 {
				d = -d
			}
			sum += d
			n++
		}
		prev = v
	}
	if n > 0 {
		jitter = sum / n
	}
	return jitter, float64(fails) * 100 / float64(len(h)), n > 0
}

// SetServer sets the control server (already normalized). locked means it
// comes from policy and the user may not change it.
func (e *Engine) SetServer(server string, locked bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess != nil && server != e.server {
		return errors.New("disconnect before changing the server")
	}
	if e.serverLocked && !locked && server != e.server {
		return errors.New("the server is set by your IT department")
	}
	if server != e.server {
		e.controlHealth.host = ""
		e.controlHealth.history = nil
	}
	e.server, e.serverLocked = server, locked
	e.api = nil
	if server != "" {
		e.api = e.o.NewAPI(server)
	}
	e.controlHealth.apiGeneration++
	if e.controlHealth.session != nil {
		e.controlHealth.poke()
	}
	return nil
}

// diagnostics builds the report sent with each heartbeat: the engine's own
// traffic, quality and network figures plus the platform's (OS, public IPs, ...).
func (e *Engine) diagnostics() *clientapi.Diagnostics {
	st := e.Status()
	d := &clientapi.Diagnostics{
		RxBytes: st.RxBytes, TxBytes: st.TxBytes, RxBps: st.RxBps, TxBps: st.TxBps,
		LatencyMs: st.LatencyMs, JitterMs: st.JitterMs, LossPct: st.LossPct, Drops15m: st.DropsRecent,
		LatencySource: st.LatencySource, ControlMs: st.ControlMs, OfficeMode: st.OfficeMode,
		Adapter: st.Network.Adapter, NetKind: st.Network.Kind, SSID: st.Network.SSID,
		SignalPct: st.Network.SignalPct, LinkMbps: st.Network.LinkMbps,
		AgentVersion: e.o.Version,
	}
	if e.o.DiagExtra != nil {
		e.o.DiagExtra(d)
	}
	return d
}

// Kick sends a heartbeat now (e.g. to deliver fresh diagnostics or pick up commands).
// RequestMove queues a move to another gateway (from an admin command).
func (e *Engine) RequestMove(target string) {
	e.mu.Lock()
	e.moveTo = &target
	e.mu.Unlock()
	e.poke()
}

// moveGateway switches the tunnel to another gateway the server picks (or
// the admin's target). The tunnel IP comes from the new gateway's pool.
func (e *Engine) moveGateway(ctx context.Context, s *Session, api API, target string) {
	mover, ok := api.(interface {
		FailoverTo(ctx context.Context, sessionID, resumeToken, bootID, target string) (clientapi.Placement, error)
	})
	if !ok {
		return
	}
	fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	p, err := mover.FailoverTo(fctx, s.ID, s.ResumeToken, s.BootID, target)
	cancel()
	if err != nil {
		if clientapi.IsReauth(err) {
			e.teardown("Your session ended. Sign in again to reconnect.")
			return
		}
		e.o.Log.Warn("move to another gateway failed; staying", "err", err)
		return
	}
	if p.Gateway.ID == s.Placement.Gateway.ID {
		return
	}
	from := s.Placement.Gateway.ID
	e.mu.Lock()
	e.setState(StateReconnecting, "Moving to gateway "+p.Gateway.ID+"…")
	e.vpnPhase = vpnSwitchingGateway
	e.mu.Unlock()
	_ = e.tunnelDown()
	e.applyMove(s, p)
	e.o.Log.Info("moved to another gateway", "from", from, "to", p.Gateway.ID, "tunnel_ip", p.Tunnel.Address)
}

func (e *Engine) Kick() {
	e.mu.Lock()
	e.forceHB = true
	e.mu.Unlock()
	e.poke()
}

// CurrentSession returns a copy of the active session, if any.
func (e *Engine) CurrentSession() (Session, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil {
		return Session{}, false
	}
	return *e.sess, true
}

// Status returns the current status.
func (e *Engine) Status() Status {
	var netInfo NetInfo
	if e.o.NetworkInfo != nil {
		netInfo = e.o.NetworkInfo() // may be slow; the platform caches it
	}
	trust := ""
	if e.o.TrustMode != nil {
		trust = e.o.TrustMode()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.o.Now()
	e.sampleTraffic(now)
	inUse := e.activeServer()
	st := Status{
		State: e.state, Message: e.message, VPNPhase: e.vpnPhase, Server: e.server, ServerInUse: inUse, ServerLocked: e.serverLocked,
		LastHeartbeat: e.lastHB, LatencyMs: int(e.latency / time.Millisecond),
		OnTrustedNetwork: e.onTrusted, TrustedReason: e.trustedWhy, OfficeMode: e.standby && e.sess != nil, Version: e.o.Version, TrustMode: trust, Network: netInfo,
		LatencyHistory: append([]int(nil), e.hbHist...),
		RateHistory:    append([]RatePoint(nil), e.rateHist...),
		RxBps:          e.rxBps, TxBps: e.txBps,
		LatencySource: "control", ControlMs: int(e.ctrlRTT / time.Millisecond),
	}
	historyCutoff := now.Add(-30 * time.Minute)
	cutoff := now.Add(-qualityWindow)
	e.controlHealth.status(&st, now, historyCutoff)
	st.GatewayLatencyHistory = latencySamples(e.pingHist, e.pingTimes, historyCutoff)
	_, st.LossPct, _ = quality(e.hbHist)
	st.JitterMs, _, st.JitterMeasured = quality(e.hbHist[recentSampleStart(e.hbTimes, cutoff):])
	if len(e.rateHist) > 0 {
		st.RateHistorySeconds = secondsSince(now, e.rateHist[0].start)
		st.RateLatestSeconds = secondsSince(now, e.rateHist[len(e.rateHist)-1].end)
	}
	if len(e.hbTimes) > 0 {
		st.LatencyHistorySeconds = secondsSince(now, e.hbTimes[0])
		st.LatencyLatestSeconds = secondsSince(now, e.hbTimes[len(e.hbTimes)-1])
		st.LossWindowSeconds = st.LatencyHistorySeconds
	}
	if e.pinging(e.sess) && len(e.pingHist) > 0 {
		st.LatencySource = "gateway"
		st.LatencyHistory = pingGraph(e.pingHist)
		st.LatencyHistorySeconds = secondsSince(now, e.pingTimes[pingGraphOffset(len(e.pingTimes))].Add(-pingEvery))
		st.LatencyLatestSeconds = secondsSince(now, e.pingTimes[len(e.pingTimes)-1])
		start := recentSampleStart(e.pingTimes, cutoff)
		st.JitterMs, st.LossPct, st.JitterMeasured = quality(e.pingHist[start:])
		for i := len(e.pingHist) - 1; i >= start; i-- {
			if e.pingHist[i] >= 0 {
				st.GatewayMs = max(1, e.pingHist[i])
				break
			}
		}
		st.LossWindowSeconds = 0
		if start < len(e.pingTimes) {
			st.LossWindowSeconds = min(int(qualityWindow/time.Second), secondsSince(now, e.pingTimes[start].Add(-pingEvery)))
		}
	}
	if e.sess != nil && !e.trafT.IsZero() {
		st.RxBytes, st.TxBytes = e.trafRx, e.trafTx
	}
	if s := e.sess; s != nil {
		st.User = s.User
		st.DeviceTrust = s.DeviceTrust
		st.DropsRecent = e.recentDrops()
		st.Gateway = s.Placement.Gateway.ID
		st.GatewayEndpoint = s.Placement.Gateway.Endpoint
		st.TunnelIP = strings.TrimSuffix(s.Placement.Tunnel.Address, "/32")
		st.ConnectedSince = s.ConnectedSince
		st.SessionExpires = s.Placement.ExpiresAt
		if e.state == StateReconnecting {
			left := e.grace(s) - e.o.Now().Sub(s.LastOK)
			if left < 0 {
				left = 0
			}
			st.GraceLeftSec = int(left / time.Second)
		}
	}
	e.deviceStatus(&st)
	return st
}

func (e *Engine) grace(s *Session) time.Duration {
	if s.Placement.GraceSeconds > 0 {
		return time.Duration(s.Placement.GraceSeconds) * time.Second
	}
	return 15 * time.Minute
}

func (e *Engine) heartbeatEvery(s *Session) time.Duration {
	if s.Placement.HeartbeatSeconds > 0 {
		return time.Duration(s.Placement.HeartbeatSeconds) * time.Second
	}
	return 30 * time.Second
}

func tunnelConfig(priv string, p clientapi.Placement) TunnelConfig {
	return TunnelConfig{
		PrivateKey: priv, Address: p.Tunnel.Address, DNS: p.Tunnel.DNS, MTU: p.Tunnel.MTU,
		PeerPublicKey: p.Gateway.PublicKey, Endpoint: p.Gateway.Endpoint,
		AllowedIPs: p.Tunnel.AllowedIPs, Keepalive: p.Tunnel.Keepalive,
	}
}

func (e *Engine) setState(s State, msg string) {
	if s == StateReconnecting && e.state == StateConnected {
		now := e.o.Now()
		e.drops = append(e.drops, now)
		cut := 0
		for cut < len(e.drops) && now.Sub(e.drops[cut]) > 15*time.Minute {
			cut++
		}
		e.drops = e.drops[cut:]
	}
	e.state, e.message = s, msg
	e.syncControlHealthSession()
	if s != StateReconnecting {
		e.vpnPhase = ""
	}
}

// recentDrops counts connection drops in the last 15 minutes (caller holds mu).
func (e *Engine) recentDrops() int {
	n := 0
	for _, t := range e.drops {
		if e.o.Now().Sub(t) <= 15*time.Minute {
			n++
		}
	}
	return n
}

func (e *Engine) poke() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Connect signs in and opens the tunnel. If the account needs an
// authenticator code and none was given, it returns an error for which
// clientapi.HasCode(err, "code_required") is true.
func (e *Engine) Connect(ctx context.Context, user, password, code string, extra ...ConnectExtra) error {
	return e.connect(ctx, user, func(api API) (string, error) { return api.LocalLogin(ctx, user, password, code) }, extra)
}

// ConnectWithToken opens the tunnel with an access token the user got by
// signing in with Microsoft (the GUI runs that browser sign-in). user is the
// UPN, shown in the app.
func (e *Engine) ConnectWithToken(ctx context.Context, user, token string, extra ...ConnectExtra) error {
	if token == "" {
		return errors.New("no sign-in token")
	}
	return e.connect(ctx, user, func(API) (string, error) { return token, nil }, extra)
}

// addProofs fills in the device trust part of a connect request. Servers
// without device trust (404) simply get none.
func (e *Engine) addProofs(ctx context.Context, api API, req *clientapi.ConnectRequest, extra []ConnectExtra) {
	var ch *clientapi.Challenge
	var proofs []clientapi.DeviceProof
	for _, x := range extra {
		if x.Challenge != nil {
			ch = x.Challenge
		}
		proofs = append(proofs, x.Proofs...)
	}
	if ch == nil {
		c, ok := api.(interface {
			Challenge(context.Context) (clientapi.Challenge, error)
		})
		if !ok {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		got, err := c.Challenge(cctx)
		cancel()
		if err != nil {
			if !clientapi.HasStatus(err, 404) {
				e.o.Log.Warn("device challenge", "err", err)
			}
			return
		}
		ch = &got
	}
	req.Nonce = ch.Nonce
	if e.o.DeviceProof != nil {
		p, j := e.o.DeviceProof(ctx, *ch)
		proofs = append(proofs, p...)
		req.Join = j
	}
	req.Proofs = proofs
}

// waitDuo shows "approve the Duo Push", polls until the user answers on
// their phone, then connects again with the approval.
func (e *Engine) waitDuo(ctx context.Context, api API, token string, creq clientapi.ConnectRequest, pending error) (clientapi.Placement, error) {
	var ae *clientapi.APIError
	errors.As(pending, &ae)
	poller, ok := api.(interface {
		DuoStatus(ctx context.Context, tx string) (string, string, error)
	})
	if !ok || ae.DuoTx == "" {
		return clientapi.Placement{}, pending
	}
	e.mu.Lock()
	e.setState(StateSigningIn, ae.Message)
	e.mu.Unlock()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return clientapi.Placement{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		st, msg, err := poller.DuoStatus(pctx, ae.DuoTx)
		cancel()
		if err != nil {
			continue
		}
		switch st {
		case "allow":
			e.mu.Lock()
			e.setState(StateConnecting, "")
			e.mu.Unlock()
			creq.DuoTx = ae.DuoTx
			return api.Connect(ctx, token, creq)
		case "deny":
			return clientapi.Placement{}, &clientapi.APIError{Status: 403, Code: "duo_denied", Message: msg}
		}
	}
	return clientapi.Placement{}, &clientapi.APIError{Status: 403, Code: "duo_denied",
		Message: "The Duo Push wasn't approved in time. Connect again to get a new one."}
}

func (e *Engine) connect(ctx context.Context, user string, signIn func(API) (string, error), extra []ConnectExtra) error {
	e.waitDeviceConnect(ctx)
	e.lifecycleMu.Lock()
	e.mu.Lock()
	switch {
	case e.busy:
		e.mu.Unlock()
		e.lifecycleMu.Unlock()
		return ErrBusy
	case e.sess != nil && !e.sess.Device: // a device tunnel is replaced by the user's
		e.mu.Unlock()
		e.lifecycleMu.Unlock()
		return errors.New("already connected")
	case e.api == nil:
		e.mu.Unlock()
		e.lifecycleMu.Unlock()
		return errors.New("no server is set up yet")
	}
	// On the office network: sign in, but leave the tunnel on standby.
	e.standby = e.onTrusted
	api, server := e.api, e.server
	e.busy = true
	e.setState(StateSigningIn, "")
	e.mu.Unlock()
	e.lifecycleMu.Unlock()

	fail := func(err error, msg string) error {
		e.mu.Lock()
		e.busy = false
		e.standby = false
		e.setState(StateDisconnected, msg)
		e.mu.Unlock()
		return err
	}

	token, err := signIn(api)
	if err != nil {
		if clientapi.HasCode(err, "code_required") {
			return fail(err, "")
		}
		return fail(err, friendly(err))
	}
	e.mu.Lock()
	e.setState(StateConnecting, "")
	e.mu.Unlock()

	priv, pub, err := e.o.KeyGen()
	if err != nil {
		return fail(err, "Couldn't create tunnel keys.")
	}
	boot := e.o.BootID()
	creq := clientapi.ConnectRequest{WGPublicKey: pub, DeviceID: e.o.DeviceID, DeviceName: e.o.DeviceName, BootID: boot, Platform: e.o.Platform}
	for _, x := range extra {
		if x.WindowsUser != "" {
			creq.WindowsUser = x.WindowsUser
		}
	}
	e.addProofs(ctx, api, &creq, extra)
	p, err := api.Connect(ctx, token, creq)
	if clientapi.HasCode(err, "duo_pending") {
		p, err = e.waitDuo(ctx, api, token, creq, err)
	}
	if err != nil {
		return fail(err, friendly(err))
	}
	if err := e.tunnelUp(tunnelConfig(priv, p)); err != nil {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = api.Disconnect(dctx, p.SessionID, p.ResumeToken)
		cancel()
		return fail(err, "Couldn't start the tunnel: "+err.Error())
	}
	now := e.o.Now()
	s := &Session{Server: server, User: strings.ToLower(strings.TrimSpace(user)), ID: p.SessionID, ResumeToken: p.ResumeToken,
		BootID: boot, PrivateKey: priv, Placement: p, ConnectedSince: now, LastOK: now, DeviceTrust: p.DeviceTrust}
	if err := e.o.Store.Save(s); err != nil {
		e.o.Log.Warn("save session", "err", err)
	}
	e.mu.Lock()
	e.sess, e.busy, e.lastHB = s, false, now
	e.tunnelPending = false
	e.resetPath()
	e.resetStats()
	e.setState(StateConnected, "")
	e.mu.Unlock()
	e.o.Log.Info("connected", "user", s.User, "gateway", p.Gateway.ID, "tunnel_ip", p.Tunnel.Address)
	e.poke()
	return nil
}

// Disconnect ends the session on purpose (the next connect needs a fresh sign-in).
func (e *Engine) Disconnect(ctx context.Context) error { return e.DisconnectBecause(ctx, "") }

// WindowsSessions returns the connected session's Windows sign-out / switch /
// lock policy (defaults filled in); ok is false when there's no session.
func (e *Engine) WindowsSessions() (p clientapi.WindowsSessions, ok bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.sess == nil || e.sess.Device {
		return clientapi.WindowsSessionsOrDefault(nil), false
	}
	return clientapi.WindowsSessionsOrDefault(e.sess.Placement.WindowsSessions), true
}

// DisconnectBecause ends the session like Disconnect and shows why (e.g. the
// Windows user signed out); an empty reason is a plain user disconnect.
func (e *Engine) DisconnectBecause(ctx context.Context, reason string) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.mu.Lock()
	if e.busy {
		e.mu.Unlock()
		return ErrBusy
	}
	s, api := e.sess, e.api
	if s == nil || s.Device { // the device tunnel isn't the user's to disconnect
		if s == nil {
			e.setState(StateDisconnected, "")
		}
		e.mu.Unlock()
		return nil
	}
	e.busy = true
	e.setState(StateDisconnecting, "")
	e.mu.Unlock()

	// Tell the server while the tunnel is still up (with full tunnel that's
	// the quickest route), but only briefly: the user is waiting.
	var told bool
	if api != nil {
		dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := api.Disconnect(dctx, s.ID, s.ResumeToken)
		cancel()
		told = err == nil || clientapi.IsReauth(err)
	}
	e.teardown(reason)
	e.mu.Lock()
	e.busy = false
	e.mu.Unlock()
	if reason != "" {
		e.o.Log.Info("disconnected", "reason", reason, "server_told", told)
	} else {
		e.o.Log.Info("disconnected by user", "server_told", told)
	}
	// If the server didn't hear it, keep trying in the background now that the
	// tunnel is down (otherwise the session would only end at the grace window).
	if !told && api != nil {
		go func() {
			for i := 0; i < 4; i++ {
				time.Sleep(time.Duration(i*3) * time.Second)
				dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := api.Disconnect(dctx, s.ID, s.ResumeToken)
				cancel()
				if err == nil || clientapi.IsReauth(err) {
					return
				}
			}
			e.o.Log.Warn("couldn't tell the server about the disconnect; the session will expire on its own")
		}()
	}
	return nil
}

// teardown stops the tunnel and forgets the session.
func (e *Engine) teardown(msg string) {
	e.mu.Lock()
	if e.sess != nil && e.sess.Device {
		msg = "" // nothing to tell a user about; the device tunnel reconnects by itself
		e.devNext = e.o.Now().Add(5 * time.Second)
	}
	e.mu.Unlock()
	if err := e.tunnelDown(); err != nil {
		e.o.Log.Error("stop tunnel", "err", err)
	}
	if err := e.o.Store.Clear(); err != nil {
		e.o.Log.Warn("clear session", "err", err)
	}
	e.mu.Lock()
	e.sess = nil
	e.tunnelPending = false
	e.resetPath()
	e.netKick, e.netChangedAt = false, time.Time{}
	e.moveTo = nil
	e.standby = false
	e.latency = 0
	e.resetStats()
	e.setState(StateDisconnected, msg)
	e.mu.Unlock()
}

// Restore picks up a session saved before a service restart. A session from
// before a reboot is discarded: rebooting always requires a fresh sign-in.
func (e *Engine) Restore() {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	s, err := e.o.Store.Load()
	if err != nil || s == nil {
		if e.o.Tunnel.Running() {
			_ = e.tunnelDown()
		}
		return
	}
	if s.BootID != e.o.BootID() {
		e.o.Log.Info("discarding session from before a reboot")
		_ = e.tunnelDown()
		_ = e.o.Store.Clear()
		e.mu.Lock()
		e.sess = nil
		e.setState(StateDisconnected, "")
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	if s.Server != e.server || e.api == nil {
		e.server = s.Server
		e.api = e.o.NewAPI(s.Server)
		e.controlHealth.apiGeneration++
	}
	e.sess = s
	e.tunnelPending = s.TunnelPending
	e.setState(StateReconnecting, "")
	e.mu.Unlock()
	e.ensureTunnel(s)
	e.o.Log.Info("restored session after service restart", "user", s.User)
	e.poke()
}

// Run drives heartbeats, recovery and office detection until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	go e.watchLoop(ctx)
	go e.controlHealthLoop(ctx)
	if e.o.Ping != nil {
		go e.pingLoop(ctx)
	}
	if e.o.NetFingerprint != nil {
		go e.netWatchLoop(ctx)
	}
	for {
		wait := e.Tick(ctx)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-e.wake:
			t.Stop()
		}
	}
}

// watchLoop keeps a long poll open to the server while connected, so an
// admin disconnect (or any other end of the session) reaches the PC within
// seconds. When the watch reports the session ended, it forces a heartbeat,
// which gets the definitive answer and tears down.
func (e *Engine) watchLoop(ctx context.Context) {
	for ctx.Err() == nil {
		e.mu.Lock()
		s, api, st := e.sess, e.api, e.state
		e.mu.Unlock()
		if s == nil || api == nil || st != StateConnected {
			sleepCtx(ctx, 2*time.Second)
			continue
		}
		wctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		pending, err := api.Watch(wctx, s.ID, s.ResumeToken)
		cancel()
		switch {
		case err == nil && pending:
			e.Kick() // an admin queued a command; the heartbeat delivers it
			sleepCtx(ctx, 2*time.Second)
		case err == nil:
			// still live; watch again right away
		case clientapi.IsReauth(err):
			e.o.Log.Info("server signalled the session ended")
			e.mu.Lock()
			e.forceHB = true
			e.mu.Unlock()
			e.poke()
			sleepCtx(ctx, 2*time.Second)
		default:
			sleepCtx(ctx, 5*time.Second) // network trouble; heartbeats handle it
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Tick does one round of work and returns how long to wait before the next.
// Exported for tests.
func (e *Engine) Tick(ctx context.Context) time.Duration {
	e.tickMu.Lock()
	defer e.tickMu.Unlock()
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	e.mu.Lock()
	s, api, busy, st, force := e.sess, e.api, e.busy, e.state, e.forceHB || e.netKick
	e.forceHB = false
	mv := e.moveTo
	if !busy {
		e.moveTo = nil
	}
	e.mu.Unlock()
	if busy {
		return time.Second
	}
	if mv != nil && s != nil {
		e.moveGateway(ctx, s, api, *mv)
		return time.Second
	}
	// Connected and checked recently: wait for the next heartbeat instead of
	// sending one early (e.g. when woken right after connecting).
	if s != nil && st == StateConnected && !force && (e.standby && !e.o.Tunnel.Running() || !e.standby && !e.tunnelPending && e.o.Tunnel.Running()) {
		if since := e.o.Now().Sub(s.LastOK); since < e.heartbeatEvery(s) {
			return e.heartbeatEvery(s) - since
		}
	}
	// Office network detection, connected or not.
	if e.o.TrustedProbe != nil {
		on, why := e.o.TrustedProbe(ctx)
		e.mu.Lock()
		if on != e.onTrusted {
			e.o.Log.Info("office network", "detected", on, "why", why)
		}
		e.onTrusted, e.trustedWhy = on, why
		e.mu.Unlock()
		switch {
		case on && s != nil && s.Device:
			// The device tunnel isn't needed in the office: end it.
			dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = api.Disconnect(dctx, s.ID, s.ResumeToken)
			cancel()
			e.teardown("")
			return 15 * time.Second
		case s != nil:
			// Office mode: stay signed in, but send traffic straight out the
			// office network. Back through the tunnel once the PC leaves.
			e.mu.Lock()
			was := e.standby
			e.standby = on
			e.mu.Unlock()
			if on && !was {
				e.o.Log.Info("office mode: tunnel on standby", "why", why)
				e.mu.Lock()
				e.resetStats()
				e.mu.Unlock()
			} else if !on && was {
				e.o.Log.Info("left the office network: tunnel back on")
				e.tunnelPending = true
				e.mu.Lock()
				s.ConnectedSince = e.o.Now() // stats warm up again
				e.mu.Unlock()
			}
		}
	}
	if s == nil {
		return e.deviceTick(ctx)
	}

	// Retry failed local setup even when the control API is currently unreachable.
	route := e.physicalRouteAvailable()
	tunnelReady := e.standby || (!e.tunnelPending && e.o.Tunnel.Running())
	if route || e.standby {
		tunnelReady = e.ensureTunnel(s)
	}
	e.mu.Lock()
	changedAt := e.netChangedAt
	roaming := e.netKick
	checkPath := roaming || e.pathMisses >= pathFailureThreshold
	e.mu.Unlock()
	path := pathUnknown
	switch {
	case e.standby || s.Device:
		e.setVPNPhase("")
	case !route:
		e.setVPNPhase(vpnWaitingForNetwork)
		path = e.checkTunnelPath(ctx, s, 1)
	case checkPath:
		e.setVPNPhase(vpnChecking)
		path = e.checkTunnelPath(ctx, s, pathFailureThreshold)
	default:
		e.mu.Lock()
		if e.vpnPhase == vpnWaitingForNetwork {
			e.vpnPhase = vpnChecking
		}
		e.mu.Unlock()
	}
	if path == pathWorking && (s.Placement.ExpiresAt.IsZero() || e.o.Now().Before(s.Placement.ExpiresAt)) {
		e.mu.Lock()
		e.setState(StateConnected, "")
		e.mu.Unlock()
	}
	diag := e.diagnostics()
	e.lifecycleMu.Unlock()
	heartbeatTimeout := 10 * time.Second
	if roaming && path == pathDown {
		// The tunnel has already missed several checks. Allow a quick
		// control reply before rebinding rather than waiting the full timeout.
		heartbeatTimeout = 4 * time.Second
	}
	hctx, cancel := context.WithTimeout(ctx, heartbeatTimeout)
	p, rtt, sent, err := e.heartbeat(hctx, api, s, diag)
	cancel()
	e.lifecycleMu.Lock()
	e.mu.Lock()
	current := e.sess == s && !e.busy
	e.mu.Unlock()
	if !current {
		return time.Second
	}
	e.mu.Lock()
	networkChanged := !e.netChangedAt.Equal(changedAt)
	e.mu.Unlock()
	if networkChanged && !clientapi.IsReauth(err) {
		// The watcher queued another check. Do not repair a path based on
		// probes collected before the latest network change.
		return time.Second
	}
	now := e.o.Now()
	if !clientapi.IsReauth(err) && now.Sub(s.ConnectedSince) >= statsWarmup {
		e.mu.Lock()
		e.recordControlCheck(now, rtt, err)
		e.mu.Unlock()
	}
	switch {
	case err == nil:
		e.acceptCommands(s, p.Commands, sent)
		if e.updatePlacement(s, p) {
			path = pathUnknown // a probe of the previous assignment no longer applies
			// A new placement can arrive with this heartbeat. Apply it now.
			tunnelReady = e.ensureTunnel(s)
		}
		e.mu.Lock()
		if st != StateConnected && tunnelReady {
			e.o.Log.Info("connection restored", "offline_for", now.Sub(s.LastOK).Round(time.Second))
		}
		s.LastOK = now
		if path == pathDown && !e.pathConfirmed {
			path = pathUnknown // ICMP has never been established on this gateway
		}
		if !p.ExpiresAt.IsZero() {
			s.Placement.ExpiresAt = p.ExpiresAt
		}
		if path != pathDown && e.netChangedAt.Equal(changedAt) {
			e.netKick, e.netChangedAt = false, time.Time{}
		}
		e.lastHB, e.ctrlRTT = now, rtt
		if !e.pinging(s) && now.Sub(s.ConnectedSince) >= statsWarmup {
			e.latency = rtt
		}
		if tunnelReady && path != pathDown && (route || path == pathWorking || e.standby) {
			e.setState(StateConnected, "")
		}
		e.mu.Unlock()
		e.saveSession(s)
		if path == pathDown {
			e.handlePathFailure(ctx, s)
			return e.o.RetryEvery
		}
		if !tunnelReady || !route {
			return e.o.RetryEvery
		}
		return e.heartbeatEvery(s)
	case clientapi.IsReauth(err):
		e.o.Log.Info("server ended the session", "err", err)
		e.teardown("Your session ended. Sign in again to reconnect.")
		return 30 * time.Second
	}

	if path == pathUnknown {
		path = e.checkTunnelPath(ctx, s, 1)
	}
	if path == pathWorking {
		e.mu.Lock()
		if e.netChangedAt.Equal(changedAt) {
			e.netKick, e.netChangedAt = false, time.Time{}
		}
		e.mu.Unlock()
		expiry := s.Placement.ExpiresAt
		if expiry.IsZero() {
			expiry = s.LastOK.Add(e.grace(s))
		}
		if !now.Before(expiry) {
			e.teardown("Your session expired. Sign in again to reconnect.")
			return 30 * time.Second
		}
		e.mu.Lock()
		e.setState(StateConnected, "")
		e.mu.Unlock()
		return e.o.RetryEvery
	}

	// An older gateway may not advertise an inside probe address.
	if route && path == pathUnknown && roaming && !e.standby && !s.Device {
		e.mu.Lock()
		if e.netChangedAt.Equal(changedAt) {
			e.netKick = false
		}
		e.mu.Unlock()
		e.repairTunnel(s)
		return time.Second
	}

	// Network trouble: ride it out within the grace window.
	down := now.Sub(s.LastOK)
	if down > e.grace(s) {
		e.o.Log.Info("grace window ran out", "offline_for", down.Round(time.Second))
		e.teardown("Your connection was down for more than 15 minutes. Sign in again to reconnect.")
		return 30 * time.Second
	}
	e.mu.Lock()
	// Only show "Reconnecting" once contact has been lost for a while: one
	// slow or failed check (e.g. while routes settle) isn't worth alarming anyone.
	// After a network change, say so (it's expected) and show it right away.
	switching := !e.netChangedAt.IsZero() && now.Sub(e.netChangedAt) < time.Minute
	if e.sess == s && switching {
		e.setState(StateReconnecting, "Connecting…")
	} else if e.sess == s && down >= e.o.ReconnectingAfter {
		e.setState(StateReconnecting, "")
	}
	tryRecovery := route && path == pathUnknown && down >= e.o.FailoverAfter && now.Sub(e.lastRecover) >= e.o.FailoverAfter
	// Network changed, the quick tunnel restart didn't help: rebuild now
	// (another gateway and tunnel IP if need be) instead of waiting.
	if route && path == pathUnknown && switching && now.Sub(e.netChangedAt) >= netRebuildAfter && e.lastRecover.Before(e.netChangedAt) {
		tryRecovery = true
	}
	if tryRecovery {
		e.lastRecover = now
	}
	e.mu.Unlock()
	if route && path == pathDown {
		e.handlePathFailure(ctx, s)
	} else if tryRecovery {
		e.recover(ctx, s)
	}
	return e.o.RetryEvery
}

// recover runs when heartbeats through the tunnel have failed for a while. It
// stops the tunnel (and its kill switch) to reach the control server
// directly: if the server answers, the gateway is the problem, so the session
// moves to another gateway; if it doesn't, the network is down, so the tunnel
// goes back up and the agent keeps waiting.
func (e *Engine) recover(ctx context.Context, s *Session) {
	e.mu.Lock()
	api := e.api
	e.mu.Unlock()
	e.setVPNPhase(vpnChecking)
	e.o.Log.Warn("gateway not answering; checking the control server directly", "gateway", s.Placement.Gateway.ID)
	if err := e.tunnelDown(); err != nil {
		e.o.Log.Warn("couldn't stop tunnel for direct recovery check", "err", err)
		e.setVPNPhase(vpnRepairing)
		return
	}
	e.tunnelPending = true
	restore := func() { e.repairTunnel(s) }

	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	observed, rtt, sent, err := e.heartbeat(hctx, api, s, nil)
	cancel()
	if !clientapi.IsReauth(err) {
		e.mu.Lock()
		e.recordControlCheck(e.o.Now(), rtt, err)
		e.mu.Unlock()
	}
	switch {
	case clientapi.IsReauth(err):
		e.teardown("Your session ended. Sign in again to reconnect.")
		return
	case err != nil:
		e.o.Log.Info("control server unreachable too; the network is down, waiting", "err", err)
		restore()
		return
	}

	// Direct contact proves the session can still resume. Tunnel readiness
	// is checked separately when the assignment is running again.
	e.mu.Lock()
	s.LastOK = e.o.Now()
	e.lastHB, e.ctrlRTT = s.LastOK, rtt
	if !observed.ExpiresAt.IsZero() {
		s.Placement.ExpiresAt = observed.ExpiresAt
	}
	e.mu.Unlock()
	e.acceptCommands(s, observed.Commands, sent)
	if e.updatePlacement(s, observed) {
		// The server already moved this session, possibly in a request whose
		// reply was lost. Apply that assignment before requesting another move.
		e.applyMove(s, observed)
		return
	}

	e.setVPNPhase(vpnSwitchingGateway)
	fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	p, err := api.Failover(fctx, s.ID, s.ResumeToken, s.BootID)
	cancel()
	switch {
	case clientapi.IsReauth(err):
		e.teardown("Your session ended. Sign in again to reconnect.")
		return
	case err != nil:
		e.o.Log.Warn("failover not possible; retrying the same gateway", "err", err)
		restore()
		return
	}
	e.applyMove(s, p)
	e.o.Log.Warn("failed over to another gateway", "gateway", p.Gateway.ID, "tunnel_ip", p.Tunnel.Address)
}

// updatePlacement remembers what the control server assigned, even if local
// application has to be retried. Older responses may omit the tunnel fields.
func (e *Engine) updatePlacement(s *Session, p clientapi.Placement) bool {
	if p.Gateway.ID == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	oldConfig := tunnelConfig(s.PrivateKey, s.Placement).WGQuick()
	if old := s.Placement.Gateway; old.ID != p.Gateway.ID || old.InsideIP != p.Gateway.InsideIP {
		e.pingHist, e.pingTimes = nil, nil
	}
	s.Placement.Gateway = p.Gateway
	s.Placement.Alternates = p.Alternates
	s.Placement.SpeedTest = p.SpeedTest
	s.Placement.OfficeNetworks = p.OfficeNetworks
	if p.Tunnel.Address != "" {
		s.Placement.Tunnel = p.Tunnel
	}
	changed := oldConfig != tunnelConfig(s.PrivateKey, s.Placement).WGQuick()
	if changed {
		e.resetPath()
	}
	e.tunnelPending = e.tunnelPending || changed
	return changed
}

func (e *Engine) ensureTunnel(s *Session) bool {
	if e.standby {
		if !e.o.Tunnel.Running() {
			return true
		}
		if err := e.tunnelDown(); err != nil {
			e.o.Log.Error("stop tunnel for office mode", "err", err)
		}
		return !e.o.Tunnel.Running()
	}
	if !e.tunnelPending && e.o.Tunnel.Running() {
		return true
	}
	e.tunnelPending = true
	if err := e.tunnelUp(tunnelConfig(s.PrivateKey, s.Placement)); err != nil {
		e.mu.Lock()
		e.setState(StateReconnecting, "Starting the tunnel…")
		e.mu.Unlock()
		e.o.Log.Error("start required tunnel configuration", "err", err)
		return false
	}
	e.tunnelPending = false
	return true
}

func (e *Engine) applyMove(s *Session, p clientapi.Placement) {
	e.updatePlacement(s, p)
	ready := e.ensureTunnel(s)
	e.mu.Lock()
	s.LastOK = e.o.Now()
	e.lastHB = s.LastOK
	if ready {
		e.setState(StateConnected, "")
	}
	e.mu.Unlock()
	e.saveSession(s)
}

func (e *Engine) saveSession(s *Session) {
	e.mu.Lock()
	s.TunnelPending = e.tunnelPending
	e.mu.Unlock()
	if err := e.o.Store.Save(s); err != nil {
		e.o.Log.Warn("save session", "err", err)
	}
}

func (e *Engine) heartbeat(ctx context.Context, api API, s *Session, diag *clientapi.Diagnostics) (clientapi.Placement, time.Duration, []string, error) {
	modern, ok := api.(interface {
		HeartbeatWithCommandAcks(context.Context, string, string, string, *clientapi.Diagnostics, []string) (clientapi.Placement, time.Duration, error)
	})
	if !ok {
		p, rtt, err := api.Heartbeat(ctx, s.ID, s.ResumeToken, s.BootID, diag)
		return p, rtt, nil, err
	}
	var ids []string
	e.mu.Lock()
	if e.commandSession == s {
		for id, done := range e.commandAcks {
			if done {
				ids = append(ids, id)
			}
		}
	}
	e.mu.Unlock()
	p, rtt, err := modern.HeartbeatWithCommandAcks(ctx, s.ID, s.ResumeToken, s.BootID, diag, ids)
	return p, rtt, ids, err
}

func (e *Engine) acceptCommands(s *Session, commands []clientapi.Command, sent []string) {
	if e.o.OnCommands == nil {
		return
	}
	e.mu.Lock()
	if e.commandSession != s {
		e.commandSession = s
		e.commandAcks = make(map[string]bool)
	}
	for _, id := range sent {
		delete(e.commandAcks, id)
	}
	var fresh []clientapi.Command
	for _, c := range commands {
		if _, seen := e.commandAcks[c.ID]; c.ID != "" && seen {
			continue
		}
		if c.ID != "" {
			e.commandAcks[c.ID] = false
		}
		fresh = append(fresh, c)
	}
	e.mu.Unlock()
	if len(fresh) == 0 {
		return
	}
	go func() {
		e.o.OnCommands(fresh)
		e.mu.Lock()
		if e.sess == s && e.commandSession == s {
			for _, c := range fresh {
				if c.ID != "" {
					e.commandAcks[c.ID] = true
				}
			}
		}
		e.mu.Unlock()
		e.Kick()
	}()
}

// friendly turns an error into a sentence for the GUI.
func friendly(err error) string {
	var ae *clientapi.APIError
	if errors.As(err, &ae) {
		switch ae.Code {
		case "bad_credentials":
			return "Wrong username or password."
		case "bad_code":
			return "That authenticator code didn't work. Try the next one."
		case "locked":
			return "Too many failed attempts. Wait 15 minutes and try again."
		case "mfa_not_enrolled":
			return "Your account needs an authenticator app set up. Ask IT."
		case "no_gateway":
			return "No VPN gateway is available right now. Try again in a minute."
		case "country_blocked", "device_pending", "device_blocked", "device_untrusted",
			"duo_denied", "duo_unavailable", "signin_method_blocked", "policy_error":
			return ae.Message
		}
		return ae.Error()
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "certificate changed"):
		return "The server's identity changed since this PC first connected. Contact IT before connecting."
	case strings.Contains(msg, "no such host"):
		return "Can't find the server. Check your internet connection."
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "refused"), strings.Contains(msg, "unreachable"):
		return "Can't reach the server. Check your internet connection."
	}
	return "Couldn't connect: " + msg
}

// Friendly is exported for the service's IPC layer.
func Friendly(err error) string { return friendly(err) }
