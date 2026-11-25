package agentcore

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"securetunnel/server/internal/clientapi"
)

// ---- fakes ----

var errNet = errors.New("dial tcp: i/o timeout")

type fakeAPI struct {
	mu          sync.Mutex
	needCode    bool
	connects    int
	gw          string
	hbErr       func(tunnelUp bool) error // nil: success
	failoverErr error
	failovers   int
	disconnects int
	tun         *fakeTunnel
	lastDiag    *clientapi.Diagnostics
	cmds        []clientapi.Command
}

func placement(gw string) clientapi.Placement {
	var p clientapi.Placement
	p.SessionID, p.ResumeToken = "sess-1", "resume-1"
	p.Tunnel.Address = "10.200.0.2/32"
	p.Tunnel.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	p.Gateway = clientapi.Gateway{ID: gw, Endpoint: gw + ".example.com:51820", PublicKey: "pk-" + gw}
	p.HeartbeatSeconds, p.GraceSeconds = 30, 900
	p.ExpiresAt = time.Date(2026, 11, 22, 21, 0, 0, 0, time.UTC)
	return p
}

func (f *fakeAPI) LocalLogin(_ context.Context, user, pw, code string) (string, error) {
	if pw != "right-password" {
		return "", &clientapi.APIError{Status: 401, Code: "bad_credentials", Message: "wrong username or password"}
	}
	if f.needCode && code == "" {
		return "", &clientapi.APIError{Status: 401, Code: "code_required", Message: "authenticator code required"}
	}
	return "token", nil
}

func (f *fakeAPI) Connect(context.Context, string, clientapi.ConnectRequest) (clientapi.Placement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connects++
	f.gw = "gw-a"
	return placement("gw-a"), nil
}

func (f *fakeAPI) Heartbeat(_ context.Context, _, _, _ string, d *clientapi.Diagnostics) (clientapi.Placement, time.Duration, error) {
	f.mu.Lock()
	f.lastDiag = d
	f.mu.Unlock()
	f.mu.Lock()
	fn, gw := f.hbErr, f.gw
	f.mu.Unlock()
	if fn != nil {
		if err := fn(f.tun.Running()); err != nil {
			return clientapi.Placement{}, 0, err
		}
	}
	p := placement(gw)
	f.mu.Lock()
	p.Commands, f.cmds = f.cmds, nil
	f.mu.Unlock()
	return p, 20 * time.Millisecond, nil
}

func (f *fakeAPI) Failover(context.Context, string, string, string) (clientapi.Placement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failovers++
	if f.failoverErr != nil {
		return clientapi.Placement{}, f.failoverErr
	}
	f.gw = "gw-b"
	p := placement("gw-b")
	p.Tunnel.Address = "10.200.8.2/32"
	return p, nil
}

func (f *fakeAPI) Disconnect(context.Context, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnects++
	return nil
}

func (f *fakeAPI) Watch(context.Context, string, string) (bool, error) { return false, nil }

type fakeTunnel struct {
	mu   sync.Mutex
	up   bool
	cfg  TunnelConfig
	ups  int
	fail error
}

func (t *fakeTunnel) Up(c TunnelConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fail != nil {
		return t.fail
	}
	t.up, t.cfg = true, c
	t.ups++
	return nil
}
func (t *fakeTunnel) Down() error { t.mu.Lock(); defer t.mu.Unlock(); t.up = false; return nil }
func (t *fakeTunnel) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.up
}

type memStore struct {
	mu sync.Mutex
	s  *Session
}

func (m *memStore) Load() (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.s == nil {
		return nil, nil
	}
	c := *m.s
	return &c, nil
}
func (m *memStore) Save(s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *s
	m.s = &c
	return nil
}
func (m *memStore) Clear() error { m.mu.Lock(); defer m.mu.Unlock(); m.s = nil; return nil }

type rig struct {
	e     *Engine
	api   *fakeAPI
	tun   *fakeTunnel
	store *memStore
	now   time.Time
	boot  string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{tun: &fakeTunnel{}, store: &memStore{}, now: time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC), boot: "boot-1"}
	r.api = &fakeAPI{tun: r.tun}
	r.e = New(Options{
		NewAPI:   func(string) API { return r.api },
		Tunnel:   r.tun,
		Store:    r.store,
		BootID:   func() string { return r.boot },
		DeviceID: "PC-1",
		KeyGen:   func() (string, string, error) { return "priv", "pub", nil },
		Now:      func() time.Time { return r.now },
	})
	if err := r.e.SetServer("https://vpn.example.com", false); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) connect(t *testing.T) {
	t.Helper()
	if err := r.e.Connect(context.Background(), "TestUser", "right-password", ""); err != nil {
		t.Fatalf("connect: %v", err)
	}
}

func (r *rig) advance(d time.Duration) { r.now = r.now.Add(d) }

// ---- tests ----

func TestConnectBringsTunnelUp(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	st := r.e.Status()
	if st.State != StateConnected || st.User != "testuser" || st.TunnelIP != "10.200.0.2" || st.Gateway != "gw-a" {
		t.Fatalf("status = %+v", st)
	}
	if !r.tun.Running() || r.tun.cfg.Endpoint != "gw-a.example.com:51820" || r.tun.cfg.PrivateKey != "priv" {
		t.Fatalf("tunnel = %+v", r.tun.cfg)
	}
	if !strings.Contains(r.tun.cfg.WGQuick(), "AllowedIPs = 0.0.0.0/0, ::/0") {
		t.Error("config is not full tunnel")
	}
	if s, _ := r.store.Load(); s == nil || s.ID != "sess-1" {
		t.Error("session not persisted")
	}
}

func TestWrongPasswordAndCodeRequired(t *testing.T) {
	r := newRig(t)
	err := r.e.Connect(context.Background(), "u", "nope", "")
	if !clientapi.HasCode(err, "bad_credentials") || r.e.Status().Message != "Wrong username or password." {
		t.Fatalf("err=%v status=%+v", err, r.e.Status())
	}
	r.api.needCode = true
	err = r.e.Connect(context.Background(), "u", "right-password", "")
	if !clientapi.HasCode(err, "code_required") || r.e.Status().State != StateDisconnected {
		t.Fatalf("err=%v state=%s", err, r.e.Status().State)
	}
	if err := r.e.Connect(context.Background(), "u", "right-password", "123456"); err != nil {
		t.Fatalf("with code: %v", err)
	}
}

func TestShortOutageResumesWithoutSignIn(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.api.hbErr = func(bool) error { return errNet }
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	if st := r.e.Status(); st.State != StateReconnecting || st.GraceLeftSec < 800 {
		t.Fatalf("during outage: %+v", st)
	}
	r.api.hbErr = nil
	r.advance(20 * time.Second)
	r.e.Tick(context.Background())
	if st := r.e.Status(); st.State != StateConnected {
		t.Fatalf("after outage: %+v", st)
	}
	if r.api.connects != 1 {
		t.Errorf("connects = %d, want 1 (no new sign-in)", r.api.connects)
	}
}

func TestGatewayFailureFailsOver(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	// Through the tunnel nothing works; direct (tunnel down) the server answers.
	r.api.hbErr = func(tunnelUp bool) error {
		if tunnelUp {
			return errNet
		}
		return nil
	}
	r.advance(70 * time.Second)
	r.e.Tick(context.Background())
	if r.api.failovers != 1 {
		t.Fatalf("failovers = %d, want 1", r.api.failovers)
	}
	st := r.e.Status()
	if st.State != StateConnected || st.Gateway != "gw-b" || st.TunnelIP != "10.200.8.2" {
		t.Fatalf("after failover: %+v", st)
	}
	if !r.tun.Running() || r.tun.cfg.Endpoint != "gw-b.example.com:51820" || r.tun.cfg.Address != "10.200.8.2/32" {
		t.Fatalf("tunnel not moved to new gateway: %+v", r.tun.cfg)
	}
}

func TestNetworkDownKeepsTunnelAndWaits(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.api.hbErr = func(bool) error { return errNet } // nothing reachable at all
	r.advance(70 * time.Second)
	r.e.Tick(context.Background())
	if r.api.failovers != 0 {
		t.Errorf("failed over while the whole network was down")
	}
	if !r.tun.Running() {
		t.Error("tunnel (and kill switch) not restored after the direct check")
	}
	if r.e.Status().State != StateReconnecting {
		t.Errorf("state = %s", r.e.Status().State)
	}
}

func TestGraceExpiryRequiresSignIn(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.api.hbErr = func(bool) error { return errNet }
	r.advance(16 * time.Minute)
	r.e.Tick(context.Background())
	st := r.e.Status()
	if st.State != StateDisconnected || !strings.Contains(st.Message, "15 minutes") || r.tun.Running() {
		t.Fatalf("after grace: %+v tunnel=%v", st, r.tun.Running())
	}
	if s, _ := r.store.Load(); s != nil {
		t.Error("expired session still persisted")
	}
}

func TestServerEndsSession(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.api.hbErr = func(bool) error {
		return &clientapi.APIError{Status: 401, Code: "reauth_required", Message: "session ended"}
	}
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	if st := r.e.Status(); st.State != StateDisconnected || r.tun.Running() {
		t.Fatalf("after admin disconnect: %+v", st)
	}
}

func TestUserDisconnect(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	if err := r.e.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.api.disconnects != 1 || r.tun.Running() || r.e.Status().State != StateDisconnected {
		t.Fatalf("disconnects=%d tunnel=%v state=%s", r.api.disconnects, r.tun.Running(), r.e.Status().State)
	}
}

func TestRestoreAfterServiceRestart(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	saved := r.store
	tun := r.tun

	// New engine (service restarted), same boot, tunnel still running.
	r2 := newRig(t)
	r2.store, r2.tun = saved, tun
	r2.api.tun = tun
	r2.e.o.Store, r2.e.o.Tunnel = saved, tun
	ups := tun.ups
	r2.e.Restore()
	if tun.ups != ups {
		t.Error("restore restarted a tunnel that was already running")
	}
	r2.api.gw = "gw-a"
	r2.e.Tick(context.Background())
	if st := r2.e.Status(); st.State != StateConnected || st.User != "testuser" {
		t.Fatalf("after restore: %+v", st)
	}
}

func TestRestoreAfterRebootDiscards(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.boot = "boot-2" // rebooted
	r.e.sess = nil
	r.e.Restore()
	if st := r.e.Status(); st.State != StateDisconnected || r.tun.Running() {
		t.Fatalf("after reboot: %+v tunnel=%v", st, r.tun.Running())
	}
	if s, _ := r.store.Load(); s != nil {
		t.Error("pre-reboot session kept")
	}
}

func TestTunnelFailureCleansUp(t *testing.T) {
	r := newRig(t)
	r.tun.fail = errors.New("driver missing")
	if err := r.e.Connect(context.Background(), "u", "right-password", ""); err == nil {
		t.Fatal("connect succeeded with a broken tunnel")
	}
	if r.api.disconnects != 1 {
		t.Error("server session not closed after tunnel failure")
	}
	if st := r.e.Status(); st.State != StateDisconnected || !strings.Contains(st.Message, "driver missing") {
		t.Errorf("status = %+v", st)
	}
}

func TestOfficeNetworkConnectsOnStandby(t *testing.T) {
	r := newRig(t)
	r.e.o.TrustedProbe = func(context.Context) (bool, string) { return true, "DNS suffix cb-sisco.com" }
	r.e.Tick(context.Background())
	if !r.e.Status().OnTrustedNetwork {
		t.Fatal("trusted network not detected")
	}
	if err := r.e.Connect(context.Background(), "u", "right-password", ""); err != nil {
		t.Fatalf("connect in the office: %v", err)
	}
	st := r.e.Status()
	if st.State != StateConnected || !st.OfficeMode || r.tun.Running() {
		t.Errorf("in the office: state=%s office_mode=%v tunnel=%v, want connected, office mode, tunnel down", st.State, st.OfficeMode, r.tun.Running())
	}
}

func TestOneFailedCheckDoesNotShowReconnecting(t *testing.T) {
	r := newRig(t)
	r.e.o.ReconnectingAfter = 45 * time.Second
	r.connect(t)
	r.api.hbErr = func(bool) error { return errNet }
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	if st := r.e.Status(); st.State != StateConnected {
		t.Fatalf("one failed check showed %s, want still connected", st.State)
	}
	r.advance(20 * time.Second)
	r.e.Tick(context.Background())
	if st := r.e.Status(); st.State != StateReconnecting {
		t.Fatalf("after 50 s without contact: %s, want reconnecting", st.State)
	}
}

func TestNoEarlyHeartbeatAfterConnect(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	calls := 0
	r.api.hbErr = func(bool) error { calls++; return errNet }
	r.advance(2 * time.Second)
	if wait := r.e.Tick(context.Background()); calls != 0 || wait != 28*time.Second {
		t.Fatalf("heartbeat sent %d times right after connecting; wait=%s, want 28s", calls, wait)
	}
}

func TestWatchSignalTearsDownImmediately(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.api.hbErr = func(bool) error {
		return &clientapi.APIError{Status: 401, Code: "reauth_required", Message: "session ended"}
	}
	r.advance(3 * time.Second) // well before the next scheduled heartbeat
	r.e.mu.Lock()
	r.e.forceHB = true // what watchLoop sets when the server signals the end
	r.e.mu.Unlock()
	r.e.Tick(context.Background())
	if st := r.e.Status(); st.State != StateDisconnected || r.tun.Running() {
		t.Fatalf("after admin disconnect signal: %+v tunnel=%v", st, r.tun.Running())
	}
}

func TestQualityStats(t *testing.T) {
	jitter, loss := quality([]int{20, 30, -1, 25, 25})
	if jitter != 5 || loss != 20 {
		t.Errorf("jitter=%d loss=%v, want 5 and 20", jitter, loss)
	}
}

func TestTrafficRates(t *testing.T) {
	r := newRig(t)
	var rx, tx uint64
	r.e.o.TrafficStats = func() (uint64, uint64, bool) { return rx, tx, true }
	r.connect(t)
	r.e.Status() // first sample
	rx, tx = 1_000_000, 250_000
	r.advance(2 * time.Second)
	st := r.e.Status()
	if st.RxBps != 4_000_000 || st.TxBps != 1_000_000 || len(st.RateHistory) != 1 {
		t.Fatalf("rx=%v tx=%v hist=%d, want 4 Mbps / 1 Mbps / 1 point", st.RxBps, st.TxBps, len(st.RateHistory))
	}
}

func TestArrivingAtOfficeGoesOnStandby(t *testing.T) {
	r := newRig(t)
	office := false
	r.e.o.TrustedProbe = func(context.Context) (bool, string) {
		if office {
			return true, "DNS suffix cb-sisco.com"
		}
		return false, ""
	}
	r.connect(t)
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	if r.e.Status().State != StateConnected {
		t.Fatal("disconnected while away from the office")
	}
	office = true // laptop plugged in at the office
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	st := r.e.Status()
	if st.State != StateConnected || !st.OfficeMode || r.tun.Running() || r.api.disconnects != 0 {
		t.Fatalf("at the office: state=%s office_mode=%v tunnel=%v disconnects=%d", st.State, st.OfficeMode, r.tun.Running(), r.api.disconnects)
	}
	if !st.OnTrustedNetwork || !strings.Contains(st.TrustedReason, "cb-sisco.com") {
		t.Errorf("status = %+v", st)
	}
	office = false // laptop goes home
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	st = r.e.Status()
	if st.State != StateConnected || st.OfficeMode || !r.tun.Running() {
		t.Fatalf("left the office: state=%s office_mode=%v tunnel=%v", st.State, st.OfficeMode, r.tun.Running())
	}
}

func TestCommandsDelivered(t *testing.T) {
	r := newRig(t)
	got := make(chan []clientapi.Command, 1)
	r.e.o.OnCommands = func(c []clientapi.Command) { got <- c }
	r.connect(t)
	r.api.cmds = []clientapi.Command{{ID: "c1", Type: "message", Text: "IT is checking your connection", From: "helpdesk1"}}
	r.e.Kick() // what the watch does when the server says commands are waiting
	r.e.Tick(context.Background())
	select {
	case c := <-got:
		if len(c) != 1 || c[0].Type != "message" || c[0].From != "helpdesk1" {
			t.Fatalf("commands = %+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("commands not handed to OnCommands")
	}
}

func TestHeartbeatCarriesDiagnostics(t *testing.T) {
	r := newRig(t)
	r.e.o.Version = "1.2.3"
	r.e.o.NetworkInfo = func() NetInfo { return NetInfo{Adapter: "Wi-Fi", Kind: "Wi-Fi", SSID: "HomeNet", SignalPct: 80} }
	r.e.o.DiagExtra = func(d *clientapi.Diagnostics) { d.OS = "Windows 11"; d.ISPIP = "47.32.2.7" }
	r.connect(t)
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	d := r.api.lastDiag
	if d == nil || d.SSID != "HomeNet" || d.OS != "Windows 11" || d.ISPIP != "47.32.2.7" || d.AgentVersion != "1.2.3" {
		t.Fatalf("diagnostics = %+v", d)
	}
}

func TestServerLockedByPolicy(t *testing.T) {
	r := newRig(t)
	if err := r.e.SetServer("https://policy.example.com", true); err != nil {
		t.Fatal(err)
	}
	if err := r.e.SetServer("https://other.example.com", false); err == nil {
		t.Error("user changed a policy-locked server")
	}
}

func TestNetworkChangeRechecksOnceSettled(t *testing.T) {
	r := newRig(t)
	net := "10.0.0.5|home.lan"
	rechecked := make(chan struct{}, 4)
	r.e.o.NetFingerprint = func() string { return net }
	r.e.o.OnNetworkChange = func(context.Context, State) { rechecked <- struct{}{} }
	last, changed := r.e.o.NetFingerprint(), time.Time{}
	now := time.Now()
	if r.e.netCheck(context.Background(), &last, &changed, now) {
		t.Fatal("recheck with no change")
	}
	net = "10.20.4.7|hq.cb-sisco.com" // docked at the office
	r.e.netCheck(context.Background(), &last, &changed, now)
	if r.e.netCheck(context.Background(), &last, &changed, now.Add(time.Second)) {
		t.Fatal("rechecked before the network settled")
	}
	if !r.e.netCheck(context.Background(), &last, &changed, now.Add(4*time.Second)) {
		t.Fatal("no recheck after settling")
	}
	select {
	case <-rechecked:
	case <-time.After(2 * time.Second):
		t.Fatal("public IP not rechecked")
	}
	if r.e.netCheck(context.Background(), &last, &changed, now.Add(8*time.Second)) {
		t.Fatal("rechecked again with no new change")
	}
}

func TestFailedHeartbeatAfterNetworkChangeRestartsTunnel(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	ups := r.tun.ups
	r.api.hbErr = func(bool) error { return errors.New("network unreachable") }
	r.e.mu.Lock()
	r.e.netKick = true // as after a network change
	r.e.mu.Unlock()
	r.advance(5 * time.Second)
	r.e.Kick()
	r.e.Tick(context.Background())
	if r.tun.ups != ups+1 || !r.tun.Running() {
		t.Fatalf("tunnel not restarted at once (ups %d → %d)", ups, r.tun.ups)
	}
	r.advance(5 * time.Second)
	r.e.Kick()
	r.e.Tick(context.Background())
	if r.tun.ups != ups+1 {
		t.Error("restarted again: only the first failure after a network change should")
	}
}

func TestNetworkChangeRebuildsOnNewGatewaySoon(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	// The gateway can't be reached from the new network; the control server can.
	r.api.hbErr = func(tunnelUp bool) error {
		if tunnelUp {
			return errors.New("timeout")
		}
		return nil
	}
	r.e.mu.Lock()
	r.e.netKick, r.e.netChangedAt = true, r.e.o.Now()
	r.e.mu.Unlock()
	r.advance(time.Second)
	r.e.Kick()
	r.e.Tick(context.Background()) // quick tunnel restart
	if st := r.e.Status(); r.api.failovers != 0 {
		t.Fatalf("failed over too early: %+v", st)
	}
	r.advance(4 * time.Second)
	r.e.Kick()
	r.e.Tick(context.Background())
	if st := r.e.Status(); st.State != StateReconnecting || st.Message != "Connecting…" {
		t.Errorf("status = %s %q, want reconnecting with 'Connecting…'", st.State, st.Message)
	}
	r.advance(6 * time.Second) // 11 s after the change
	r.e.Kick()
	r.e.Tick(context.Background())
	if r.api.failovers != 1 {
		t.Fatalf("not rebuilt on another gateway ~10 s after the network change (failovers=%d)", r.api.failovers)
	}
}

func TestOfficeExitRetriesFailedTunnelStart(t *testing.T) {
	r := newRig(t)
	office := true
	r.e.o.TrustedProbe = func(context.Context) (bool, string) { return office, "" }
	ctx := context.Background()
	r.e.Tick(ctx)
	r.connect(t)

	office = false
	r.tun.fail = errors.New("temporary service startup failure")
	r.advance(30 * time.Second)
	r.e.Tick(ctx)
	if st := r.e.Status(); st.State != StateReconnecting || r.tun.Running() {
		t.Fatalf("failed tunnel restart: state %s, running %v", st.State, r.tun.Running())
	}

	r.tun.fail = nil
	r.advance(5 * time.Second)
	r.e.Tick(ctx)
	if st := r.e.Status(); st.State != StateConnected || !r.tun.Running() {
		t.Fatalf("tunnel retry: state %s, running %v", st.State, r.tun.Running())
	}
}

func TestHeartbeatAppliesMoveWhoseReplyWasLost(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.api.gw = "gw-b"
	r.advance(30 * time.Second)
	r.e.Tick(context.Background())
	if got := r.tun.cfg.Endpoint; got != "gw-b.example.com:51820" {
		t.Fatalf("heartbeat left tunnel on %s", got)
	}
}

func TestOldHeartbeatCannotTearDownReplacement(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.api.hbErr = func(bool) error {
		close(started)
		<-release
		return &clientapi.APIError{Status: 401, Code: "reauth_required"}
	}
	ctx := context.Background()
	r.advance(30 * time.Second)
	go func() {
		defer close(done)
		r.e.Tick(ctx)
	}()
	<-started
	err := r.e.Disconnect(ctx)
	if err == nil {
		err = r.e.Connect(ctx, "TestUser", "right-password", "")
	}
	close(release)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	if st := r.e.Status(); st.State != StateConnected || !r.tun.Running() {
		t.Fatalf("old heartbeat changed replacement: state %s, running %v", st.State, r.tun.Running())
	}
}

func TestRoamingKeepsWorkingTunnelWhenHeartbeatFails(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.e.sess.Placement.Gateway.InsideIP = "10.200.0.1"
	var probePhase string
	r.e.o.Ping = func(_ context.Context, source, ip netip.Addr, _ time.Duration) (time.Duration, error) {
		probePhase = r.e.Status().VPNPhase
		if source.String() != "10.200.0.2" || ip.String() != "10.200.0.1" {
			t.Errorf("unexpected probe: %s to %s", source, ip)
		}
		return 20 * time.Millisecond, nil
	}
	r.api.hbErr = func(bool) error { return errors.New("control server down") }
	r.e.netKick = true
	ups := r.tun.ups
	r.advance(16 * time.Minute)
	r.e.Kick()
	r.e.Tick(context.Background())
	if probePhase != vpnChecking || r.e.Status().VPNPhase != "" {
		t.Fatalf("banner phase while probing = %q, after reply = %q", probePhase, r.e.Status().VPNPhase)
	}
	if r.e.Status().State != StateConnected || r.tun.ups != ups || r.api.failovers != 0 {
		t.Fatal("a working tunnel was disrupted after a missed heartbeat")
	}

	r.now = r.e.sess.Placement.ExpiresAt
	r.e.Kick()
	r.e.Tick(context.Background())
	if r.e.Status().State != StateDisconnected || r.tun.Running() {
		t.Fatal("a working tunnel survived the absolute session expiry")
	}
}

func TestRoamingWaitsForRouteAndRepairsSameAssignment(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.e.sess.Placement.Gateway.InsideIP = "10.200.0.1"
	routeAvailable := false
	r.e.o.PhysicalRouteAvailable = func() (bool, bool) { return routeAvailable, true }
	r.e.o.Ping = func(context.Context, netip.Addr, netip.Addr, time.Duration) (time.Duration, error) {
		return 0, errors.New("no probe reply")
	}
	r.api.hbErr = func(bool) error { return errors.New("control server unreachable") }
	r.e.netKick = true
	ups, original := r.tun.ups, r.tun.cfg.WGQuick()
	r.advance(5 * time.Second)
	r.e.Kick()
	r.e.Tick(context.Background())
	if r.e.Status().VPNPhase != vpnWaitingForNetwork {
		t.Fatalf("banner phase without physical route = %q", r.e.Status().VPNPhase)
	}
	if r.tun.ups != ups || r.api.failovers != 0 {
		t.Fatal("changed the tunnel before a physical route was available")
	}

	routeAvailable = true
	r.advance(5 * time.Second)
	r.e.Kick()
	r.e.Tick(context.Background())
	if r.tun.ups != ups+1 || r.tun.cfg.WGQuick() != original || r.api.failovers != 0 {
		t.Fatal("roaming repair did not preserve the existing assignment")
	}
}

func TestPathDetectionRequiresConsecutiveMissesAfterFirstReply(t *testing.T) {
	e := newRig(t).e
	for i := 0; i < pathFailureThreshold*2; i++ {
		if e.observePath(false) {
			t.Fatal("an unconfirmed ICMP target triggered recovery")
		}
	}
	e.observePath(true)
	for i := 1; i < pathFailureThreshold; i++ {
		if e.observePath(false) {
			t.Fatal("started recovery early")
		}
	}
	e.observePath(true)
	if e.observePath(false) {
		t.Fatal("a successful reply did not reset the failure streak")
	}
	for i := 2; i < pathFailureThreshold; i++ {
		e.observePath(false)
	}
	if !e.observePath(false) || e.observePath(false) {
		t.Fatal("the threshold should trigger recovery exactly once per failure streak")
	}
}

func TestRoamingTriesLocalRepairBeforeMovingGateway(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.e.sess.Placement.Gateway.InsideIP = "10.200.0.1"
	r.e.sess.Placement.Alternates = []clientapi.Gateway{{ID: "gw-b"}}
	r.e.o.Ping = func(context.Context, netip.Addr, netip.Addr, time.Duration) (time.Duration, error) {
		return 0, errors.New("no probe reply")
	}
	r.api.hbErr = func(tunnelUp bool) error {
		if tunnelUp {
			return errors.New("control server unreachable through tunnel")
		}
		return nil
	}
	r.e.netKick = true
	ups := r.tun.ups
	r.advance(5 * time.Second)
	r.e.Kick()
	r.e.Tick(context.Background())
	if r.tun.ups != ups+1 || r.api.failovers != 0 {
		t.Fatal("expected one local repair with no gateway move")
	}
	r.advance(netRebuildAfter)
	r.e.Tick(context.Background())
	if r.api.failovers != 1 || r.e.Status().Gateway != "gw-b" {
		t.Fatal("expected gateway failover after local repair and continued probe loss")
	}
}

func TestStatusReportsGraphAndLossSampleAges(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.e.recordHB(20, r.now.Add(-35*time.Second))
	r.e.recordHB(-1, r.now.Add(-5*time.Second))
	r.e.rateHist = []RatePoint{
		{start: r.now.Add(-12 * time.Second), end: r.now.Add(-11 * time.Second)},
		{start: r.now.Add(-8 * time.Second), end: r.now.Add(-7 * time.Second)},
	}
	st := r.e.Status()
	if st.RateHistorySeconds != 12 || st.RateLatestSeconds != 7 ||
		st.LatencyHistorySeconds != 35 || st.LatencyLatestSeconds != 5 || st.LossWindowSeconds != 35 {
		t.Fatalf("unexpected heartbeat and usage age metadata: %+v", st)
	}

	r.e.o.Ping = func(context.Context, netip.Addr, netip.Addr, time.Duration) (time.Duration, error) {
		return time.Millisecond, nil
	}
	r.e.sess.Placement.Gateway.InsideIP = "10.200.0.1"
	for i := 63; i > 0; i-- {
		r.e.pingHist = append(r.e.pingHist, 20)
		r.e.pingTimes = append(r.e.pingTimes, r.now.Add(-time.Duration(i)*pingEvery))
	}
	st = r.e.Status()
	if st.LatencySource != "gateway" || st.LatencyHistorySeconds != 315 ||
		st.LatencyLatestSeconds != 5 || st.LossWindowSeconds != 305 {
		t.Fatalf("unexpected gateway age metadata: %+v", st)
	}
}

func TestReturningToWiFiGetsNewLocalRepair(t *testing.T) {
	r := newRig(t)
	r.connect(t)
	r.e.sess.Placement.Gateway.InsideIP = "10.200.0.1"
	r.e.o.Ping = func(context.Context, netip.Addr, netip.Addr, time.Duration) (time.Duration, error) {
		return 0, errors.New("gateway unreachable on the new route")
	}
	r.api.hbErr = func(bool) error { return errors.New("control server unreachable") }
	r.e.pathRepairedAt = r.e.o.Now()
	fingerprint := "wifi"
	r.e.o.NetFingerprint = func() string { return fingerprint }
	last, pending := "hotspot", time.Time{}
	ctx := context.Background()
	r.advance(time.Second)
	r.e.netCheck(ctx, &last, &pending, r.now)
	r.advance(netSettle)
	r.e.netCheck(ctx, &last, &pending, r.now)
	ups := r.tun.ups
	r.e.Tick(ctx)
	if r.tun.ups != ups+1 || r.api.failovers != 0 {
		t.Fatal("expected a fresh same-gateway repair on the Wi-Fi route")
	}
}
