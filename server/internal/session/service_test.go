package session

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"securetunnel/server/internal/model"
	"securetunnel/server/internal/store"
)

const testKey = "YAnz2ldbyfkLT6tBkM0OC3m6/NiGdpdvq9eCnsSxk2A=" // any 32 bytes, base64

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func setup(t *testing.T) (*Service, *store.Memory, *clock) {
	t.Helper()
	ctx := context.Background()
	clk := &clock{t: time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)}
	st := store.NewMemory()
	for _, g := range []model.Gateway{
		{ID: "dc-gw1", Site: "dc", Endpoint: "vpn1.example.com:51820", Pool: netip.MustParsePrefix("10.200.0.0/29"), Capacity: 100, Enabled: true},
		{ID: "site2-gw1", Site: "site2", Endpoint: "vpn2.example.com:51820", Pool: netip.MustParsePrefix("10.200.8.0/29"), Capacity: 100, Enabled: true},
	} {
		if err := st.UpsertGateway(ctx, g); err != nil {
			t.Fatal(err)
		}
		if err := st.RecordGatewayHealth(ctx, g.ID, 0, clk.t); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(st, Config{
		Grace:            15 * time.Minute,
		SuspendAfter:     90 * time.Second,
		Heartbeat:        30 * time.Second,
		MaxLifetime:      12 * time.Hour,
		GatewayHealthTTL: 24 * time.Hour, // tests advance the clock a lot
	}, clk.now, nil)
	return svc, st, clk
}

func connect(t *testing.T, svc *Service, device, boot string) Placement {
	t.Helper()
	p, err := svc.Connect(context.Background(),
		model.Identity{UserOID: "oid-1", UPN: "user@example.com", TenantID: "tid"},
		ConnectRequest{WGPublicKey: testKey, DeviceID: device, BootID: boot, Platform: "windows"})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return p
}

func TestConnectAssignsAddressAndGateway(t *testing.T) {
	svc, _, _ := setup(t)
	p := connect(t, svc, "dev-1", "boot-1")
	if p.ResumeToken == "" || p.Session.ID == "" {
		t.Fatal("missing session id or resume token")
	}
	if got := p.Session.TunnelIP.String(); got != "10.200.0.2" {
		t.Errorf("tunnel ip = %s, want 10.200.0.2 (first client address)", got)
	}
	if len(p.Alternates) != 1 || p.Alternates[0].ID == p.Gateway.ID {
		t.Errorf("alternates = %+v, want the other gateway", p.Alternates)
	}
}

func TestResumeWithinGraceNeedsNoMFA(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	p := connect(t, svc, "dev-1", "boot-1")

	clk.add(10 * time.Minute) // network dropped for 10 minutes
	if r, _ := svc.Sweep(ctx); r.Suspended != 1 {
		t.Fatalf("sweep = %+v, want 1 suspended", r)
	}
	got, err := svc.Heartbeat(ctx, p.Session.ID, p.ResumeToken, "boot-1")
	if err != nil {
		t.Fatalf("resume within grace failed: %v", err)
	}
	if got.Session.State != model.StateActive || got.Session.TunnelIP != p.Session.TunnelIP {
		t.Errorf("after resume: state=%s ip=%s, want active and unchanged ip", got.Session.State, got.Session.TunnelIP)
	}
}

func TestResumeAfterGraceRequiresMFA(t *testing.T) {
	svc, _, clk := setup(t)
	p := connect(t, svc, "dev-1", "boot-1")
	clk.add(16 * time.Minute)
	if _, err := svc.Heartbeat(context.Background(), p.Session.ID, p.ResumeToken, "boot-1"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired", err)
	}
}

func TestSweepExpiresAfterGrace(t *testing.T) {
	svc, st, clk := setup(t)
	ctx := context.Background()
	p := connect(t, svc, "dev-1", "boot-1")
	clk.add(15*time.Minute + time.Second)
	if r, _ := svc.Sweep(ctx); r.Expired != 1 {
		t.Fatalf("sweep = %+v, want 1 expired", r)
	}
	peers, _ := st.LivePeers(ctx, p.Gateway.ID)
	if len(peers) != 0 {
		t.Errorf("expired session still listed as a gateway peer")
	}
}

func TestRebootRequiresMFA(t *testing.T) {
	svc, _, clk := setup(t)
	p := connect(t, svc, "dev-1", "boot-1")
	clk.add(2 * time.Minute)
	if _, err := svc.Heartbeat(context.Background(), p.Session.ID, p.ResumeToken, "boot-2"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired after reboot", err)
	}
	// The session must stay ended, even if the old boot ID is presented again.
	if _, err := svc.Heartbeat(context.Background(), p.Session.ID, p.ResumeToken, "boot-1"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("session revived after reboot: %v", err)
	}
}

func TestUserDisconnectRequiresMFA(t *testing.T) {
	svc, _, _ := setup(t)
	ctx := context.Background()
	p := connect(t, svc, "dev-1", "boot-1")
	if err := svc.Disconnect(ctx, p.Session.ID, p.ResumeToken); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Heartbeat(ctx, p.Session.ID, p.ResumeToken, "boot-1"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired after disconnect", err)
	}
}

func TestMaxLifetimeRequiresMFA(t *testing.T) {
	svc, _, clk := setup(t)
	ctx := context.Background()
	p := connect(t, svc, "dev-1", "boot-1")
	for i := 0; i < 12*60; i++ { // stable connection, heartbeating every minute for 12h
		clk.add(time.Minute)
		if _, err := svc.Heartbeat(ctx, p.Session.ID, p.ResumeToken, "boot-1"); err != nil {
			t.Fatalf("heartbeat at minute %d: %v", i+1, err)
		}
	}
	clk.add(time.Minute)
	if _, err := svc.Heartbeat(ctx, p.Session.ID, p.ResumeToken, "boot-1"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired past max lifetime", err)
	}
}

func TestWrongResumeTokenRejected(t *testing.T) {
	svc, _, _ := setup(t)
	p := connect(t, svc, "dev-1", "boot-1")
	if _, err := svc.Heartbeat(context.Background(), p.Session.ID, "not-the-token", "boot-1"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("err = %v, want ErrReauthRequired", err)
	}
}

func TestNewConnectReplacesDeviceSession(t *testing.T) {
	svc, _, _ := setup(t)
	ctx := context.Background()
	old := connect(t, svc, "dev-1", "boot-1")
	_ = connect(t, svc, "dev-1", "boot-1")
	if _, err := svc.Heartbeat(ctx, old.Session.ID, old.ResumeToken, "boot-1"); !errors.Is(err, ErrReauthRequired) {
		t.Fatalf("old session still usable after reconnect: %v", err)
	}
}

func TestFailoverKeepsSessionAndMovesGateway(t *testing.T) {
	svc, _, _ := setup(t)
	ctx := context.Background()
	p := connect(t, svc, "dev-1", "boot-1")
	f, err := svc.Failover(ctx, p.Session.ID, p.ResumeToken, "boot-1")
	if err != nil {
		t.Fatalf("failover: %v", err)
	}
	if f.Gateway.ID == p.Gateway.ID {
		t.Fatalf("failover stayed on %s", p.Gateway.ID)
	}
	if !f.Gateway.Pool.Contains(f.Session.TunnelIP) {
		t.Errorf("new ip %s not in new gateway pool %s", f.Session.TunnelIP, f.Gateway.Pool)
	}
	if _, err := svc.Heartbeat(ctx, p.Session.ID, p.ResumeToken, "boot-1"); err != nil {
		t.Errorf("session not usable after failover: %v", err)
	}
}

func TestUnhealthyGatewaySkipped(t *testing.T) {
	svc, st, clk := setup(t)
	svc.cfg.GatewayHealthTTL = 45 * time.Second
	ctx := context.Background()
	clk.add(time.Minute)
	_ = st.RecordGatewayHealth(ctx, "site2-gw1", 0, clk.t) // only site2 reported recently
	p := connect(t, svc, "dev-1", "boot-1")
	if p.Gateway.ID != "site2-gw1" {
		t.Errorf("placed on %s, want the healthy site2-gw1", p.Gateway.ID)
	}
}

func TestPoolExhaustionSpillsToOtherGateway(t *testing.T) {
	svc, _, _ := setup(t)
	// Each /29 pool has 5 client addresses (.2-.6); 10 devices fill both.
	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		p := connect(t, svc, "dev-"+string(rune('a'+i)), "boot")
		seen[p.Gateway.ID]++
	}
	if seen["dc-gw1"] != 5 || seen["site2-gw1"] != 5 {
		t.Errorf("placement = %v, want 5 on each", seen)
	}
	_, err := svc.Connect(context.Background(), model.Identity{UserOID: "x"},
		ConnectRequest{WGPublicKey: testKey, DeviceID: "dev-z", BootID: "b"})
	if !errors.Is(err, ErrNoGateway) {
		t.Errorf("err = %v, want ErrNoGateway when all pools are full", err)
	}
}

func TestBurstSpreadsAcrossGateways(t *testing.T) {
	// Both gateways last reported 0 peers. Placement must use live session
	// counts, so a burst alternates instead of filling the first gateway.
	svc, _, _ := setup(t)
	seen := map[string]int{}
	for i := 0; i < 6; i++ {
		p := connect(t, svc, "burst-"+string(rune('a'+i)), "boot")
		seen[p.Gateway.ID]++
	}
	if seen["dc-gw1"] != 3 || seen["site2-gw1"] != 3 {
		t.Errorf("placement = %v, want 3 on each", seen)
	}
}

func TestFullGatewaySkippedByLiveCount(t *testing.T) {
	svc, st, clk := setup(t)
	ctx := context.Background()
	// Shrink dc-gw1 to 2 sessions; the health report still says 0 peers.
	gws, _ := st.ListGateways(ctx)
	for _, g := range gws {
		if g.ID == "dc-gw1" {
			g.Capacity = 2
			_ = st.UpsertGateway(ctx, g)
		}
	}
	_ = st.RecordGatewayHealth(ctx, "dc-gw1", 0, clk.t)
	_ = st.SetGatewayEnabled(ctx, "site2-gw1", false)
	connect(t, svc, "cap-a", "boot")
	connect(t, svc, "cap-b", "boot")
	_, err := svc.Connect(ctx, model.Identity{UserOID: "x"},
		ConnectRequest{WGPublicKey: testKey, DeviceID: "cap-c", BootID: "boot"})
	if !errors.Is(err, ErrNoGateway) {
		t.Errorf("third connect: err = %v, want ErrNoGateway (gateway full by live count, though it reports 0 peers)", err)
	}
}

func setMetrics(t *testing.T, st *store.Memory, id string, at time.Time, cpu float64, memPct float64, freeGB float64) {
	t.Helper()
	const gb = 1 << 30
	m := model.HostMetrics{At: at, CPUPercent: cpu,
		MemTotal: 100 * gb, MemUsed: uint64(memPct) * gb,
		DiskTotal: 100 * gb, DiskUsed: uint64(100-freeGB) * gb}
	if err := st.SetGatewayMetrics(context.Background(), id, m); err != nil {
		t.Fatal(err)
	}
}

func TestOverLimitGatewaySkipped(t *testing.T) {
	svc, st, clk := setup(t)
	svc.cfg.DefaultPolicy = model.PlacementPolicy{MaxCPUPercent: 70, MaxMemPercent: 70, MinFreeDiskGB: 10}
	setMetrics(t, st, "dc-gw1", clk.t, 85, 40, 50)    // CPU over
	setMetrics(t, st, "site2-gw1", clk.t, 20, 40, 50) // fine
	for i := 0; i < 3; i++ {
		if p := connect(t, svc, "lim-"+string(rune('a'+i)), "boot"); p.Gateway.ID != "site2-gw1" {
			t.Fatalf("connect %d placed on %s, want site2-gw1 (dc-gw1 is over its CPU limit)", i, p.Gateway.ID)
		}
	}
	setMetrics(t, st, "site2-gw1", clk.t, 20, 40, 5) // now short on disk too
	if p := connect(t, svc, "lim-z", "boot"); p.Gateway.ID != "dc-gw1" {
		t.Errorf("with both over limits, placed on %s; want least-loaded dc-gw1 (0 sessions)", p.Gateway.ID)
	}
}

func TestAdminPolicyOverridesDefault(t *testing.T) {
	svc, st, clk := setup(t)
	ctx := context.Background()
	svc.cfg.DefaultPolicy = model.PlacementPolicy{MaxCPUPercent: 70, MaxMemPercent: 70, MinFreeDiskGB: 10}
	setMetrics(t, st, "dc-gw1", clk.t, 20, 75, 50) // memory 75%: over the default 70
	setMetrics(t, st, "site2-gw1", clk.t, 20, 40, 50)
	connect(t, svc, "pol-a", "boot") // goes to site2 (dc over memory)
	_ = st.SetPlacementPolicy(ctx, model.PlacementPolicy{MaxCPUPercent: 70, MaxMemPercent: 90, MinFreeDiskGB: 10})
	if p := connect(t, svc, "pol-b", "boot"); p.Gateway.ID != "dc-gw1" {
		t.Errorf("after raising the memory limit to 90%%, placed on %s; want dc-gw1 (fewest sessions)", p.Gateway.ID)
	}
}

func TestStaleMetricsDoNotBlock(t *testing.T) {
	svc, st, clk := setup(t)
	svc.cfg.DefaultPolicy = model.PlacementPolicy{MaxCPUPercent: 70, MaxMemPercent: 70, MinFreeDiskGB: 10}
	svc.cfg.GatewayHealthTTL = 45 * time.Second
	setMetrics(t, st, "dc-gw1", clk.t.Add(-10*time.Minute), 99, 99, 1) // old sample
	_ = st.SetGatewayEnabled(context.Background(), "site2-gw1", false)
	if p := connect(t, svc, "stale-a", "boot"); p.Gateway.ID != "dc-gw1" {
		t.Errorf("placed on %s; stale metrics should not block dc-gw1", p.Gateway.ID)
	}
}

func TestCapacitySizeDoesNotWeightBalance(t *testing.T) {
	svc, st, _ := setup(t)
	ctx := context.Background()
	gws, _ := st.ListGateways(ctx)
	for _, g := range gws {
		if g.ID == "site2-gw1" {
			g.Capacity = 5000 // much bigger, but balance is by session count
			_ = st.UpsertGateway(ctx, g)
		}
	}
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		seen[connect(t, svc, "size-"+string(rune('a'+i)), "boot").Gateway.ID]++
	}
	if seen["dc-gw1"] != 2 || seen["site2-gw1"] != 2 {
		t.Errorf("placement = %v, want 2 on each regardless of capacity", seen)
	}
}

func TestWatchReturnsWhenAdminDisconnects(t *testing.T) {
	svc, _, _ := setup(t)
	p := connect(t, svc, "watch-a", "boot")
	done := make(chan error, 1)
	go func() {
		_, err := svc.Watch(context.Background(), p.Session.ID, p.ResumeToken, 20*time.Second)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if err := svc.AdminDisconnect(context.Background(), p.Session.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrReauthRequired) {
			t.Fatalf("watch returned %v, want ErrReauthRequired", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("watch did not notice the admin disconnect within 5 s")
	}
}

func TestWatchWakesForCommands(t *testing.T) {
	svc, st, _ := setup(t)
	ctx := context.Background()
	p := connect(t, svc, "cmd-a", "boot")
	if _, err := svc.SendCommand(ctx, p.Session.ID, "helpdesk1", "speedtest", ""); err != nil {
		t.Fatal(err)
	}
	pending, err := svc.Watch(ctx, p.Session.ID, p.ResumeToken, 10*time.Second)
	if err != nil || !pending {
		t.Fatalf("watch: pending=%v err=%v, want true", pending, err)
	}
	cmds, _ := st.TakeCommands(ctx, p.Session.ID)
	if len(cmds) != 1 || cmds[0].Type != "speedtest" || cmds[0].From != "helpdesk1" {
		t.Fatalf("commands = %+v", cmds)
	}
	if has, _ := st.HasCommands(ctx, p.Session.ID); has {
		t.Error("commands not cleared after delivery")
	}
	_ = svc.Disconnect(ctx, p.Session.ID, p.ResumeToken)
	if _, err := svc.SendCommand(ctx, p.Session.ID, "helpdesk1", "speedtest", ""); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("command to an ended session: %v, want ErrReauthRequired", err)
	}
}

func TestDeviceApproval(t *testing.T) {
	svc, st, _ := setup(t)
	ctx := context.Background()
	dev := model.Device{ID: "guid-1", Name: "LT-4100", Platform: "windows", LastUser: "dan"}

	// Approval off: new devices are approved automatically.
	if d, err := svc.CheckDevice(ctx, dev); err != nil || d.Status != model.DeviceApproved {
		t.Fatalf("approval off: status=%s err=%v", d.Status, err)
	}
	// Approval on: a new device is held as pending.
	_ = st.SetSetting(ctx, "device_policy", model.DevicePolicy{RequireApproval: true})
	dev2 := model.Device{ID: "guid-2", Name: "LT-4200", Platform: "windows", LastUser: "amy"}
	if d, err := svc.CheckDevice(ctx, dev2); !errors.Is(err, ErrDevicePending) || d.Status != model.DevicePending {
		t.Fatalf("new device: status=%s err=%v, want pending", d.Status, err)
	}
	// The device approved earlier is still fine.
	if _, err := svc.CheckDevice(ctx, dev); err != nil {
		t.Fatalf("known device: %v", err)
	}
	// Admin approves the new one.
	if n, _ := st.ApprovePending(ctx, "admin", time.Now()); n != 1 {
		t.Fatalf("approved %d, want 1", n)
	}
	if _, err := svc.CheckDevice(ctx, dev2); err != nil {
		t.Fatalf("after approval: %v", err)
	}
	// Blocked devices can't connect even with approval switched off.
	_ = st.SetDeviceStatus(ctx, "guid-1", model.DeviceBlocked, "admin", true, time.Now())
	_ = st.SetSetting(ctx, "device_policy", model.DevicePolicy{RequireApproval: false})
	if _, err := svc.CheckDevice(ctx, dev); !errors.Is(err, ErrDeviceBlocked) {
		t.Fatalf("blocked device: %v, want ErrDeviceBlocked", err)
	}
}

func TestBadWireGuardKeyRejected(t *testing.T) {
	svc, _, _ := setup(t)
	_, err := svc.Connect(context.Background(), model.Identity{UserOID: "x"},
		ConnectRequest{WGPublicKey: "nope", DeviceID: "d", BootID: "b"})
	if !errors.Is(err, ErrBadRequest) {
		t.Errorf("err = %v, want ErrBadRequest", err)
	}
}
