package agentcore

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"securetunnel/server/internal/clientapi"
)

// devAPI adds the device tunnel calls to the fake server.
type devAPI struct {
	*fakeAPI
	dmu        sync.Mutex
	devErr     error
	devConnect int
	lastReq    clientapi.DeviceConnectRequest
}

func (d *devAPI) Challenge(context.Context) (clientapi.Challenge, error) {
	return clientapi.Challenge{Nonce: "nonce-1"}, nil
}

func (d *devAPI) ConnectDevice(_ context.Context, r clientapi.DeviceConnectRequest) (clientapi.Placement, error) {
	d.dmu.Lock()
	defer d.dmu.Unlock()
	d.devConnect++
	d.lastReq = r
	if d.devErr != nil {
		return clientapi.Placement{}, d.devErr
	}
	p := placement("gw-a")
	p.SessionID, p.ResumeToken, p.Kind = "dev-1", "dev-resume", "device"
	p.Tunnel.Address = "10.200.0.3/32"
	p.Tunnel.AllowedIPs = []string{"10.0.0.10/32", "10.200.0.1/32"}
	return p, nil
}

func newDeviceRig(t *testing.T, allowed *bool) (*rig, *devAPI) {
	t.Helper()
	r := &rig{tun: &fakeTunnel{}, store: &memStore{}, now: time.Date(2026, 11, 22, 9, 0, 0, 0, time.UTC), boot: "boot-1"}
	r.api = &fakeAPI{tun: r.tun}
	d := &devAPI{fakeAPI: r.api}
	r.e = New(Options{
		NewAPI:   func(string) API { return d },
		Tunnel:   r.tun,
		Store:    r.store,
		BootID:   func() string { return r.boot },
		DeviceID: "PC-1", DeviceName: "LT-4100",
		KeyGen:   func() (string, string, error) { return "priv", "pub", nil },
		Now:      func() time.Time { return r.now },
		DeviceProof: func(_ context.Context, ch clientapi.Challenge) ([]clientapi.DeviceProof, *clientapi.JoinInfo) {
			return []clientapi.DeviceProof{{Kind: "device_cert", Alg: "ES256", Sig: "sig"}}, nil
		},
		DeviceTunnel: func() bool { return *allowed },
	})
	if err := r.e.SetServer("https://vpn.example.com", false); err != nil {
		t.Fatal(err)
	}
	return r, d
}

func TestDeviceTunnelLifecycle(t *testing.T) {
	ctx := context.Background()
	allowed := true
	r, d := newDeviceRig(t, &allowed)

	// Nobody signed in: the device tunnel comes up, split to the DC subnets.
	r.e.Tick(ctx)
	if !r.tun.Running() || strings.Join(r.tun.cfg.AllowedIPs, ",") != "10.0.0.10/32,10.200.0.1/32" {
		t.Fatalf("device tunnel = running %v cfg %+v", r.tun.Running(), r.tun.cfg)
	}
	if d.lastReq.Nonce != "nonce-1" || len(d.lastReq.Proofs) != 1 || d.lastReq.DeviceName != "LT-4100" {
		t.Errorf("request = %+v", d.lastReq)
	}
	st := r.e.Status()
	if st.State != StateDisconnected || st.DeviceTunnel == nil || st.User != "" || st.TunnelIP != "" {
		t.Fatalf("status with only the device tunnel = %+v", st)
	}
	if s, _ := r.store.Load(); s == nil || !s.Device {
		t.Error("device session not saved as a device session")
	}
	// A device tunnel isn't the user's to disconnect.
	if err := r.e.Disconnect(ctx); err != nil || !r.tun.Running() {
		t.Fatalf("disconnect touched the device tunnel: err=%v running=%v", err, r.tun.Running())
	}

	// The user signs in: their full tunnel replaces it.
	r.connect(t)
	st = r.e.Status()
	if st.State != StateConnected || st.User != "testuser" || st.DeviceTunnel != nil {
		t.Fatalf("after sign-in = %+v", st)
	}
	if !strings.Contains(r.tun.cfg.WGQuick(), "AllowedIPs = 0.0.0.0/0") {
		t.Error("user tunnel is not full tunnel")
	}

	// The user signs out of SecureTunnel: the device tunnel comes back.
	if err := r.e.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if r.tun.Running() {
		t.Fatal("tunnel still up right after sign-out")
	}
	r.e.Tick(ctx)
	if !r.e.DeviceTunnelUp() || d.devConnect != 2 {
		t.Fatalf("device tunnel not back after sign-out (connects=%d)", d.devConnect)
	}
}

func TestDeviceTunnelBacksOffAndHonorsLocalSwitch(t *testing.T) {
	ctx := context.Background()
	allowed := false
	r, d := newDeviceRig(t, &allowed)

	r.e.Tick(ctx)
	if d.devConnect != 0 || r.tun.Running() {
		t.Fatal("device tunnel opened although turned off on this PC")
	}

	allowed = true
	d.devErr = &clientapi.APIError{Status: 403, Code: "device_tunnel_off", Message: "off"}
	r.e.Tick(ctx)
	r.e.Tick(ctx)
	if d.devConnect != 1 {
		t.Fatalf("connects = %d, want 1 (wait before asking again)", d.devConnect)
	}
	if st := r.e.Status(); st.State != StateDisconnected || st.Message != "" {
		t.Errorf("a refused device tunnel shouldn't show anything to the user: %+v", st)
	}
	r.advance(3 * time.Minute)
	d.devErr = nil
	r.e.Tick(ctx)
	if d.devConnect != 2 || !r.e.DeviceTunnelUp() {
		t.Fatalf("not retried after the wait (connects=%d)", d.devConnect)
	}

	// The server ends it (turned off): it goes quietly and is retried later.
	r.api.hbErr = func(bool) error { return &clientapi.APIError{Status: 401, Code: "reauth_required"} }
	r.advance(time.Minute)
	r.e.Tick(ctx)
	if r.e.DeviceTunnelUp() || r.tun.Running() {
		t.Fatal("device tunnel still up after the server ended it")
	}
	if st := r.e.Status(); st.Message != "" {
		t.Errorf("message = %q, want none for a device tunnel", st.Message)
	}
}
