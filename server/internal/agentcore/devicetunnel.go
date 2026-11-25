package agentcore

import (
	"context"
	"time"

	"securetunnel/server/internal/clientapi"
)

// The device tunnel ("connect before logon"): while no user session is up,
// the service connects with the PC's device certificate so the Windows
// sign-in screen can reach domain controllers, DNS and management servers.
// The server limits it to a few subnets. A user's connect replaces it (the
// server ends the device session and the tunnel is swapped); when the user's
// session ends, the device tunnel comes back on the next tick.

// DeviceTunnelStatus is shown in the GUI while the device tunnel is up.
type DeviceTunnelStatus struct {
	Gateway  string    `json:"gateway"`
	TunnelIP string    `json:"tunnel_ip"`
	Since    time.Time `json:"since"`
	Subnets  []string  `json:"subnets"`
}

const (
	deviceRetryMin = 30 * time.Second
	deviceRetryMax = 5 * time.Minute
	// deviceOffRetry: the server said no for a policy reason (turned off, not
	// approved, no certificate); check again now and then in case IT changes it.
	deviceOffRetry = 2 * time.Minute
)

// deviceWanted reports whether a device tunnel should be opened now (caller holds mu).
func (e *Engine) deviceWanted(now time.Time) bool {
	return e.o.DeviceTunnel != nil && e.sess == nil && !e.busy && !e.devBusy && !e.onTrusted &&
		e.api != nil && !now.Before(e.devNext) && e.o.DeviceTunnel()
}

// deviceTick opens the device tunnel when wanted. It runs from Tick when there
// is no session and returns how long until the next tick.
func (e *Engine) deviceTick(ctx context.Context) time.Duration {
	now := e.o.Now()
	e.mu.Lock()
	if !e.deviceWanted(now) {
		e.mu.Unlock()
		return 15 * time.Second
	}
	api, server := e.api, e.server
	e.devBusy = true
	e.mu.Unlock()

	wait, err := e.connectDevice(ctx, api, server)

	e.mu.Lock()
	e.devBusy = false
	if err != nil {
		e.devNext = e.o.Now().Add(wait)
	} else {
		e.devFails = 0
	}
	e.mu.Unlock()
	if err != nil {
		return 15 * time.Second
	}
	return time.Second
}

// connectDevice signs a fresh challenge with the device certificate and opens
// the device tunnel. On failure it returns how long to wait before retrying.
func (e *Engine) connectDevice(ctx context.Context, api API, server string) (time.Duration, error) {
	dev, ok := api.(interface {
		Challenge(context.Context) (clientapi.Challenge, error)
		ConnectDevice(context.Context, clientapi.DeviceConnectRequest) (clientapi.Placement, error)
	})
	if !ok || e.o.DeviceProof == nil {
		return deviceRetryMax, errNoDeviceTunnel
	}
	backoff := func(err error) (time.Duration, error) {
		e.mu.Lock()
		e.devFails++
		n := e.devFails
		e.mu.Unlock()
		d := deviceRetryMin << min(n-1, 4)
		if d > deviceRetryMax {
			d = deviceRetryMax
		}
		return d, err
	}

	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ch, err := dev.Challenge(cctx)
	cancel()
	if err != nil {
		if clientapi.HasStatus(err, 404) {
			return deviceOffRetry, err
		}
		return backoff(err)
	}
	proofs, join := e.o.DeviceProof(ctx, clientapi.Challenge{Nonce: ch.Nonce, Issuers: ch.Issuers, DeviceCert: true})
	var certProofs []clientapi.DeviceProof
	for _, p := range proofs {
		if p.Kind == "device_cert" {
			certProofs = append(certProofs, p)
		}
	}
	if len(certProofs) == 0 {
		e.logDevice("no device certificate could sign; the device tunnel needs one from a CA the server trusts")
		return deviceOffRetry, errNoDeviceTunnel
	}
	priv, pub, err := e.o.KeyGen()
	if err != nil {
		return backoff(err)
	}
	boot := e.o.BootID()
	cctx, cancel = context.WithTimeout(ctx, 20*time.Second)
	p, err := dev.ConnectDevice(cctx, clientapi.DeviceConnectRequest{WGPublicKey: pub, DeviceID: e.o.DeviceID,
		DeviceName: e.o.DeviceName, BootID: boot, Platform: e.o.Platform, Nonce: ch.Nonce, Proofs: certProofs, Join: join})
	cancel()
	if err != nil {
		switch {
		case clientapi.HasCode(err, "device_tunnel_off"), clientapi.HasCode(err, "not_enabled"):
			return deviceOffRetry, err
		case clientapi.HasCode(err, "device_not_approved"), clientapi.HasCode(err, "device_untrusted"),
			clientapi.HasCode(err, "country_blocked"):
			e.logDevice("device tunnel refused", "err", err)
			return deviceOffRetry, err
		case clientapi.HasCode(err, "user_session_active"):
			return time.Minute, err
		}
		e.logDevice("device tunnel connect failed", "err", err)
		return backoff(err)
	}

	// A user may have started signing in meanwhile; their connect replaces
	// this session on the server, so don't bring the tunnel up.
	e.mu.Lock()
	userBusy := e.busy || e.sess != nil
	e.mu.Unlock()
	if userBusy {
		return deviceRetryMin, errNoDeviceTunnel
	}
	if err := e.tunnelUp(tunnelConfig(priv, p)); err != nil {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = api.Disconnect(dctx, p.SessionID, p.ResumeToken)
		cancel()
		e.logDevice("start device tunnel", "err", err)
		return backoff(err)
	}
	now := e.o.Now()
	s := &Session{Server: server, ID: p.SessionID, ResumeToken: p.ResumeToken, BootID: boot, PrivateKey: priv,
		Placement: p, ConnectedSince: now, LastOK: now, DeviceTrust: p.DeviceTrust, Device: true}
	if err := e.o.Store.Save(s); err != nil {
		e.o.Log.Warn("save session", "err", err)
	}
	e.mu.Lock()
	e.sess, e.lastHB = s, now
	e.resetStats()
	e.setState(StateConnected, "")
	e.mu.Unlock()
	e.o.Log.Info("device tunnel connected (before sign-in)", "gateway", p.Gateway.ID, "tunnel_ip", p.Tunnel.Address,
		"subnets", p.Tunnel.AllowedIPs)
	e.poke()
	return 0, nil
}

// logDevice logs device tunnel problems, but only once per kind of message
// in a row, so a PC that isn't set up for it doesn't fill the log.
func (e *Engine) logDevice(msg string, args ...any) {
	e.mu.Lock()
	same := e.devLastLog == msg
	e.devLastLog = msg
	e.mu.Unlock()
	if !same {
		e.o.Log.Warn(msg, args...)
	}
}

// waitDeviceConnect waits for an in-progress device tunnel connect to finish
// before a user's connect starts (at most a little longer than its timeouts).
func (e *Engine) waitDeviceConnect(ctx context.Context) {
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		b := e.devBusy
		e.mu.Unlock()
		if !b {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// deviceStatus makes the GUI show "not connected" (with the device tunnel
// noted) while only the device tunnel is up, so the user can still sign in.
// Caller holds mu.
func (e *Engine) deviceStatus(st *Status) {
	s := e.sess
	if s == nil || !s.Device {
		return
	}
	st.DeviceTunnel = &DeviceTunnelStatus{Gateway: s.Placement.Gateway.ID, TunnelIP: st.TunnelIP,
		Since: s.ConnectedSince, Subnets: s.Placement.Tunnel.AllowedIPs}
	if !e.busy {
		st.State, st.Message = StateDisconnected, ""
	}
	st.User, st.Gateway, st.GatewayEndpoint, st.TunnelIP = "", "", "", ""
	st.ConnectedSince, st.SessionExpires, st.GraceLeftSec, st.DeviceTrust = time.Time{}, time.Time{}, 0, nil
}

// WakeDeviceTunnel tries the device tunnel right away (e.g. the Windows user
// signed out and their tunnel just ended) instead of at the next retry.
func (e *Engine) WakeDeviceTunnel() {
	e.mu.Lock()
	e.devNext, e.devFails = time.Time{}, 0
	e.mu.Unlock()
	e.poke()
}

// DeviceTunnelUp reports whether the device tunnel (and no user session) is up.
func (e *Engine) DeviceTunnelUp() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sess != nil && e.sess.Device
}

type deviceErr string

func (d deviceErr) Error() string { return string(d) }

const errNoDeviceTunnel = deviceErr("device tunnel not available")
