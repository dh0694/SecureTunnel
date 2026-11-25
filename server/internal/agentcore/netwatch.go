package agentcore

import (
	"context"
	"time"
)

// Network changes (plugging in, joining Wi-Fi, docking, waking from sleep)
// trigger a full recheck instead of waiting for the timers: the public IP
// (OnNetworkChange), the office rules and a heartbeat (which also updates the
// admin site and, through WireGuard roaming, the tunnel).

const (
	netPollEvery = 2 * time.Second
	netSettle    = 3 * time.Second // DHCP and DNS suffixes arrive a moment after the link
	// If the tunnel still isn't through this long after a network change (the
	// quick restart didn't help), rebuild it: direct check, then another gateway.
	netRebuildAfter = 10 * time.Second
)

func (e *Engine) netWatchLoop(ctx context.Context) {
	last := e.o.NetFingerprint()
	var changedAt time.Time // first sight of a change not yet handled
	for ctx.Err() == nil {
		sleepCtx(ctx, netPollEvery)
		if e.netCheck(ctx, &last, &changedAt, time.Now()) {
			e.o.Log.Info("network changed: rechecking public IP, office network and connection", "network", last)
		}
	}
}

// netCheck handles one poll; it reports whether a recheck ran. Split out for tests.
func (e *Engine) netCheck(ctx context.Context, last *string, changedAt *time.Time, now time.Time) bool {
	fp := e.o.NetFingerprint()
	if fp != *last {
		*last, *changedAt = fp, now // (re)start the settle wait on every change
		e.mu.Lock()
		if e.sess != nil && !e.sess.Device && !e.standby && !e.busy {
			e.vpnPhase = vpnChecking
			e.netChangedAt = e.o.Now()
		}
		e.mu.Unlock()
		return false
	}
	if changedAt.IsZero() || now.Sub(*changedAt) < netSettle {
		return false
	}
	*changedAt = time.Time{}
	if fp == "" || fp == "|" {
		e.Kick() // check whether Windows still has a usable route
		return false
	}
	// Connections to the server opened on the old network may hang: drop them.
	if e.o.OnTunnelChange != nil {
		e.o.OnTunnelChange()
	}
	e.mu.Lock()
	e.netKick = true // check the tunnel on the settled route before repairing it
	e.netChangedAt = e.o.Now()
	e.mu.Unlock()
	e.Kick() // office check + heartbeat now, without waiting for the public IP
	if e.o.OnNetworkChange != nil {
		st := e.Status().State
		go func() {
			e.o.OnNetworkChange(ctx, st) // public IP (can take a few seconds)
			e.Kick()                     // office check again with the new public IP
		}()
	}
	return true
}
