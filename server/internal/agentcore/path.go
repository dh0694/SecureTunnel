package agentcore

import (
	"context"
	"net/netip"
	"time"
)

const (
	pathFailureThreshold = 3
	roamProbeTimeout     = time.Second
	roamProbeInterval    = 500 * time.Millisecond
)

const (
	vpnChecking          = "checking"
	vpnWaitingForNetwork = "waiting_for_network"
	vpnRepairing         = "repairing"
	vpnSwitchingGateway  = "switching_gateway"
)

func (e *Engine) setVPNPhase(phase string) {
	e.mu.Lock()
	e.vpnPhase = phase
	e.mu.Unlock()
}

type pathState uint8

const (
	pathUnknown pathState = iota
	pathWorking
	pathDown
)

// observePath tracks consecutive failures on a gateway that has answered
// before. A gateway that never answers ICMP must not trigger a move by itself.
// Caller holds mu.
func (e *Engine) observePath(ok bool) bool {
	if ok {
		e.pathConfirmed, e.pathMisses = true, 0
		e.pathRepairedAt = time.Time{}
		return false
	}
	if !e.pathConfirmed {
		return false
	}
	e.pathMisses++
	return e.pathMisses == pathFailureThreshold
}

// resetPath is called with mu held when the session or its tunnel changes.
func (e *Engine) resetPath() {
	e.pathConfirmed = false
	e.pathMisses = 0
	e.pathRepairedAt = time.Time{}
}

func (e *Engine) physicalRouteAvailable() bool {
	if e.o.PhysicalRouteAvailable == nil {
		return true
	}
	available, known := e.o.PhysicalRouteAvailable()
	return available || !known
}

// checkTunnelPath probes the gateway's inside address. A single negative
// sample records a miss, but only a complete multi-probe check signals loss.
func (e *Engine) checkTunnelPath(ctx context.Context, s *Session, attempts int) pathState {
	if e.o.Ping == nil || e.standby || e.tunnelPending || !e.o.Tunnel.Running() {
		return pathUnknown
	}
	source, ip := tunnelProbeAddresses(s)
	if !source.IsValid() || !ip.IsValid() {
		return pathUnknown
	}
	routed := false
	for _, route := range s.Placement.Tunnel.AllowedIPs {
		if prefix, err := netip.ParsePrefix(route); err == nil && prefix.Contains(ip) {
			routed = true
			break
		}
	}
	if !routed {
		return pathUnknown
	}
	for i := 0; i < attempts; i++ {
		if i > 0 {
			sleepCtx(ctx, roamProbeInterval)
		}
		if ctx.Err() != nil {
			return pathUnknown
		}
		_, err := e.o.Ping(ctx, source, ip, roamProbeTimeout)
		e.mu.Lock()
		e.observePath(err == nil)
		e.mu.Unlock()
		if err == nil {
			return pathWorking
		}
	}
	if attempts == 1 {
		return pathUnknown
	}
	return pathDown
}

func tunnelProbeAddresses(s *Session) (source, destination netip.Addr) {
	address, _ := netip.ParsePrefix(s.Placement.Tunnel.Address)
	destination, _ = netip.ParseAddr(s.Placement.Gateway.InsideIP)
	return address.Addr(), destination
}

func (e *Engine) repairTunnel(s *Session) {
	e.setVPNPhase(vpnRepairing)
	e.o.Log.Info("repairing the local tunnel", "gateway", s.Placement.Gateway.ID)
	e.tunnelPending = true
	e.ensureTunnel(s) // Up replaces the local adapter using the current assignment.
}

func (e *Engine) handlePathFailure(ctx context.Context, s *Session) {
	now := e.o.Now()
	e.mu.Lock()
	repairedAt := e.pathRepairedAt
	e.setState(StateReconnecting, "Trying to reconnect…")
	localRepair := repairedAt.IsZero() || (len(s.Placement.Alternates) == 0 && now.Sub(repairedAt) >= 30*time.Second)
	if localRepair {
		e.pathRepairedAt = now
	}
	failover := !localRepair && now.Sub(repairedAt) >= netRebuildAfter &&
		now.Sub(e.lastRecover) >= e.o.FailoverAfter && len(s.Placement.Alternates) > 0
	if failover {
		e.lastRecover = now
	}
	e.mu.Unlock()
	if localRepair {
		e.repairTunnel(s)
	} else if failover {
		e.recover(ctx, s)
	}
}
