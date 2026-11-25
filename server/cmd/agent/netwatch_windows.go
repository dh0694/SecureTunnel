package main

import (
	"context"
	"sort"
	"strings"

	"securetunnel/server/internal/agentcore"
)

// netFingerprint is the engine's NetFingerprint: the PC's own adapter
// addresses and DNS suffixes (the tunnel adapter is left out).
func netFingerprint() string {
	ips := physicalIPs()
	sfx := adapterDNSSuffixes()
	sort.Strings(ips)
	sort.Strings(sfx)
	return strings.Join(ips, ",") + "|" + strings.ToLower(strings.Join(sfx, ","))
}

// onNetworkChange rechecks the public IP so the office check sees the new one.
func (a *agentService) onNetworkChange(ctx context.Context, st agentcore.State) {
	if a.ips != nil && (st == agentcore.StateConnected || st == agentcore.StateDisconnected) {
		a.ips.refresh(ctx, st)
	}
}
