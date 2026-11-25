package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/speedtest"
)

// IPInfo is shown in the app and reported to the server.
type IPInfo struct {
	VPNIP     string    `json:"vpn_ip,omitempty"` // what websites see while connected
	ISPIP     string    `json:"isp_ip,omitempty"` // the internet connection's own public IP
	CheckedAt time.Time `json:"checked_at"`
}

// ipTracker looks up public IPs about once a minute and whenever the
// connection state changes. While connected, the VPN IP is looked up through
// the tunnel and the ISP IP outside it (via the tunnel process, like the
// speed test); while disconnected there is only the ISP IP.
type ipTracker struct {
	a *agentService

	mu        sync.Mutex
	info      IPInfo
	lastState agentcore.State
}

func (t *ipTracker) get() IPInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.info
}

func (t *ipTracker) loop(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		st := t.a.engine.Status().State
		t.mu.Lock()
		stale := time.Since(t.info.CheckedAt) > 60*time.Second || st != t.lastState
		t.mu.Unlock()
		if stale && (st == agentcore.StateConnected || st == agentcore.StateDisconnected) {
			t.refresh(ctx, st)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (t *ipTracker) refresh(ctx context.Context, st agentcore.State) {
	host := t.a.speed.policy().Host
	var info IPInfo
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	direct := &http.Client{Timeout: 15 * time.Second}
	if st == agentcore.StateConnected {
		if ip, err := speedtest.PublicIP(lctx, direct, host); err == nil {
			info.VPNIP = ip // routed through the tunnel
		}
		if ip, err := bypassIP(host); err == nil {
			info.ISPIP = ip
		}
	} else if ip, err := speedtest.PublicIP(lctx, direct, host); err == nil {
		info.ISPIP = ip
	}
	info.CheckedAt = time.Now()
	t.mu.Lock()
	t.info, t.lastState = info, st
	t.mu.Unlock()
}

// fillDiagnostics adds the Windows-side details to the heartbeat report.
func (a *agentService) fillDiagnostics(d *clientapi.Diagnostics) {
	d.Hostname, _ = os.Hostname()
	d.OS = osVersion()
	d.UptimeSec = int64(windows.DurationSinceBoot() / time.Second)
	d.LocalIP = localIP()
	if a.ips != nil {
		ip := a.ips.get()
		d.ISPIP, d.VPNIP = ip.ISPIP, ip.VPNIP
	}
	if a.upd != nil { // shown on the admin site's App updates page
		u := a.upd.info()
		d.UpdateState, d.UpdateVersion, d.UpdatePostponed = u.State, u.Latest, u.Postponed
		switch {
		case !u.Countdown.IsZero():
			d.UpdateState, d.UpdateAt = "installing_soon", u.Countdown
		case !u.InstallAt.IsZero() && u.State == "ready":
			d.UpdateState, d.UpdateAt = "scheduled", u.InstallAt
		}
	}
}

var (
	osOnce sync.Once
	osName string
)

// osVersion returns e.g. "Windows 11 Pro 24H2 (build 26100.4061)".
func osVersion() string {
	osOnce.Do(func() {
		v := windows.RtlGetVersion()
		product, display, ubr := "Windows", "", uint64(0)
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
			if s, _, err := k.GetStringValue("ProductName"); err == nil {
				product = s
			}
			if s, _, err := k.GetStringValue("DisplayVersion"); err == nil {
				display = s
			}
			ubr, _, _ = k.GetIntegerValue("UBR")
			k.Close()
		}
		// Windows 11 still reports "Windows 10" in ProductName.
		if v.BuildNumber >= 22000 {
			product = strings.Replace(product, "Windows 10", "Windows 11", 1)
		}
		osName = strings.TrimSpace(fmt.Sprintf("%s %s (build %d.%d)", product, display, v.BuildNumber, ubr))
	})
	return osName
}

// localIP is the physical adapter's IPv4 address.
func localIP() string {
	ifc := physicalInterface()
	if ifc == nil {
		return ""
	}
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLinkLocalUnicast() {
				return ip4.String()
			}
		}
	}
	return ""
}
