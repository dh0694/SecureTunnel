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

const (
	publicIPTimeout = 6 * time.Second
	publicIPRetry   = 3 * time.Second
	publicIPRefresh = time.Minute
)

type ipLookup struct {
	next   time.Time
	cancel context.CancelFunc
}

// ipTracker publishes each address independently. Network and tunnel changes
// invalidate pending lookups so a result from the old route cannot be shown.
type ipTracker struct {
	a      *agentService
	tunnel *serviceTunnel
	wake   chan struct{}

	mu         sync.Mutex
	info       IPInfo
	generation uint64
	ispNetwork string
	vpn, isp   ipLookup
}

func (t *ipTracker) get() IPInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.info
}

func (t *ipTracker) ispForNetwork(network string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if network == "" || t.ispNetwork != network {
		return ""
	}
	return t.info.ISPIP
}

func (t *ipTracker) notify() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *ipTracker) invalidate() {
	t.mu.Lock()
	t.generation++
	// Keep a verified ISP IP across tunnel-only changes. Office detection
	// checks the physical network before trusting this value.
	t.info.VPNIP = ""
	for _, lookup := range []*ipLookup{&t.vpn, &t.isp} {
		if lookup.cancel != nil {
			lookup.cancel()
		}
		*lookup = ipLookup{}
	}
	t.mu.Unlock()
	t.notify()
}

func (t *ipTracker) requestRefresh() {
	t.mu.Lock()
	t.vpn.next, t.isp.next = time.Time{}, time.Time{}
	t.mu.Unlock()
	t.notify()
}

func (t *ipTracker) loop(ctx context.Context) {
	tick := time.NewTicker(publicIPRetry)
	defer tick.Stop()
	for ctx.Err() == nil {
		t.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-t.wake:
		}
	}
}

func (t *ipTracker) refresh(ctx context.Context) {
	t.mu.Lock()
	generation := t.generation
	t.mu.Unlock()

	st := t.a.engine.Status()
	// The physical IP can be the evidence that lets a reconnecting session
	// recognize the office. It must be refreshed during recovery as well.
	if st.State != agentcore.StateConnected && st.State != agentcore.StateDisconnected && st.State != agentcore.StateReconnecting {
		return
	}
	running := t.tunnel.Running()
	vpn := st.State == agentcore.StateConnected && !st.OfficeMode
	vpn = vpn && running
	host := t.a.speed.policy().Host
	network := netFingerprint()

	t.mu.Lock()
	defer t.mu.Unlock()
	if generation != t.generation {
		return
	}
	if network == "" || t.ispNetwork != network {
		t.info.ISPIP = ""
	}
	if vpn {
		t.start(ctx, &t.vpn, &t.info.VPNIP, host, "", false)
	}
	if network != "" {
		t.start(ctx, &t.isp, &t.info.ISPIP, host, network, running)
	}
}

// start runs with mu held. The lookup's context and generation belong to one
// route so completion can update only the field it actually measured.
func (t *ipTracker) start(ctx context.Context, lookup *ipLookup, field *string, host, network string, bypass bool) {
	if lookup.cancel != nil || time.Now().Before(lookup.next) {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, publicIPTimeout)
	lookup.cancel = cancel
	generation := t.generation
	go func() {
		defer cancel()
		var ip string
		var err error
		if bypass {
			ip, err = bypassIP(ctx, host)
		} else {
			client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
			ip, err = speedtest.PublicIP(ctx, client, host)
		}

		if network != "" && network != netFingerprint() {
			ip = "" // The physical route changed while the request was running.
		}
		t.mu.Lock()
		if generation != t.generation {
			t.mu.Unlock()
			return
		}
		lookup.cancel = nil
		now := time.Now()
		changed := false
		if err != nil || ip == "" {
			lookup.next = now.Add(publicIPRetry)
		} else {
			lookup.next = now.Add(publicIPRefresh)
			if network != "" {
				changed = ip != *field || network != t.ispNetwork
				t.ispNetwork = network
			}
			*field = ip
			t.info.CheckedAt = now
		}
		t.mu.Unlock()
		if changed {
			t.a.engine.Kick()
		}
	}()
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
