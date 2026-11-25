package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"securetunnel/server/internal/agentcfg"
	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/clienttls"
	"securetunnel/server/internal/model"
)

// Office network detection. The rules (DNS suffixes, local subnets, office
// public IPs) come from the server with each heartbeat and are cached on disk,
// so the agent also recognises the office before connecting.

var officeMu sync.Mutex

func officeCachePath() string { return filepath.Join(dataDir(), "office-networks.json") }

// officePolicy returns the current rules: from the live session if
// connected (and cache them), otherwise from the cache.
func (a *agentService) officePolicy() model.OfficeNetworkPolicy {
	officeMu.Lock()
	defer officeMu.Unlock()
	var on clientapi.OfficeNetworks
	if s, ok := a.engine.CurrentSession(); ok {
		on = s.Placement.OfficeNetworks
		var cached clientapi.OfficeNetworks
		if b, err := os.ReadFile(officeCachePath()); err != nil || json.Unmarshal(b, &cached) != nil || !reflect.DeepEqual(cached, on) {
			if b, err := json.Marshal(on); err == nil {
				_ = os.WriteFile(officeCachePath(), b, 0o600)
			}
		}
	} else if b, err := os.ReadFile(officeCachePath()); err == nil {
		_ = json.Unmarshal(b, &on)
	}
	return model.OfficeNetworkPolicy{Enabled: on.Enabled, DNSSuffixes: on.DNSSuffixes, LocalSubnets: on.LocalSubnets, PublicIPs: on.PublicIPs}
}

// officeProbe is the engine's TrustedProbe.
func (a *agentService) officeProbe(ctx context.Context) (bool, string) {
	pol := a.officePolicy()
	route, index := preferredOfficeAdapter()
	if index != 0 {
		var isp string
		if a.ips != nil && len(pol.PublicIPs) != 0 {
			isp = a.ips.ispForNetwork(officeNetworkFingerprint(route, index))
		}
		if ok, why := pol.Match(adapterDNSSuffixes(index), physicalIPs(index), isp); ok {
			return true, why
		}
	}
	// Optional registry-configured HTTPS probe (only meaningful outside the tunnel).
	if a.engine.Status().State == agentcore.StateDisconnected {
		if ok := registryProbe(ctx); ok {
			return true, "office probe answered"
		}
	}
	return false, ""
}

// adapterDNSSuffixes lists the selected adapter’s connection-specific suffix.
func adapterDNSSuffixes(index int) []string {
	size := uint32(16 << 10)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var out []string
		for p := aa; p != nil; p = p.Next {
			if p.OperStatus != windows.IfOperStatusUp || (int(p.IfIndex) != index && int(p.Ipv6IfIndex) != index) {
				continue
			}
			if windows.UTF16PtrToString(p.FriendlyName) == tunnelName {
				continue
			}
			if s := windows.UTF16PtrToString(p.DnsSuffix); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// physicalIPs lists usable IPv4 addresses on the selected adapter.
func physicalIPs(index int) []string {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, ifc := range ifcs {
		if ifc.Index != index || ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == tunnelName {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLinkLocalUnicast() {
					out = append(out, ip4.String())
				}
			}
		}
	}
	return out
}

// registryProbe: an HTTPS request to an internal-only URL with a pinned
// certificate, configured by policy (TrustedNetworkProbeUrl / TrustedNetworkCertSha256).
func registryProbe(ctx context.Context) bool {
	url := readString(policyKey, "TrustedNetworkProbeUrl")
	pin := clienttls.NormalizePin(readString(policyKey, "TrustedNetworkCertSha256"))
	if url == "" || pin == "" {
		return false
	}
	t := &clienttls.Trust{Host: agentcfg.Host(url), Pins: &clienttls.MemoryPins{Pin: pin}}
	c := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: t.Config(), Proxy: nil}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return true
}
