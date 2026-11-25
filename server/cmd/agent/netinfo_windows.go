package main

import (
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"securetunnel/server/internal/agentcore"
)

// tunnelTraffic returns the SecureTunnel adapter's byte counters.
func tunnelTraffic() (rx, tx uint64, ok bool) {
	ifc, err := net.InterfaceByName(tunnelName)
	if err != nil {
		return 0, 0, false
	}
	row := windows.MibIfRow2{InterfaceIndex: uint32(ifc.Index)}
	if err := windows.GetIfEntry2Ex(windows.MibIfEntryNormal, &row); err != nil {
		return 0, 0, false
	}
	return row.InOctets, row.OutOctets, true
}

var (
	netMu     sync.Mutex
	netCached agentcore.NetInfo
	netAt     time.Time
)

// cachedNetworkInfo describes the physical network, refreshed every 10 s.
func cachedNetworkInfo() agentcore.NetInfo {
	netMu.Lock()
	defer netMu.Unlock()
	if time.Since(netAt) < 10*time.Second {
		return netCached
	}
	netCached, netAt = networkInfo(), time.Now()
	return netCached
}

// physicalInterface is the adapter the PC uses for the internet: up, not
// loopback, not our tunnel or a virtual switch, with a routable IPv4 address.
func physicalInterface() *net.Interface {
	ifcs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for i := range ifcs {
		ifc := &ifcs[i]
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || ifc.Name == tunnelName {
			continue
		}
		lname := strings.ToLower(ifc.Name)
		if strings.Contains(lname, "vethernet") || strings.Contains(lname, "bluetooth") || strings.Contains(lname, "wireguard") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if ip4 := ipn.IP.To4(); ip4 != nil && !ip4.IsLinkLocalUnicast() {
					return ifc
				}
			}
		}
	}
	return nil
}

func networkInfo() agentcore.NetInfo {
	var info agentcore.NetInfo
	ifc := physicalInterface()
	if ifc == nil {
		return info
	}
	info.Adapter = ifc.Name
	lname := strings.ToLower(ifc.Name)
	switch {
	case strings.Contains(lname, "wi-fi"), strings.Contains(lname, "wireless"), strings.Contains(lname, "wlan"):
		info.Kind = "Wi-Fi"
	case strings.Contains(lname, "cellular"), strings.Contains(lname, "mobile"):
		info.Kind = "Cellular"
	default:
		info.Kind = "Ethernet"
	}
	if info.Kind == "Wi-Fi" {
		ssid, signal, mbps := wlanDetails()
		info.SSID, info.SignalPct, info.LinkMbps = ssid, signal, mbps
	}
	return info
}

// wlanDetails parses `netsh wlan show interfaces`.
func wlanDetails() (ssid string, signal, mbps int) {
	cmd := exec.Command("netsh", "wlan", "show", "interfaces")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return "", 0, 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "SSID":
			ssid = v
		case "Signal":
			signal, _ = strconv.Atoi(strings.TrimSuffix(v, "%"))
		case "Receive rate (Mbps)":
			f, _ := strconv.ParseFloat(v, 64)
			mbps = int(f)
		}
	}
	return ssid, signal, mbps
}
