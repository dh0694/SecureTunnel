package main

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// netFingerprint is the engine's NetFingerprint: the PC's own adapter
// addresses, DNS suffixes, and preferred default routes.
func netFingerprint() string {
	ips := physicalIPs()
	sfx := adapterDNSSuffixes()
	sort.Strings(ips)
	sort.Strings(sfx)
	fp := strings.Join(ips, ",") + "|" + strings.ToLower(strings.Join(sfx, ","))
	if route, _ := preferredPhysicalRoute(windows.AF_INET); route != "" {
		fp += "|v4=" + route
	}
	if route, _ := preferredPhysicalRoute(windows.AF_INET6); route != "" {
		fp += "|v6=" + route
	}
	return fp
}

// physicalRouteAvailable reports whether Windows has an active default route
// outside the tunnel. A usable route in either family confirms availability.
// Only report absence if both families were checked successfully.
func physicalRouteAvailable() (available, known bool) {
	v4, known4 := preferredPhysicalRoute(windows.AF_INET)
	if v4 != "" {
		return true, true
	}
	v6, known6 := preferredPhysicalRoute(windows.AF_INET6)
	return v6 != "", v6 != "" || (known4 && known6)
}

func preferredPhysicalRoute(family winipcfg.AddressFamily) (string, bool) {
	identity, _, known := preferredPhysicalRouteInfo(family)
	return identity, known
}

func preferredPhysicalRouteInfo(family winipcfg.AddressFamily) (identity string, index int, known bool) {
	routes, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return "", 0, false
	}

	known = true
	lowestMetric := ^uint64(0)
	for i := range routes {
		route := &routes[i]
		if route.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		ifc, err := route.InterfaceLUID.Interface()
		if err != nil {
			known = false
			continue
		}
		if ifc.OperStatus != winipcfg.IfOperStatusUp || ifc.Type == winipcfg.IfTypeSoftwareLoopback ||
			strings.EqualFold(ifc.Alias(), tunnelName) {
			continue
		}
		metric := uint64(route.Metric)
		if ipifc, err := route.InterfaceLUID.IPInterface(family); err == nil {
			metric += uint64(ipifc.Metric)
		}
		key := fmt.Sprintf("%d@%s", route.InterfaceLUID, route.NextHop.Addr())
		if metric < lowestMetric || (metric == lowestMetric && key < identity) {
			identity, index, lowestMetric = key, int(ifc.InterfaceIndex), metric
		}
	}
	return identity, index, known
}
