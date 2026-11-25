//go:build windows

package main

import "strings"

// deviceTunnelAllowed is the engine's DeviceTunnel hook: whether this PC may
// open the pre-logon device tunnel while no user is connected. The server
// decides whether it's on (Policies page) and which devices may use it; this
// is a per-PC off switch on top:
//
//	HKLM\SOFTWARE\Policies\SecureTunnel  DeviceTunnel = "0" / "1"  (GPO/Intune; wins)
//	HKLM\SOFTWARE\SecureTunnel           DeviceTunnel = "0" / "1"  (set by hand or a script, as admin)
//
// Missing means allowed. Without a device certificate the server refuses it
// and the agent quietly checks again every couple of minutes.
func deviceTunnelAllowed() bool {
	for _, key := range []string{policyKey, settingsKey} {
		switch strings.ToLower(readString(key, "DeviceTunnel")) {
		case "0", "false", "off", "no":
			return false
		case "1", "true", "on", "yes":
			return true
		}
	}
	return true
}
