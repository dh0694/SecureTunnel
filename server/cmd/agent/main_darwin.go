//go:build darwin

// Command agent is the SecureTunnel agent. On the Mac one binary does three
// jobs:
//
//	securetunnel daemon    background service (root LaunchDaemon): VPN engine + WireGuard
//	securetunnel ui        per-user helper (LaunchAgent): serves the app window
//	securetunnel open      what SecureTunnel.app runs: opens the window
//	securetunnel version
package main

import (
	"fmt"
	"os"
)

var version = "dev"

func main() {
	cmd := "open"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "daemon":
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "the daemon must run as root (it's started by launchd)")
			os.Exit(1)
		}
		err = runDaemon()
	case "ui":
		err = runUI()
	case "open", "-psn":
		err = openApp()
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		if len(cmd) > 4 && cmd[:4] == "-psn" { // Finder launch argument on older macOS
			err = openApp()
			break
		}
		fmt.Fprintln(os.Stderr, "usage: securetunnel [daemon|ui|open|version]")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "securetunnel:", err)
		os.Exit(1)
	}
}
