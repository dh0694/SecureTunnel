// Command agent is the SecureTunnel Windows agent (securetunnel.exe).
//
//	securetunnel.exe                         tray icon and window (run per user, at logon)
//	securetunnel.exe service                 the background service (run by Windows)
//	securetunnel.exe tunnel <conf>           a WireGuard tunnel service (run by Windows)
//	securetunnel.exe install [--server X] [--pin SHA256]
//	securetunnel.exe uninstall [--keep-settings]
//	securetunnel.exe version
package main

import (
	"fmt"
	"os"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "":
		runGUI()
	case "service":
		if err := runService(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "tunnel":
		if len(args) < 2 {
			os.Exit(2)
		}
		conf.PresetRootDirectory(dataDir())
		go serveBypass() // internet speed test, the one thing allowed outside the tunnel
		if err := tunnel.Run(args[1]); err != nil {
			logToFile("tunnel.log", "tunnel service failed: "+err.Error())
			os.Exit(1)
		}
	case "install":
		os.Exit(install(args[1:]))
	case "uninstall":
		os.Exit(uninstall(args[1:]))
	case "version", "--version", "-v":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", cmd)
		os.Exit(2)
	}
}
