package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"syscall"
)

func hideWindow(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} }

// gatherLogs collects the Windows agent's logs and network settings.
func (a *agentService) gatherLogs(ctx context.Context) []logSource {
	dir := dataDir()
	return []logSource{
		{name: "agent.log", data: tailFile(filepath.Join(dir, "agent.log"), 1500<<10)},
		{name: "agent.log.old", data: tailFile(filepath.Join(dir, "agent.log.old"), 400<<10)},
		{name: "install.log", data: tailFile(filepath.Join(dir, "install.log"), 64<<10)},
		{name: "checks.txt", data: diagText(a.diagnose(ctx))},
		{name: "network/ipconfig.txt", data: commandOutput("ipconfig", "/all")},
		{name: "network/routes.txt", data: commandOutput("route", "print")},
		{name: "network/wifi.txt", data: commandOutput("netsh", "wlan", "show", "interfaces")},
		{name: "network/tunnel-service.txt", data: commandOutput("sc", "queryex", "WireGuardTunnel$SecureTunnel")},
	}
}