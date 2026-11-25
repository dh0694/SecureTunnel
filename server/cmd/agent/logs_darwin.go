//go:build darwin

package main

import (
	"context"
	"os/exec"
	"path/filepath"
)

func hideWindow(*exec.Cmd) {}

// gatherLogs collects the Mac agent's logs and network settings.
func (a *agentDaemon) gatherLogs(ctx context.Context) []logSource {
	return []logSource{
		{name: "agent.log", data: tailFile(filepath.Join(appSupport, "agent.log"), 1500<<10)},
		{name: "agent.log.old", data: tailFile(filepath.Join(appSupport, "agent.log.old"), 400<<10)},
		{name: "daemon.err", data: tailFile(filepath.Join(appSupport, "daemon.err"), 128<<10)},
		{name: "checks.txt", data: diagText(a.diagnose(ctx))},
		{name: "network/ifconfig.txt", data: commandOutput("/sbin/ifconfig")},
		{name: "network/routes.txt", data: commandOutput("/usr/sbin/netstat", "-rn")},
		{name: "network/dns.txt", data: commandOutput("/usr/sbin/scutil", "--dns")},
		{name: "network/macos.txt", data: commandOutput("/usr/bin/sw_vers")},
	}
}