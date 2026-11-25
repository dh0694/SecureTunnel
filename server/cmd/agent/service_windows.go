package main

import (
	"context"
	"strings"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"securetunnel/server/internal/agentcfg"
	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/clienttls"
)

// ---- the background service ----

type agentService struct {
	log    *slog.Logger
	engine *agentcore.Engine
	upd    *updater
	speed  *speedTester
	ips    *ipTracker
	notice noticeBox
	owner  winOwner // the Windows user who connected the tunnel

	mu         sync.Mutex
	trusts     map[string]*clienttls.Trust
	transports []*http.Transport
}

// resetConnections drops pooled HTTP connections. Called after the tunnel goes
// up or down: a connection opened over the old route would otherwise be reused
// and hang until it times out.
func (a *agentService) resetConnections() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.transports {
		t.CloseIdleConnections()
	}
}

func runService() error {
	if err := ensureDataDir(); err != nil {
		return err
	}
	logPath := filepath.Join(dataDir(), "agent.log")
	if st, err := os.Stat(logPath); err == nil && st.Size() > 5<<20 {
		_ = os.Rename(logPath, logPath+".old")
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	a := &agentService{log: slog.New(slog.NewTextHandler(f, nil)), trusts: map[string]*clienttls.Trust{}}
	return svc.Run(serviceName, a)
}

func (a *agentService) trust(server string) *clienttls.Trust {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.trusts[server]
	if !ok {
		t = &clienttls.Trust{Host: agentcfg.Host(server), Pins: regPins{server: server}}
		a.trusts[server] = t
	}
	return t
}

func (a *agentService) newAPI(server string) agentcore.API {
	return a.client(server)
}

// client talks to the server, falling back to the backup addresses when
// the main one can't be reached.
func (a *agentService) client(server string) *clientapi.Client {
	c := a.singleClient(server)
	for _, b := range backupServers() {
		if b != server {
			c.Fallbacks = append(c.Fallbacks, a.singleClient(b))
		}
	}
	return c
}

func (a *agentService) singleClient(server string) *clientapi.Client {
	tr := &http.Transport{
		TLSClientConfig:     a.trust(server).Config(),
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     30 * time.Second,
	}
	a.mu.Lock()
	a.transports = append(a.transports, tr)
	if len(a.transports) > 8 {
		a.transports = a.transports[len(a.transports)-8:]
	}
	a.mu.Unlock()
	return &clientapi.Client{Base: server, HTTP: &http.Client{Transport: tr, Timeout: 20 * time.Second},
		UserAgent: "SecureTunnel-Agent/" + version}
}

func (a *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	exe, _ := os.Executable()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.engine = agentcore.New(agentcore.Options{
		NewAPI:   a.newAPI,
		Tunnel:   &serviceTunnel{exe: exe, log: a.log},
		Store:    newStore(),
		BootID:   bootID,
		DeviceID: deviceID(),
		DeviceName: deviceName(),
		Platform: "windows",
		KeyGen: func() (string, string, error) {
			k, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return "", "", err
			}
			return k.String(), k.PublicKey().String(), nil
		},
		TrustedProbe: func(ctx context.Context) (bool, string) { return a.officeProbe(ctx) },
		NetFingerprint:  netFingerprint,
		OnNetworkChange: func(ctx context.Context, st agentcore.State) { a.onNetworkChange(ctx, st) },
		TrustMode: func() string {
			s, _ := configuredServer()
			if s == "" {
				return ""
			}
			return string(a.trust(s).LastMode())
		},
		Log:            a.log,
		Version:        version,
		OnTunnelChange: a.resetConnections,
		TrafficStats:   tunnelTraffic,
		Ping:           icmpPing,
		NetworkInfo:    cachedNetworkInfo,
		DiagExtra: func(d *clientapi.Diagnostics) {
			a.fillDiagnostics(d)
			d.WindowsUser = a.owner.get().Name
		},
		OnCommands:     a.handleCommands,
		DeviceProof:    a.deviceProof,
		DeviceTunnel:   deviceTunnelAllowed,
	})
	if s, locked := configuredServer(); s != "" {
		_ = a.engine.SetServer(s, locked)
	}
	a.engine.Restore()
	a.owner.load()
	go a.checkOwnerAfterRestore()
	go a.engine.Run(ctx)

	ln, err := listenPipe()
	if err != nil {
		a.log.Error("open control pipe", "err", err)
		return true, 1
	}
	a.upd = &updater{a: a}
	a.speed = &speedTester{a: a}
	a.ips = &ipTracker{a: a}
	go servePipe(ln, a)
	go a.upd.run(ctx)
	go a.speed.loop(ctx)
	go a.ips.loop(ctx)
	go a.cacheBackups(ctx)
	relaunchGUIIfUpdated(a.log.Warn)

	a.log.Info("service started", "version", version)
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptSessionChange}
	for c := range req {
		switch c.Cmd {
		case svc.Interrogate:
			status <- c.CurrentStatus
		case svc.SessionChange:
			// Windows sign-in, sign-out, user switch and lock (see winsession_windows.go).
			if c.EventData != 0 {
				n := *(**wtsSessionNotification)(unsafe.Pointer(&c.EventData))
				go a.onSessionChange(c.EventType, n.SessionID)
			}
		case svc.Stop, svc.Shutdown:
			status <- svc.Status{State: svc.StopPending}
			// The tunnel keeps running and the session stays saved, so a
			// service restart (e.g. an upgrade) picks up where it left off.
			_ = ln.Close()
			a.log.Info("service stopping")
			return false, 0
		}
	}
	return false, 0
}

// diagnose runs the checks shown on the Diagnose tab.
func (a *agentService) diagnose(ctx context.Context) []diagItem {
	var out []diagItem
	add := func(name string, ok bool, detail string) { out = append(out, diagItem{Name: name, OK: ok, Detail: detail}) }

	server, locked := configuredServer()
	if server == "" {
		add("Server address", false, "No server is set up yet. Enter it on the Settings tab.")
		return out
	}
	how := "set in the app"
	if locked {
		how = "set by your IT department"
	}
	add("Server address", true, server+" ("+how+")")

	host := agentcfg.Host(server)
	if net.ParseIP(host) == nil {
		start := time.Now()
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			add("Name lookup (DNS)", false, "This PC can't find "+host+". Check your internet connection.")
		} else {
			add("Name lookup (DNS)", true, fmt.Sprintf("Found %s at %s in %d ms", host, addrs[0], time.Since(start).Milliseconds()))
		}
	}

	c := a.client(server)
	start := time.Now()
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := c.Health(hctx)
	cancel()
	if err != nil {
		add("Server reachable", false, agentcore.Friendly(err))
	} else {
		mode := map[clienttls.Mode]string{
			clienttls.ModeSystem: "its certificate is trusted",
			clienttls.ModePinned: "its certificate matches the one saved on first connect",
			clienttls.ModeFirst:  "its certificate was saved now (first connection)",
		}[a.trust(server).LastMode()]
		add("Server reachable", true, fmt.Sprintf("Answered in %d ms; %s", time.Since(start).Milliseconds(), mode))
	}

	if backs := backupServers(); len(backs) > 0 {
		var up, down []string
		for _, b := range backs {
			bctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			err := a.singleClient(b).Health(bctx)
			cancel()
			if err != nil {
				down = append(down, agentcfg.Host(b))
			} else {
				up = append(up, agentcfg.Host(b))
			}
		}
		detail := ""
		if len(up) > 0 {
			detail = "Reachable: " + strings.Join(up, ", ")
		}
		if len(down) > 0 {
			if detail != "" {
				detail += ". "
			}
			detail += "Not reachable: " + strings.Join(down, ", ")
		}
		add("Backup servers", len(up) > 0, detail+". Used automatically if the main address is down.")
	}

	st := a.engine.Status()
	if st.GatewayEndpoint != "" {
		detail := "Connected through " + st.Gateway + " (" + st.GatewayEndpoint + ")"
		if st.LatencySource == "gateway" && st.LatencyMs > 0 {
			detail += fmt.Sprintf("; replies in %d ms through the tunnel", st.LatencyMs)
		}
		add("VPN gateway", st.State == agentcore.StateConnected, detail)
	}
	if st.ControlMs > 0 {
		add("Control server response", st.ControlMs < 2000, fmt.Sprintf(
			"Check-ins answered in %d ms. This includes Cloudflare and the server's own work, so it's normally higher than the gateway latency on the Status tab.", st.ControlMs))
	}
	exe, _ := os.Executable()
	if _, err := os.Stat(filepath.Join(filepath.Dir(exe), "wireguard.dll")); err != nil {
		add("VPN driver", false, "The WireGuard driver (wireguard.dll) is missing. Reinstall SecureTunnel.")
	} else {
		add("VPN driver", true, "WireGuard driver installed")
	}
	tun := &serviceTunnel{exe: exe, log: a.log}
	switch {
	case st.DeviceTunnel != nil:
		add("VPN tunnel", true, "Device tunnel only (before sign-in): just "+strings.Join(st.DeviceTunnel.Subnets, ", ")+
			" goes through the VPN, through "+st.DeviceTunnel.Gateway+". Connect to get the full VPN.")
	case tun.Running():
		add("VPN tunnel", true, "On: your traffic goes through the VPN")
	case st.OfficeMode:
		add("VPN tunnel", true, "On standby: you're on the office network, so traffic goes direct")
	case st.State == agentcore.StateDisconnected:
		add("VPN tunnel", true, "Off, because you're not connected")
	default:
		add("VPN tunnel", false, "Off although you should be connected. Disconnect and connect again.")
	}
	if st.OnTrustedNetwork {
		add("Office network", true, "This PC is on the office network, so the VPN isn't needed")
	}
	return out
}

// ---- install / uninstall (run by the installer, elevated) ----

func install(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	server := fs.String("server", "", "control server name or IP, e.g. vpn.example.com or 203.0.113.10")
	pin := fs.String("pin", "", "optional SHA-256 of the server's public key")
	backup := fs.String("backup", "", "optional backup addresses, comma separated")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(format string, a ...any) int {
		msg := fmt.Sprintf(format, a...)
		fmt.Fprintln(os.Stderr, msg)
		logToFile("install.log", msg)
		return 1
	}
	if err := ensureDataDir(); err != nil {
		return fail("create data folder: %v", err)
	}
	if *server != "" {
		s, err := agentcfg.NormalizeServer(*server)
		if err != nil {
			return fail("server %q: %v", *server, err)
		}
		if err := saveServer(s); err != nil {
			return fail("save server: %v", err)
		}
		if *pin != "" {
			if err := (regPins{server: s}).SetPin(clienttls.NormalizePin(*pin)); err != nil {
				return fail("save pin: %v", err)
			}
		}
	}
	if *backup != "" {
		var list []string
		for _, b := range strings.Split(*backup, ",") {
			n, err := agentcfg.NormalizeServer(strings.TrimSpace(b))
			if err != nil {
				return fail("backup server %q: %v", b, err)
			}
			list = append(list, n)
		}
		if err := writeString(settingsKey, "BackupServers", strings.Join(list, ",")); err != nil {
			return fail("save backup servers: %v", err)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		return fail("find exe: %v", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fail("open service manager: %v", err)
	}
	defer m.Disconnect()
	removeService(m, serviceName)
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  "SecureTunnel",
		Description:  "Keeps the SecureTunnel VPN connected.",
	}, "service")
	if err != nil {
		return fail("create service: %v", err)
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400)
	if err := s.Start(); err != nil {
		return fail("start service: %v", err)
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err == nil {
		_ = k.SetStringValue("SecureTunnel", `"`+exe+`"`)
		k.Close()
	}
	logToFile("install.log", "installed "+version)
	return 0
}

func uninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	keep := fs.Bool("keep-settings", false, "keep the server address and certificate pin (used by upgrades)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	m, err := mgr.Connect()
	if err == nil {
		removeService(m, serviceName)
		m.Disconnect()
	}
	exe, _ := os.Executable()
	_ = (&serviceTunnel{exe: exe, log: slog.New(slog.NewTextHandler(os.Stderr, nil))}).Down()
	deleteValue(runKey, "SecureTunnel")
	if !*keep {
		// A real uninstall forgets the session. An upgrade keeps it, so the new
		// version resumes the connection without a new sign-in.
		_ = newStore().Clear()
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, settingsKey)
	}
	return 0
}

func removeService(m *mgr.Mgr, name string) {
	s, err := m.OpenService(name)
	if err != nil {
		return
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		for i := 0; i < 80; i++ {
			st, err := s.Query()
			if err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	_ = s.Delete()
	for i := 0; i < 40; i++ {
		s2, err := m.OpenService(name)
		if err != nil {
			return
		}
		s2.Close()
		time.Sleep(250 * time.Millisecond)
	}
}

// cacheBackups saves the backup addresses the server sends, so they're known
// even when the main address can't be reached later.
func (a *agentService) cacheBackups(ctx context.Context) {
	path := filepath.Join(dataDir(), "backup-servers.json")
	last := ""
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		if s, ok := a.engine.CurrentSession(); ok {
			list := s.Placement.BackupServers
			if list == nil {
				list = []string{}
			}
			b, _ := json.Marshal(list)
			if string(b) != last {
				if err := os.WriteFile(path, b, 0o644); err == nil {
					last = string(b)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
