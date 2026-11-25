//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"securetunnel/server/internal/agentcfg"
	"securetunnel/server/internal/agentcore"
	"securetunnel/server/internal/clientapi"
	"securetunnel/server/internal/clienttls"
	"securetunnel/server/internal/model"
)

// The Mac daemon (root, LaunchDaemon com.securetunnel.agent) runs the same
// connection engine as the Windows service, with WireGuard in-process, and
// answers the app over a Unix socket using the same JSON protocol as the
// Windows named pipe.

type agentDaemon struct {
	log    *slog.Logger
	engine *agentcore.Engine
	tun    *macTunnel
	upd    *macUpdater
	notice noticeBox

	mu         sync.Mutex
	trusts     map[string]*clienttls.Trust
	transports []*http.Transport
}

func runDaemon() error {
	if err := ensureDataDir(); err != nil {
		return err
	}
	logPath := filepath.Join(appSupport, "agent.log")
	if st, err := os.Stat(logPath); err == nil && st.Size() > 5<<20 {
		_ = os.Rename(logPath, logPath+".old")
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	a := &agentDaemon{log: slog.New(slog.NewTextHandler(f, nil)), trusts: map[string]*clienttls.Trust{}}
	a.tun = &macTunnel{log: a.log}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.engine = agentcore.New(agentcore.Options{
		NewAPI:     func(server string) agentcore.API { return a.client(server) },
		Tunnel:     a.tun,
		Store:      newStore(),
		BootID:     bootID,
		DeviceID:   deviceID(),
		DeviceName: deviceName(),
		Platform:   "macos",
		KeyGen: func() (string, string, error) {
			k, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return "", "", err
			}
			return k.String(), k.PublicKey().String(), nil
		},
		TrustedProbe: a.officeProbe,
		// Addresses only: cheap to read every 2 s (scutil for DNS is not).
		NetFingerprint: func() string { ips := physicalIPs(); sort.Strings(ips); return strings.Join(ips, ",") },
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
		TrafficStats:   a.tun.traffic,
		NetworkInfo:    cachedNetworkInfo,
		DiagExtra: func(d *clientapi.Diagnostics) {
			d.OS = macOSVersion()
		},
		OnCommands:  a.handleCommands,
		DeviceProof: a.deviceProof,
	})
	if s, locked := configuredServer(); s != "" {
		_ = a.engine.SetServer(s, locked)
	}
	a.engine.Restore()
	go a.engine.Run(ctx)

	a.upd = &macUpdater{a: a}
	go a.upd.run(ctx)

	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	// Any logged-in user may drive their VPN (like the Windows pipe).
	_ = os.Chmod(socketPath, 0o666)
	a.log.Info("daemon started", "version", version)
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go a.handleConn(c)
	}
}

func (a *agentDaemon) resetConnections() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range a.transports {
		t.CloseIdleConnections()
	}
}

func (a *agentDaemon) trust(server string) *clienttls.Trust {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.trusts[server]
	if !ok {
		t = &clienttls.Trust{Host: agentcfg.Host(server), Pins: filePins{server: server}}
		a.trusts[server] = t
	}
	return t
}

func (a *agentDaemon) client(server string) *clientapi.Client {
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

// deviceProof sends the Mac's join state (Macs have no Entra device
// certificate the daemon can use, so there are no proofs).
func (a *agentDaemon) deviceProof(context.Context, clientapi.Challenge) ([]clientapi.DeviceProof, *clientapi.JoinInfo) {
	return nil, &clientapi.JoinInfo{}
}

// ---- IPC (same JSON as the Windows pipe) ----

type ipcRequest struct {
	Cmd       string                  `json:"cmd"`
	Username  string                  `json:"username,omitempty"`
	Password  string                  `json:"password,omitempty"`
	Code      string                  `json:"code,omitempty"`
	Server    string                  `json:"server,omitempty"`
	ID        string                  `json:"id,omitempty"`
	Token     string                  `json:"token,omitempty"`
	Challenge *clientapi.Challenge    `json:"challenge,omitempty"`
	Proofs    []clientapi.DeviceProof `json:"proofs,omitempty"`
}

type diagItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type UpdateInfo struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest,omitempty"`
	State     string    `json:"state"`
	Message   string    `json:"message,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

type ipcResponse struct {
	OK        bool                  `json:"ok"`
	Error     string                `json:"error,omitempty"`
	ErrorCode string                `json:"error_code,omitempty"`
	Status    *agentcore.Status     `json:"status,omitempty"`
	Diag      []diagItem            `json:"diag,omitempty"`
	Update    *UpdateInfo           `json:"update,omitempty"`
	Notice    *Notice               `json:"notice,omitempty"`
	Auth      *clientapi.AuthConfig `json:"auth,omitempty"`
	Challenge *clientapi.Challenge  `json:"challenge,omitempty"`
	LogRef    string                `json:"log_ref,omitempty"`
}

func (a *agentDaemon) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(200 * time.Second))
	var req ipcRequest
	if err := json.NewDecoder(c).Decode(&req); err != nil {
		return
	}
	_ = json.NewEncoder(c).Encode(a.handle(req))
}

func extraFrom(req ipcRequest) agentcore.ConnectExtra {
	x := agentcore.ConnectExtra{Challenge: req.Challenge}
	for _, p := range req.Proofs {
		if p.Kind == "user_cert" {
			x.Proofs = append(x.Proofs, p)
		}
	}
	return x
}

func (a *agentDaemon) handle(req ipcRequest) ipcResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	e := a.engine
	errResp := func(err error) ipcResponse {
		r := ipcResponse{Error: agentcore.Friendly(err)}
		var ae *clientapi.APIError
		if errors.As(err, &ae) {
			r.ErrorCode = ae.Code
			if ae.Code == "code_required" {
				r.Error = "Enter the code from your authenticator app."
			}
		} else if err != nil && !errors.Is(err, agentcore.ErrBusy) {
			r.Error = err.Error()
			if f := agentcore.Friendly(err); f != "Couldn't connect: "+err.Error() {
				r.Error = f
			}
		}
		st := e.Status()
		r.Status = &st
		return r
	}
	switch req.Cmd {
	case "status":
	case "connect":
		if err := e.Connect(ctx, req.Username, req.Password, req.Code, extraFrom(req)); err != nil {
			return errResp(err)
		}
	case "connect_token":
		if err := e.ConnectWithToken(ctx, req.Username, req.Token, extraFrom(req)); err != nil {
			return errResp(err)
		}
	case "auth_config", "challenge":
		server, _ := configuredServer()
		if server == "" {
			return errResp(errors.New("no server is set up yet"))
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if req.Cmd == "challenge" {
			ch, err := a.client(server).Challenge(cctx)
			if err != nil {
				return errResp(err)
			}
			return ipcResponse{OK: true, Challenge: &ch}
		}
		cfg, err := a.client(server).AuthConfig(cctx)
		if clientapi.HasStatus(err, 404) {
			cfg, err = clientapi.AuthConfig{Local: true}, nil
		}
		if err != nil {
			return errResp(err)
		}
		st := e.Status()
		return ipcResponse{OK: true, Status: &st, Auth: &cfg}
	case "disconnect":
		if err := e.Disconnect(ctx); err != nil {
			return errResp(err)
		}
	case "set_server":
		if _, locked := configuredServer(); locked {
			return errResp(errors.New("the server is set by your IT department"))
		}
		s, err := agentcfg.NormalizeServer(req.Server)
		if err != nil {
			return errResp(err)
		}
		if err := e.SetServer(s, false); err != nil {
			return errResp(err)
		}
		if err := saveServer(s); err != nil {
			return errResp(err)
		}
	case "diagnose":
		st := e.Status()
		return ipcResponse{OK: true, Status: &st, Diag: a.diagnose(ctx)}
	case "check_update":
		a.upd.check(ctx)
	case "install_update":
		if err := a.upd.requestInstall(); err != nil {
			return errResp(err)
		}
	case "speedtest":
		return errResp(errors.New("speed tests aren't available on the Mac app yet"))
	case "send_logs":
		ref, err := sendLogs(ctx, e, a.client, deviceID(), "user", a.gatherLogs)
		if err != nil {
			return errResp(err)
		}
		st := e.Status()
		return ipcResponse{OK: true, Status: &st, LogRef: ref}
	case "dismiss_notice":
		a.notice.dismiss(req.ID)
	default:
		return ipcResponse{Error: "unknown command"}
	}
	st := e.Status()
	ui := a.upd.info()
	return ipcResponse{OK: true, Status: &st, Update: &ui, Notice: a.notice.get()}
}

// ---- admin commands ----

type Notice struct {
	ID   string    `json:"id"`
	Text string    `json:"text"`
	From string    `json:"from"`
	At   time.Time `json:"at"`
}

type noticeBox struct {
	mu sync.Mutex
	n  *Notice
}

func (b *noticeBox) get() *Notice {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n == nil {
		return nil
	}
	n := *b.n
	return &n
}

func (b *noticeBox) set(n Notice) {
	b.mu.Lock()
	b.n = &n
	b.mu.Unlock()
}

func (b *noticeBox) dismiss(id string) {
	b.mu.Lock()
	if b.n != nil && (id == "" || b.n.ID == id) {
		b.n = nil
	}
	b.mu.Unlock()
}

func (a *agentDaemon) handleCommands(cmds []clientapi.Command) {
	for _, c := range cmds {
		a.log.Info("admin command", "type", c.Type, "from", c.From)
		switch c.Type {
		case "diagnostics":
			a.engine.Kick()
		case "move":
			a.engine.RequestMove(c.Text)
		case "logs":
			go func() {
				ref, err := sendLogs(context.Background(), a.engine, a.client, deviceID(), "admin", a.gatherLogs)
				a.log.Info("logs collected by IT", "ref", ref, "err", err)
			}()
		case "message":
			if c.Text != "" {
				a.notice.set(Notice{ID: c.ID, Text: c.Text, From: c.From, At: c.At})
				notifyUsers("Message from IT", c.Text)
			}
		}
	}
}

// notifyUsers shows a macOS notification to the logged-in user.
func notifyUsers(title, text string) {
	uid := consoleUID()
	if uid == "" {
		return
	}
	script := fmt.Sprintf("display notification %q with title %q", text, title)
	_ = exec.Command("/bin/launchctl", "asuser", uid, "/usr/bin/osascript", "-e", script).Start()
}

// consoleUID is the uid of the user at the Mac's screen ("" if none).
func consoleUID() string {
	out, err := exec.Command("/usr/bin/stat", "-f", "%u", "/dev/console").Output()
	if err != nil {
		return ""
	}
	uid := strings.TrimSpace(string(out))
	if uid == "0" {
		return ""
	}
	return uid
}

// ---- office detection ----

var officeMu sync.Mutex

func officeCachePath() string { return filepath.Join(appSupport, "office-networks.json") }

func (a *agentDaemon) officePolicy() model.OfficeNetworkPolicy {
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

func (a *agentDaemon) officeProbe(context.Context) (bool, string) {
	return a.officePolicy().Match(dnsSuffixes(), physicalIPs(), "")
}

// dnsSuffixes lists the search domains of the Mac's networks (not ours).
func dnsSuffixes() []string {
	out, err := exec.Command("/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var list []string
	for _, line := range strings.Split(string(out), "\n") {
		l := strings.TrimSpace(line)
		var v string
		switch {
		case strings.HasPrefix(l, "search domain["):
			_, v, _ = strings.Cut(l, ":")
		case strings.HasPrefix(l, "domain "):
			_, v, _ = strings.Cut(l, ":")
		default:
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && !seen[v] && !strings.HasSuffix(v, ".arpa") && v != "local" {
			seen[v] = true
			list = append(list, v)
		}
	}
	return list
}

// physicalIPs lists the IPv4 addresses on the Mac's own network interfaces.
func physicalIPs() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || strings.HasPrefix(i.Name, "utun") {
			continue
		}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			if ipn, ok := ad.(*net.IPNet); ok && ipn.IP.To4() != nil {
				out = append(out, ipn.IP.String())
			}
		}
	}
	return out
}

// ---- network info and diagnostics ----

var (
	netMu   sync.Mutex
	netAt   time.Time
	netLast agentcore.NetInfo
)

func cachedNetworkInfo() agentcore.NetInfo {
	netMu.Lock()
	defer netMu.Unlock()
	if time.Since(netAt) < 15*time.Second {
		return netLast
	}
	netAt = time.Now()
	_, iface := defaultRoute()
	if strings.HasPrefix(iface, "utun") {
		iface = "" // connected: the physical interface is behind the tunnel
	}
	if iface == "" {
		iface = firstPhysicalInterface()
	}
	n := agentcore.NetInfo{Adapter: iface, Kind: "Network"}
	if out, err := exec.Command("/usr/sbin/networksetup", "-listallhardwareports").Output(); err == nil {
		port := ""
		for _, line := range strings.Split(string(out), "\n") {
			if v, ok := strings.CutPrefix(line, "Hardware Port: "); ok {
				port = v
			}
			if v, ok := strings.CutPrefix(line, "Device: "); ok && v == iface {
				switch {
				case strings.Contains(port, "Wi-Fi"):
					n.Kind = "Wi-Fi"
				case strings.Contains(port, "Ethernet") || strings.Contains(port, "Thunderbolt") || strings.Contains(port, "LAN"):
					n.Kind = "Ethernet"
				case strings.Contains(port, "iPhone"):
					n.Kind = "Cellular"
				default:
					n.Kind = port
				}
			}
		}
	}
	netLast = n
	return n
}

func firstPhysicalInterface() string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp != 0 && i.Flags&net.FlagLoopback == 0 && strings.HasPrefix(i.Name, "en") {
			if addrs, _ := i.Addrs(); len(addrs) > 0 {
				return i.Name
			}
		}
	}
	return ""
}

func macOSVersion() string {
	out, err := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
	if err != nil {
		return "macOS"
	}
	return "macOS " + strings.TrimSpace(string(out))
}

func (a *agentDaemon) diagnose(ctx context.Context) []diagItem {
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
			add("Name lookup (DNS)", false, "This Mac can't find "+host+". Check your internet connection.")
		} else {
			add("Name lookup (DNS)", true, fmt.Sprintf("Found %s at %s in %d ms", host, addrs[0], time.Since(start).Milliseconds()))
		}
	}
	start := time.Now()
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := a.client(server).Health(hctx)
	cancel()
	if err != nil {
		add("Server reachable", false, agentcore.Friendly(err))
	} else {
		add("Server reachable", true, fmt.Sprintf("Answered in %d ms", time.Since(start).Milliseconds()))
	}
	st := a.engine.Status()
	if st.GatewayEndpoint != "" {
		add("VPN gateway", st.State == agentcore.StateConnected, "Connected through "+st.Gateway+" ("+st.GatewayEndpoint+")")
	}
	switch {
	case a.tun.Running():
		add("VPN tunnel", true, "On: your traffic goes through the VPN")
	case st.OfficeMode:
		add("VPN tunnel", true, "On standby: you're on the office network, so traffic goes direct")
	case st.State == agentcore.StateDisconnected:
		add("VPN tunnel", true, "Off, because you're not connected")
	default:
		add("VPN tunnel", false, "Off although you should be connected. Disconnect and connect again.")
	}
	if st.OnTrustedNetwork {
		add("Office network", true, "This Mac is on the office network, so the VPN isn't needed")
	}
	return out
}

// pipeCall sends one request to the daemon (used by the app's UI process).
func pipeCall(req ipcRequest, timeout time.Duration) (ipcResponse, error) {
	c, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return ipcResponse{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return ipcResponse{}, err
	}
	var resp ipcResponse
	err = json.NewDecoder(c).Decode(&resp)
	return resp, err
}
