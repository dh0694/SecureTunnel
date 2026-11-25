// Command gatewayagent runs on each WireGuard gateway. It creates and configures
// the WireGuard interface, pulls the desired peer set from the control server,
// reconciles the interface to match, and reports health.
//
// If the control server is unreachable, the agent keeps its last known peer set
// (also persisted to disk, so it survives an agent restart) and removes each peer
// only at its absolute session expiry. Existing tunnels keep working.
//
// Subcommands:
//
//	gatewayagent          run the agent
//	gatewayagent genkey   print a new WireGuard private key and its public key
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"securetunnel/server/internal/hostmetrics"
	"securetunnel/server/internal/model"
)

type config struct {
	ControlURL  string
	Token       string
	CAFile      string
	Interface   string
	ListenPort  int
	PrivateKey  wgtypes.Key
	MTU         int
	Poll        time.Duration
	HealthEvery time.Duration
	StateFile   string
	LabNATIface string // if set, masquerade tunnel traffic out this interface (lab only)
}

type peer struct {
	SessionID  string    `json:"session_id"`
	PublicKey  string    `json:"public_key"`
	AllowedIPs []string  `json:"allowed_ips"`
	ExpiresAt  time.Time `json:"expires_at"`
	UPN        string    `json:"upn"`
	Device     bool      `json:"device,omitempty"`      // pre-logon device tunnel
	RestrictTo []string  `json:"restrict_to,omitempty"` // device tunnels: the only destinations forwarded
}

type peerSet struct {
	GatewayID   string    `json:"gateway_id"`
	GatewayAddr string    `json:"gateway_address"`
	GeneratedAt time.Time `json:"generated_at"`
	Peers       []peer    `json:"peers"`
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "genkey" {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("private_key=%s\npublic_key=%s\n", k, k.PublicKey())
		return
	}
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func loadConfig() (config, error) {
	c := config{
		ControlURL:  strings.TrimRight(os.Getenv("GA_CONTROL_URL"), "/"),
		CAFile:      os.Getenv("GA_CA_FILE"),
		Interface:   envOr("GA_INTERFACE", "wg0"),
		StateFile:   envOr("GA_STATE_FILE", "/var/lib/securetunnel/peers.json"),
		LabNATIface: os.Getenv("GA_LAB_NAT_IFACE"),
	}
	var errs []error
	if c.ControlURL == "" {
		errs = append(errs, errors.New("GA_CONTROL_URL is required"))
	}
	if strings.ContainsAny(c.Interface, " \t\r\n\v\f\\\"'!#") {
		errs = append(errs, errors.New("GA_INTERFACE contains characters unsupported by iptables-restore"))
	}
	tok, err := readSecret("GA_TOKEN", "GA_TOKEN_FILE")
	if err != nil {
		errs = append(errs, err)
	}
	c.Token = tok
	keyStr, err := readSecret("GA_PRIVATE_KEY", "GA_PRIVATE_KEY_FILE")
	if err != nil {
		errs = append(errs, err)
	} else if c.PrivateKey, err = wgtypes.ParseKey(keyStr); err != nil {
		errs = append(errs, fmt.Errorf("private key: %w", err))
	}
	c.ListenPort, err = strconv.Atoi(envOr("GA_LISTEN_PORT", "51820"))
	if err != nil {
		errs = append(errs, fmt.Errorf("GA_LISTEN_PORT: %w", err))
	}
	c.MTU, err = strconv.Atoi(envOr("GA_MTU", "1420"))
	if err != nil {
		errs = append(errs, fmt.Errorf("GA_MTU: %w", err))
	}
	if c.Poll, err = time.ParseDuration(envOr("GA_POLL", "5s")); err != nil {
		errs = append(errs, fmt.Errorf("GA_POLL: %w", err))
	}
	if c.HealthEvery, err = time.ParseDuration(envOr("GA_HEALTH_EVERY", "15s")); err != nil {
		errs = append(errs, fmt.Errorf("GA_HEALTH_EVERY: %w", err))
	}
	return c, errors.Join(errs...)
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpc, err := newHTTPClient(cfg.CAFile)
	if err != nil {
		return err
	}
	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("open wireguard control: %w", err)
	}
	defer wg.Close()

	blockForwarding := [][]string{{"-j", "DROP"}}
	if err := applyRestrictions(cfg.Interface, blockForwarding); err != nil {
		return fmt.Errorf("block forwarding until device tunnel policy is installed: %w", err)
	}
	if err := ensureInterface(wg, cfg); err != nil {
		return err
	}
	log.Info("interface ready", "iface", cfg.Interface, "port", cfg.ListenPort, "public_key", cfg.PrivateKey.PublicKey().String())

	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(b)) != "1" {
		log.Error("IPv4 forwarding is off on this host; tunnel traffic will not be routed. Run: sysctl -w net.ipv4.ip_forward=1")
	}
	// Older versions enforced the subnet policy in the filter table. Remove
	// those jumps while the new policy still blocks forwarding.
	for _, suffix := range []string{"", "-N"} {
		dropRules([][]string{{"-I", "FORWARD", "-i", cfg.Interface, "-j", restrictChain + "-" + cfg.Interface + suffix}})
	}
	if err := setupForwarding(cfg.Interface); err != nil {
		log.Warn("firewall forwarding setup failed", "err", err)
	}

	// Start from the persisted peer set so a restart during a control-plane
	// outage does not drop anyone.
	current, _ := loadState(cfg.StateFile)
	addrApplied := ""
	natApplied := "" // the pool currently masqueraded (lab NAT)
	restrictApplied := ""
	forwardingReady := false
	lastContact := time.Time{}

	poll := time.NewTicker(cfg.Poll)
	health := time.NewTicker(cfg.HealthEvery)
	defer poll.Stop()
	defer health.Stop()

	reconcileOnce := func() {
		ps, err := fetchPeers(ctx, httpc, cfg)
		if err != nil {
			if time.Since(lastContact) > 30*time.Second {
				log.Warn("control server unreachable; keeping last known peers", "err", err, "last_contact", lastContact)
			}
			ps = current
		} else {
			lastContact = time.Now()
			current = ps
			if err := saveState(cfg.StateFile, ps); err != nil {
				log.Warn("save state", "err", err)
			}
		}
		if ps.GatewayAddr != "" && ps.GatewayAddr != addrApplied {
			if err := setAddress(cfg.Interface, ps.GatewayAddr); err != nil {
				log.Error("set interface address", "addr", ps.GatewayAddr, "err", err)
			} else {
				addrApplied = ps.GatewayAddr
				log.Info("interface address set", "addr", ps.GatewayAddr)
				if cfg.LabNATIface != "" {
					pool, err := netip.ParsePrefix(ps.GatewayAddr)
					if err != nil {
						log.Error("lab NAT: bad gateway address", "addr", ps.GatewayAddr, "err", err)
					} else {
						p := pool.Masked().String()
						if natApplied != "" && natApplied != p { // the range changed: stop masquerading the old one
							dropRules(labNATRules(natApplied, cfg.LabNATIface))
						}
						if err := labNAT(p, cfg.LabNATIface); err != nil {
							log.Error("lab NAT setup failed", "err", err)
						} else {
							natApplied = p
							log.Warn("LAB NAT enabled: client pool is masqueraded; production should route without NAT",
								"pool", p, "out", cfg.LabNATIface)
						}
					}
				}
			}
		}
		now := time.Now()
		rules := restrictRules(ps.Peers, now)
		restrictions := strings.Join(flatten(rules), "|")
		if forwardingReady && restrictions != restrictApplied {
			// The old peer may still be present when its address is assigned
			// to a different peer. Permit forwarding only after both updates.
			if err := applyRestrictions(cfg.Interface, blockForwarding); err != nil {
				log.Error("pause forwarding for device tunnel policy change", "err", err)
				return
			}
			forwardingReady = false
		}
		added, removed, err := reconcile(wg, cfg.Interface, ps.Peers, now)
		if err != nil {
			log.Error("reconcile", "err", err)
			return
		}
		if added+removed > 0 {
			log.Info("peers reconciled", "added_or_updated", added, "removed", removed, "desired", len(ps.Peers))
		}
		if !forwardingReady {
			if err := applyRestrictions(cfg.Interface, rules); err != nil {
				log.Error("device tunnel firewall rules; forwarding remains blocked", "err", err)
				return
			}
			restrictApplied, forwardingReady = restrictions, true
			log.Info("device tunnel firewall rules applied", "rules", len(rules))
		}
	}

	reconcileOnce()
	if forwardingReady {
		reportHealth(ctx, httpc, cfg, wg, log)
	}
	for {
		select {
		case <-ctx.Done():
			log.Info("shutting down; leaving interface and peers in place")
			return nil
		case <-poll.C:
			reconcileOnce()
		case <-health.C:
			if forwardingReady {
				reportHealth(ctx, httpc, cfg, wg, log)
			}
		}
	}
}

// ensureInterface creates the WireGuard link if needed and sets its key and port.
func ensureInterface(wg *wgctrl.Client, cfg config) error {
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = cfg.Interface
		attrs.MTU = cfg.MTU
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: attrs}); err != nil {
			return fmt.Errorf("create %s (is the wireguard kernel module available?): %w", cfg.Interface, err)
		}
		if link, err = netlink.LinkByName(cfg.Interface); err != nil {
			return err
		}
	}
	if err := wg.ConfigureDevice(cfg.Interface, wgtypes.Config{
		PrivateKey: &cfg.PrivateKey,
		ListenPort: &cfg.ListenPort,
	}); err != nil {
		return fmt.Errorf("configure %s: %w", cfg.Interface, err)
	}
	_ = netlink.LinkSetMTU(link, cfg.MTU)
	return netlink.LinkSetUp(link)
}

func setAddress(iface, cidr string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return err
	}
	// The range can be changed on the admin site: drop any other IPv4
	// address left from the previous range.
	old, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil // the new address is in place; leftovers are harmless
	}
	for _, a := range old {
		if !a.IP.Equal(addr.IP) || a.Mask.String() != addr.Mask.String() {
			_ = netlink.AddrDel(link, &a)
		}
	}
	return nil
}

// dropRules removes iptables rules (written with -A or -I) if present.
func dropRules(rules [][]string) {
	for _, r := range rules {
		del := append([]string{}, r...)
		for i, a := range del {
			if a == "-A" || a == "-I" {
				del[i] = "-D"
			}
		}
		for exec.Command("iptables", del...).Run() == nil { // remove every copy
		}
	}
}

// reconcile makes the interface's peers match the desired set without touching
// peers that are already correct, so their handshakes and sessions are kept.
// Desired peers past their absolute expiry are treated as absent.
func reconcile(wg *wgctrl.Client, iface string, desired []peer, now time.Time) (changed, removed int, err error) {
	dev, err := wg.Device(iface)
	if err != nil {
		return 0, 0, err
	}
	want := map[wgtypes.Key][]net.IPNet{}
	for _, p := range desired {
		if now.After(p.ExpiresAt) {
			continue
		}
		k, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			continue
		}
		var ips []net.IPNet
		for _, a := range p.AllowedIPs {
			if _, n, err := net.ParseCIDR(a); err == nil {
				ips = append(ips, *n)
			}
		}
		want[k] = ips
	}

	var cfgs []wgtypes.PeerConfig
	have := map[wgtypes.Key]bool{}
	for _, p := range dev.Peers {
		have[p.PublicKey] = true
		ips, ok := want[p.PublicKey]
		if !ok {
			cfgs = append(cfgs, wgtypes.PeerConfig{PublicKey: p.PublicKey, Remove: true})
			removed++
			continue
		}
		if !sameIPs(p.AllowedIPs, ips) {
			cfgs = append(cfgs, wgtypes.PeerConfig{PublicKey: p.PublicKey, ReplaceAllowedIPs: true, AllowedIPs: ips})
			changed++
		}
	}
	for k, ips := range want {
		if !have[k] {
			cfgs = append(cfgs, wgtypes.PeerConfig{PublicKey: k, ReplaceAllowedIPs: true, AllowedIPs: ips})
			changed++
		}
	}
	if len(cfgs) == 0 {
		return 0, 0, nil
	}
	return changed, removed, wg.ConfigureDevice(iface, wgtypes.Config{Peers: cfgs})
}

func sameIPs(a, b []net.IPNet) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, n := range a {
		seen[n.String()] = true
	}
	for _, n := range b {
		if !seen[n.String()] {
			return false
		}
	}
	return true
}

func fetchPeers(ctx context.Context, c *http.Client, cfg config) (peerSet, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ControlURL+"/v1/gateway/peers", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	resp, err := c.Do(req)
	if err != nil {
		return peerSet{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return peerSet{}, fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var ps peerSet
	err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&ps)
	return ps, err
}

// traffic tracks WireGuard byte counters between health reports.
type traffic struct {
	rx, tx uint64
	at     time.Time
}

var (
	sampler  = &hostmetrics.Sampler{DiskPath: "/", Label: os.Getenv("GA_HOST_LABEL")}
	lastTraf traffic
)

func reportHealth(ctx context.Context, c *http.Client, cfg config, wg *wgctrl.Client, log *slog.Logger) {
	dev, err := wg.Device(cfg.Interface)
	if err != nil {
		log.Error("read device", "err", err)
		return
	}
	m := sampler.Sample()
	var rx, tx uint64
	now := time.Now()
	for _, p := range dev.Peers {
		rx += uint64(p.ReceiveBytes)
		tx += uint64(p.TransmitBytes)
		if !p.LastHandshakeTime.IsZero() && now.Sub(p.LastHandshakeTime) < 3*time.Minute {
			m.Handshakes++
		}
	}
	if !lastTraf.at.IsZero() {
		secs := now.Sub(lastTraf.at).Seconds()
		if secs > 0 && rx >= lastTraf.rx && tx >= lastTraf.tx { // counters reset when peers are removed
			m.NetRxBps = float64(rx-lastTraf.rx) * 8 / secs
			m.NetTxBps = float64(tx-lastTraf.tx) * 8 / secs
		}
	}
	lastTraf = traffic{rx: rx, tx: tx, at: now}

	b, _ := json.Marshal(struct {
		ActivePeers int               `json:"active_peers"`
		Metrics     model.HostMetrics `json:"metrics"`
	}{len(dev.Peers), m})
	body := string(b)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ControlURL+"/v1/gateway/health", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return // fetchPeers already logs control-plane outages
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		log.Warn("health report rejected", "status", resp.StatusCode)
	}
}

func newHTTPClient(caFile string) (*http.Client, error) {
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		tcfg.RootCAs = pool
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tcfg}}, nil
}

func loadState(path string) (peerSet, error) {
	var ps peerSet
	b, err := os.ReadFile(path)
	if err != nil {
		return ps, err
	}
	err = json.Unmarshal(b, &ps)
	return ps, err
}

func saveState(path string, ps peerSet) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(ps)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// setupForwarding allows routed traffic to and from the WireGuard interface.
// Docker sets the host's FORWARD policy to DROP, so without these rules a
// gateway on a Docker host forwards nothing. The firewall beyond the gateway
// remains the real enforcement point.
func setupForwarding(wgIface string) error {
	return ensureRules([][]string{
		{"-I", "FORWARD", "-i", wgIface, "-j", "ACCEPT"},
		{"-I", "FORWARD", "-o", wgIface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	})
}

// restrictChain applies the outbound forwarding policy before the filter table
// handles general forwarding and established connections.
const restrictChain = "ST-DEVICE" // + "-<interface>", e.g. ST-DEVICE-wg0

// restrictRules builds the chain's rules (without "-A chain") for the desired peers.
func restrictRules(peers []peer, now time.Time) [][]string {
	var out [][]string
	for _, p := range peers {
		if !p.Device || now.After(p.ExpiresAt) {
			continue
		}
		for _, src := range p.AllowedIPs {
			if ip, _, err := net.ParseCIDR(src); err != nil || ip.To4() == nil {
				continue
			}
			for _, dst := range p.RestrictTo {
				if ip, _, err := net.ParseCIDR(dst); err != nil || ip.To4() == nil {
					continue
				}
				out = append(out, []string{"-s", src, "-d", dst, "-j", "RETURN"})
			}
			out = append(out, []string{"-s", src, "-j", "DROP"})
		}
	}
	return out
}

func flatten(rules [][]string) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, strings.Join(r, " "))
	}
	return out
}

// applyRestrictions replaces only this gateway's chain in one transaction.
func applyRestrictions(wgIface string, rules [][]string) error {
	chain := restrictChain + "-" + wgIface
	var batch strings.Builder
	fmt.Fprintf(&batch, "*mangle\n:%s - [0:0]\n-F %s\n", chain, chain)
	jump := []string{"FORWARD", "-i", wgIface, "-j", chain}
	if exec.Command("iptables", append([]string{"-w", "-t", "mangle", "-C"}, jump...)...).Run() == nil {
		fmt.Fprintf(&batch, "-D %s\n", strings.Join(jump, " "))
	}
	fmt.Fprintf(&batch, "-I FORWARD 1 -i %s -j %s\n", wgIface, chain)
	for _, r := range rules {
		fmt.Fprintf(&batch, "-A %s %s\n", chain, strings.Join(r, " "))
	}
	batch.WriteString("COMMIT\n")
	cmd := exec.Command("iptables-restore", "-w", "--noflush")
	cmd.Stdin = strings.NewReader(batch.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables-restore %s: %w: %s", chain, err, out)
	}
	return nil
}

// labNAT masquerades traffic from the client pool out one interface, for lab
// setups where the core network has no route back to the pool. Only the pool's
// source addresses are touched, so other services on the host are unaffected.
// Production gateways route without NAT so the firewall sees real tunnel IPs.
func labNAT(pool, outIface string) error { return ensureRules(labNATRules(pool, outIface)) }

func labNATRules(pool, outIface string) [][]string {
	return [][]string{{"-t", "nat", "-A", "POSTROUTING", "-s", pool, "-o", outIface, "-j", "MASQUERADE"}}
}

// ensureRules adds each iptables rule unless an identical one already exists.
func ensureRules(rules [][]string) error {
	for _, r := range rules {
		check := append([]string{}, r...)
		for i, a := range check {
			if a == "-A" || a == "-I" {
				check[i] = "-C"
			}
		}
		if exec.Command("iptables", check...).Run() == nil {
			continue // already present
		}
		if out, err := exec.Command("iptables", r...).CombinedOutput(); err != nil {
			return fmt.Errorf("iptables %s: %v: %s", strings.Join(r, " "), err, out)
		}
	}
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func readSecret(envName, fileEnv string) (string, error) {
	if v := os.Getenv(envName); v != "" {
		return strings.TrimSpace(v), nil
	}
	if f := os.Getenv(fileEnv); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", fmt.Errorf("%s: %w", fileEnv, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", fmt.Errorf("%s or %s is required", envName, fileEnv)
}
