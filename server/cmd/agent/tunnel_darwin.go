//go:build darwin

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"securetunnel/server/internal/agentcore"
)

// macTunnel runs WireGuard in this (root) process with wireguard-go on a
// utun interface, then sets the address, routes and DNS with the standard
// macOS tools. Full tunnel uses the 0/1 + 128/1 split so the original default
// route stays untouched; the gateway endpoint gets a host route via the
// physical network.
type macTunnel struct {
	log *slog.Logger

	mu       sync.Mutex
	dev      *device.Device
	ifname   string
	endpoint string // gateway IP with a host route we added
	dns      *dnsOverride
}

func b64ToHex(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return "", errors.New("bad WireGuard key")
	}
	return hex.EncodeToString(b), nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// defaultRoute returns the current IPv4 default gateway and interface.
func defaultRoute() (gw, iface string) {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").Output()
	if err != nil {
		return "", ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "gateway":
			gw = strings.TrimSpace(v)
		case "interface":
			iface = strings.TrimSpace(v)
		}
	}
	return gw, iface
}

func (t *macTunnel) Up(c agentcore.TunnelConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev != nil {
		t.downLocked()
	}
	priv, err := b64ToHex(c.PrivateKey)
	if err != nil {
		return err
	}
	pub, err := b64ToHex(c.PeerPublicKey)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		return fmt.Errorf("gateway endpoint %q: %w", c.Endpoint, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	cancel()
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("look up gateway %s: %v", host, err)
	}
	epIP := ips[0].Unmap().String()

	mtu := c.MTU
	if mtu <= 0 {
		mtu = 1380
	}
	tdev, err := tun.CreateTUN("utun", mtu)
	if err != nil {
		return fmt.Errorf("create utun: %w", err)
	}
	name, _ := tdev.Name()
	logger := device.NewLogger(device.LogLevelError, "wireguard: ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\n", priv, pub, net.JoinHostPort(epIP, port))
	if c.Keepalive > 0 {
		fmt.Fprintf(&uapi, "persistent_keepalive_interval=%d\n", c.Keepalive)
	}
	uapi.WriteString("replace_allowed_ips=true\n")
	for _, a := range c.AllowedIPs {
		fmt.Fprintf(&uapi, "allowed_ip=%s\n", strings.TrimSpace(a))
	}
	if err := dev.IpcSet(uapi.String()); err != nil {
		dev.Close()
		return fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("start WireGuard: %w", err)
	}
	t.dev, t.ifname = dev, name

	addr := strings.TrimSuffix(c.Address, "/32")
	if err := run("/sbin/ifconfig", name, "inet", addr, addr, "netmask", "255.255.255.255", "mtu", strconv.Itoa(mtu), "up"); err != nil {
		t.downLocked()
		return err
	}
	// Keep the gateway itself reachable over the physical network.
	gw, iface := defaultRoute()
	switch {
	case gw != "" && net.ParseIP(gw) != nil:
		_ = run("/sbin/route", "-q", "-n", "add", "-inet", "-host", epIP, gw)
		t.endpoint = epIP
	case iface != "":
		_ = run("/sbin/route", "-q", "-n", "add", "-inet", "-host", epIP, "-interface", iface)
		t.endpoint = epIP
	}
	for _, a := range c.AllowedIPs {
		p, err := netip.ParsePrefix(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		var nets []string
		switch {
		case p.Bits() == 0 && p.Addr().Is4():
			nets = []string{"0.0.0.0/1", "128.0.0.0/1"}
		case p.Bits() == 0 && p.Addr().Is6():
			nets = []string{"::/1", "8000::/1"}
		default:
			nets = []string{p.String()}
		}
		fam := "-inet"
		if p.Addr().Is6() {
			fam = "-inet6"
		}
		for _, n := range nets {
			if err := run("/sbin/route", "-q", "-n", "add", fam, "-net", n, "-interface", name); err != nil && fam == "-inet" {
				t.log.Warn("add route", "net", n, "err", err)
			}
		}
	}
	if len(c.DNS) > 0 {
		d, err := setDNS(c.DNS)
		if err != nil {
			t.log.Warn("set DNS", "err", err)
		}
		t.dns = d
	}
	t.log.Info("tunnel up", "interface", name, "address", addr, "gateway", epIP)
	return nil
}

func (t *macTunnel) Down() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.downLocked()
	return nil
}

func (t *macTunnel) downLocked() {
	if t.dns != nil {
		t.dns.restore()
		t.dns = nil
	}
	if t.dev != nil {
		t.dev.Close() // removes the utun interface and its routes
		t.dev = nil
	}
	if t.endpoint != "" {
		_ = run("/sbin/route", "-q", "-n", "delete", "-inet", "-host", t.endpoint)
		t.endpoint = ""
	}
	t.ifname = ""
}

func (t *macTunnel) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.dev != nil
}

// traffic returns the tunnel's byte counters.
func (t *macTunnel) traffic() (rx, tx uint64, ok bool) {
	t.mu.Lock()
	dev := t.dev
	t.mu.Unlock()
	if dev == nil {
		return 0, 0, false
	}
	s, err := dev.IpcGet()
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(line, "=")
		n, _ := strconv.ParseUint(v, 10, 64)
		switch k {
		case "rx_bytes":
			rx += n
		case "tx_bytes":
			tx += n
		}
	}
	return rx, tx, true
}

// ---- DNS ----
//
// macOS uses the DNS settings of the primary network service. While
// connected we replace them (in the dynamic store, not the saved network
// settings) and put the originals back on disconnect.

type dnsOverride struct {
	key      string
	original string // scutil "d.add" lines to restore, or "" to remove
}

func scutil(script string) (string, error) {
	cmd := exec.Command("/usr/sbin/scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func primaryService() string {
	out, err := scutil("show State:/Network/Global/IPv4\n")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && strings.TrimSpace(k) == "PrimaryService" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func setDNS(servers []string) (*dnsOverride, error) {
	svc := primaryService()
	if svc == "" {
		return nil, errors.New("no primary network service")
	}
	key := "State:/Network/Service/" + svc + "/DNS"
	cur, _ := scutil("show " + key + "\n")
	var orig []string
	if !strings.Contains(cur, "No such key") {
		// Keep the server addresses and search domains to put back later.
		var addrs, domains []string
		section := ""
		for _, line := range strings.Split(cur, "\n") {
			l := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(l, "ServerAddresses"):
				section = "a"
			case strings.HasPrefix(l, "SearchDomains"):
				section = "d"
			case l == "}":
				section = ""
			case strings.Contains(l, " : ") && section != "":
				_, v, _ := strings.Cut(l, " : ")
				if section == "a" {
					addrs = append(addrs, strings.TrimSpace(v))
				} else {
					domains = append(domains, strings.TrimSpace(v))
				}
			}
		}
		if len(addrs) > 0 {
			orig = append(orig, "d.add ServerAddresses * "+strings.Join(addrs, " "))
		}
		if len(domains) > 0 {
			orig = append(orig, "d.add SearchDomains * "+strings.Join(domains, " "))
		}
	}
	script := "d.init\nd.add ServerAddresses * " + strings.Join(servers, " ") + "\nset " + key + "\n"
	if _, err := scutil(script); err != nil {
		return nil, err
	}
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
	return &dnsOverride{key: key, original: strings.Join(orig, "\n")}, nil
}

func (d *dnsOverride) restore() {
	script := "remove " + d.key + "\n"
	if d.original != "" {
		script = "d.init\n" + d.original + "\nset " + d.key + "\n"
	}
	_, _ = scutil(script)
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}
