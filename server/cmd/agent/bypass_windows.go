package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"securetunnel/server/internal/speedtest"
)

// The full-tunnel kill switch blocks all traffic outside the tunnel except
// from the tunnel service's own process (it has to reach the gateway). The
// internet speed test therefore runs here, inside that process, and binds its
// sockets to the physical network adapter, so only the speed-test traffic
// leaves outside the tunnel. Only SYSTEM (the SecureTunnel service) can ask
// for a test, and only the speed-test host it names is contacted.

const (
	bypassPipe = `\\.\pipe\SecureTunnelBypass`
	bypassSDDL = "D:P(A;;GA;;;SY)"
	// IP_UNICAST_IF / IPV6_UNICAST_IF: send from this interface regardless of routes.
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

type bypassRequest struct {
	Kind      string `json:"kind,omitempty"` // "" (speed test) or "ip" (public IP lookup)
	Host      string `json:"host"`
	DownBytes int    `json:"down_bytes"`
	UpBytes   int    `json:"up_bytes"`
}

type bypassResponse struct {
	Result speedtest.Result `json:"result"`
	IP     string           `json:"ip,omitempty"`
	Error  string           `json:"error,omitempty"`
}

// serveBypass runs in the tunnel process for its lifetime.
func serveBypass() {
	ln, err := winio.ListenPipe(bypassPipe, &winio.PipeConfig{SecurityDescriptor: bypassSDDL})
	if err != nil {
		logToFile("tunnel.log", "speed test helper: "+err.Error())
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(4 * time.Minute))
			var req bypassRequest
			if json.NewDecoder(c).Decode(&req) != nil {
				return
			}
			var resp bypassResponse
			var err error
			if req.Kind == "ip" {
				resp.IP, err = bypassPublicIP(req.Host)
			} else {
				resp.Result, err = bypassSpeedTest(req)
			}
			if err != nil {
				resp.Error = err.Error()
			}
			_ = json.NewEncoder(c).Encode(resp)
		}(c)
	}
}

func bypassSpeedTest(req bypassRequest) (speedtest.Result, error) {
	host := strings.ToLower(strings.TrimSpace(req.Host))
	if host == "" || strings.ContainsAny(host, "/:@ ?#") {
		return speedtest.Result{}, errors.New("invalid speed test host")
	}
	ifc := physicalInterface()
	if ifc == nil {
		return speedtest.Result{}, errors.New("no physical network adapter found")
	}
	c := physicalClient(ifc.Index)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return speedtest.Run(ctx, c, speedtest.Cloudflare(host), clampBytes(req.DownBytes), clampBytes(req.UpBytes))
}

// bypassPublicIP asks the speed-test host (outside the tunnel) which IP it
// sees: the ISP's public IP.
func bypassPublicIP(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || strings.ContainsAny(host, "/:@ ?#") {
		return "", errors.New("invalid host")
	}
	_, index, _ := preferredPhysicalRouteInfo(windows.AF_INET)
	if index == 0 {
		return "", errors.New("no physical network adapter found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), publicIPTimeout)
	defer cancel()
	return speedtest.PublicIP(ctx, physicalClient(index), host)
}

func clampBytes(n int) int {
	if n < 1<<20 {
		return 1 << 20
	}
	if n > 100<<20 {
		return 100 << 20
	}
	return n
}

// physicalClient makes an HTTP client whose connections go out ifIndex
// instead of following the routing table into the tunnel.
func physicalClient(ifIndex int) *http.Client {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, _ string, c syscall.RawConn) error {
			var serr error
			err := c.Control(func(fd uintptr) {
				if strings.HasSuffix(network, "6") {
					serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, ipv6UnicastIf, ifIndex)
					return
				}
				// IPv4 wants the index in network byte order.
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], uint32(ifIndex))
				serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIf, int(binary.LittleEndian.Uint32(b[:])))
			})
			if err != nil {
				return err
			}
			return serr
		},
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	return &http.Client{Transport: tr, Timeout: 3 * time.Minute}
}

// bypassCall is the service side: ask the tunnel process to run a test.
func bypassCall(req bypassRequest) (speedtest.Result, error) {
	dial := 3 * time.Second
	c, err := winio.DialPipe(bypassPipe, &dial)
	if err != nil {
		return speedtest.Result{}, fmt.Errorf("speed test helper not available: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Minute))
	if err := json.NewEncoder(c).Encode(req); err != nil {
		return speedtest.Result{}, err
	}
	var resp bypassResponse
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return speedtest.Result{}, err
	}
	if resp.Error != "" {
		return resp.Result, errors.New(resp.Error)
	}
	return resp.Result, nil
}

// bypassIP asks the tunnel process for the ISP public IP (outside the tunnel).
func bypassIP(ctx context.Context, host string) (string, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := winio.DialPipeContext(dialCtx, bypassPipe)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if err := json.NewEncoder(c).Encode(bypassRequest{Kind: "ip", Host: host}); err != nil {
		return "", err
	}
	var resp bypassResponse
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", errors.New(resp.Error)
	}
	return resp.IP, nil
}
