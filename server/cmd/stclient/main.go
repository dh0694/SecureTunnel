// Command stclient is a proof-of-concept test client. It signs in with a local
// account, opens a VPN session, writes a WireGuard config you can import into the
// official WireGuard app, and heartbeats until Ctrl+C (which disconnects).
//
//	stclient -server https://vpn.lab:8443 -user testuser -ca tls.crt -out securetunnel.conf
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type placement struct {
	SessionID   string `json:"session_id"`
	ResumeToken string `json:"resume_token"`
	Tunnel      struct {
		Address    string   `json:"address"`
		DNS        []string `json:"dns"`
		AllowedIPs []string `json:"allowed_ips"`
		MTU        int      `json:"mtu"`
		Keepalive  int      `json:"persistent_keepalive"`
	} `json:"tunnel"`
	Gateway struct {
		ID        string `json:"id"`
		Endpoint  string `json:"endpoint"`
		PublicKey string `json:"public_key"`
	} `json:"gateway"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	GraceSeconds     int       `json:"grace_seconds"`
	ExpiresAt        time.Time `json:"expires_at"`
}

type apiError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *apiError) Error() string { return fmt.Sprintf("%s (%s)", e.Message, e.Code) }

func main() {
	server := flag.String("server", "", "control server URL, e.g. https://vpn.lab:8443")
	user := flag.String("user", "", "local account username")
	caFile := flag.String("ca", "", "CA/certificate file to trust (for the lab's self-signed cert)")
	insecure := flag.Bool("insecure", false, "skip TLS verification (lab only)")
	out := flag.String("out", "securetunnel.conf", "where to write the WireGuard config")
	device := flag.String("device", "", "device ID (default: hostname)")
	bootID := flag.String("boot-id", "", "boot ID (default: random; change it to simulate a reboot)")
	flag.Parse()
	if *server == "" {
		flag.Usage()
		os.Exit(2)
	}
	if *user == "" {
		*user = prompt("Username: ", false)
		if *user == "" {
			fail(errors.New("a username is required"))
		}
	}
	if *device == "" {
		h, _ := os.Hostname()
		*device = "stclient-" + h
	}
	if *bootID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		*bootID = hex.EncodeToString(b)
	}
	c, err := newClient(strings.TrimRight(*server, "/"), *caFile, *insecure)
	if err != nil {
		fail(err)
	}
	if err := c.run(*user, *device, *bootID, *out); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

type client struct {
	base string
	http *http.Client
}

func newClient(base, caFile string, insecure bool) (*client, error) {
	tcfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure} //nolint:gosec // opt-in lab flag
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
	return &client{base: base, http: &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tcfg}}}, nil
}

func (c *client) call(method, path, bearer string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		e := &apiError{Status: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Message == "" {
			e.Message = strings.TrimSpace(string(data))
		}
		return e
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func prompt(label string, secret bool) string {
	fmt.Fprint(os.Stderr, label)
	if secret && term.IsTerminal(int(os.Stdin.Fd())) {
		b, _ := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b)
	}
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(s)
}

func (c *client) signIn(user string) (string, error) {
	password := prompt("Password for "+user+": ", true)
	body := map[string]string{"username": user, "password": password, "code": ""}
	var resp struct {
		Token string `json:"token"`
	}
	err := c.call(http.MethodPost, "/v1/auth/local", "", body, &resp)
	var ae *apiError
	if errors.As(err, &ae) && ae.Code == "code_required" {
		body["code"] = prompt("Authenticator code: ", false)
		err = c.call(http.MethodPost, "/v1/auth/local", "", body, &resp)
	}
	return resp.Token, err
}

func (c *client) run(user, device, bootID, outPath string) error {
	token, err := c.signIn(user)
	if err != nil {
		return fmt.Errorf("sign-in: %w", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	var p placement
	err = c.call(http.MethodPost, "/v1/sessions", token, map[string]string{
		"wg_public_key": key.PublicKey().String(), "device_id": device, "boot_id": bootID, "platform": "stclient",
	}, &p)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if err := os.WriteFile(outPath, []byte(wgConfig(key, p)), 0o600); err != nil {
		if cleanupErr := c.call(http.MethodDelete, "/v1/sessions/"+p.SessionID, p.ResumeToken, nil, nil); cleanupErr != nil {
			return errors.Join(err, fmt.Errorf("disconnect after config write failed: %w", cleanupErr))
		}
		return err
	}
	fmt.Fprintf(os.Stderr, "\nConnected. Session %s on %s, tunnel IP %s.\n", p.SessionID, p.Gateway.ID, p.Tunnel.Address)
	fmt.Fprintf(os.Stderr, "WireGuard config written to %s. Import it into the WireGuard app and activate it.\n", outPath)
	fmt.Fprintf(os.Stderr, "Leave this running: it heartbeats every %ds. Ctrl+C disconnects (next connect needs a fresh sign-in).\n\n", p.HeartbeatSeconds)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	every := time.Duration(p.HeartbeatSeconds) * time.Second
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	failingSince := time.Time{}
	for {
		select {
		case <-ctx.Done():
			err := c.call(http.MethodDelete, "/v1/sessions/"+p.SessionID, p.ResumeToken, nil, nil)
			if err != nil {
				return fmt.Errorf("disconnect: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Disconnected. Deactivate the tunnel in the WireGuard app too.")
			return nil
		case <-t.C:
			var hb placement
			err := c.call(http.MethodPost, "/v1/sessions/"+p.SessionID+"/heartbeat", p.ResumeToken, map[string]string{"boot_id": bootID}, &hb)
			var ae *apiError
			switch {
			case err == nil:
				if !failingSince.IsZero() {
					fmt.Fprintf(os.Stderr, "%s  back online after %s, session resumed with no sign-in\n", stamp(), time.Since(failingSince).Round(time.Second))
					failingSince = time.Time{}
				}
			case errors.As(err, &ae) && ae.Code == "reauth_required":
				return errors.New("the session ended (disconnected by an admin, grace window expired, or 12h limit); run stclient again to sign in")
			default:
				if failingSince.IsZero() {
					failingSince = time.Now()
				}
				left := time.Duration(p.GraceSeconds)*time.Second - time.Since(failingSince)
				fmt.Fprintf(os.Stderr, "%s  heartbeat failed (%v); grace window has about %s left\n", stamp(), err, left.Round(time.Second))
			}
		}
	}
}

func stamp() string { return time.Now().Format("15:04:05") }

func wgConfig(key wgtypes.Key, p placement) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# SecureTunnel test session %s (expires %s)\n", p.SessionID, p.ExpiresAt.Local().Format(time.RFC1123))
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\n", key, p.Tunnel.Address)
	if len(p.Tunnel.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(p.Tunnel.DNS, ", "))
	}
	if p.Tunnel.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", p.Tunnel.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\n",
		p.Gateway.PublicKey, p.Gateway.Endpoint, strings.Join(p.Tunnel.AllowedIPs, ", "))
	if p.Tunnel.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Tunnel.Keepalive)
	}
	return b.String()
}
