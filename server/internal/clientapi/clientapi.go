// Package clientapi is the HTTP client for the control server's client API,
// shared by the Windows agent and the stclient test tool.
package clientapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/model"
)

// Placement is the server's answer to connect, heartbeat and failover.
type Placement struct {
	SessionID   string `json:"session_id"`
	ResumeToken string `json:"resume_token,omitempty"`
	Tunnel      struct {
		Address    string   `json:"address"`
		DNS        []string `json:"dns"`
		AllowedIPs []string `json:"allowed_ips"`
		MTU        int      `json:"mtu"`
		Keepalive  int      `json:"persistent_keepalive"`
	} `json:"tunnel"`
	Gateway          Gateway   `json:"gateway"`
	Alternates       []Gateway `json:"alternates"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
	GraceSeconds     int       `json:"grace_seconds"`
	ExpiresAt        time.Time `json:"expires_at"`
	DeviceTrust      *DeviceTrust `json:"device_trust,omitempty"` // connect response only
	BackupServers    []string     `json:"backup_servers,omitempty"` // other addresses of the same control servers
	SpeedTest        struct {
		IntervalHours int    `json:"interval_hours"`
		SizeMB        int    `json:"size_mb"`
		Host          string `json:"host"`
	} `json:"speed_test"`
	OfficeNetworks OfficeNetworks `json:"office_networks"`
	// WindowsSessions comes with the connect response (nil from older servers).
	WindowsSessions *WindowsSessions `json:"windows_sessions,omitempty"`
	Commands       []Command      `json:"commands,omitempty"`
	// Kind is "device" for a pre-logon device tunnel ("" = a user's session).
	Kind string `json:"kind,omitempty"`
}

// IsDevice reports whether this is a pre-logon device tunnel.
func (p Placement) IsDevice() bool { return p.Kind == "device" }

// DeviceConnectRequest opens a pre-logon device tunnel: no user token, only
// the device certificate's signature over a fresh challenge.
type DeviceConnectRequest struct {
	WGPublicKey string        `json:"wg_public_key"`
	DeviceID    string        `json:"device_id"`
	BootID      string        `json:"boot_id"`
	Platform    string        `json:"platform"`
	DeviceName  string        `json:"device_name,omitempty"`
	Nonce       string        `json:"nonce"`
	Proofs      []DeviceProof `json:"proofs"`
	Join        *JoinInfo     `json:"join,omitempty"`
}

// ConnectDevice opens a device tunnel (POST /v1/sessions/device).
func (c *Client) ConnectDevice(ctx context.Context, r DeviceConnectRequest) (Placement, error) {
	var p Placement
	err := c.do(ctx, http.MethodPost, "/v1/sessions/device", "", r, &p)
	return p, err
}

// Command is an admin action for this PC.
type Command struct {
	ID   string    `json:"id"`
	Type string    `json:"type"` // "speedtest", "diagnostics" or "message"
	Text string    `json:"text,omitempty"`
	From string    `json:"from,omitempty"`
	At   time.Time `json:"at"`
}

// OfficeNetworks are the rules for recognising the corporate network.
type OfficeNetworks struct {
	Enabled      bool     `json:"enabled"`
	DNSSuffixes  []string `json:"dns_suffixes"`
	LocalSubnets []string `json:"local_subnets"`
	PublicIPs    []string `json:"public_ips"`
}

// SpeedReport is one result sent to the server.
type SpeedReport struct {
	Kind      string    `json:"kind"` // "internet" or "vpn"
	DownBps   float64   `json:"down_bps"`
	UpBps     float64   `json:"up_bps"`
	LatencyMs int       `json:"latency_ms"`
	Network   string    `json:"network"`
	Auto      bool      `json:"auto"`
	At        time.Time `json:"at"`
}

// ReportSpeed sends speed test results for the session.
func (c *Client) ReportSpeed(ctx context.Context, sessionID, resumeToken string, results []SpeedReport) error {
	return c.do(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/speedtest/result", resumeToken,
		map[string]any{"results": results}, nil)
}

// Gateway is a gateway as the client sees it.
type Gateway struct {
	ID          string `json:"id"`
	Site        string `json:"site"`
	Endpoint    string `json:"endpoint"`
	TCPEndpoint string `json:"tcp_endpoint,omitempty"`
	PublicKey   string `json:"public_key"`
	InsideIP    string `json:"inside_ip,omitempty"` // gateway's tunnel address (older servers: empty)
}

// ConnectRequest is sent with the sign-in token to open a session.
type ConnectRequest struct {
	WGPublicKey string `json:"wg_public_key"`
	DeviceID    string `json:"device_id"`
	BootID      string `json:"boot_id"`
	Platform    string `json:"platform"`
	DeviceName  string `json:"device_name,omitempty"`

	// Device trust: a nonce from Challenge, signatures over it, and join info.
	Nonce  string        `json:"nonce,omitempty"`
	Proofs []DeviceProof `json:"proofs,omitempty"`
	Join   *JoinInfo     `json:"join,omitempty"`
	DuoTx  string        `json:"duo_tx,omitempty"` // approved Duo Push (see DuoStatus)
	// WindowsUser is the Windows account that asked to connect (UPN or DOMAIN\user).
	WindowsUser string `json:"windows_user,omitempty"`
}

// DuoStatus checks a pending Duo Push: "waiting", "allow" or "deny".
func (c *Client) DuoStatus(ctx context.Context, tx string) (status, message string, err error) {
	var r struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	err = c.do(ctx, http.MethodGet, "/v1/auth/duo/status?tx="+url.QueryEscape(tx), "", nil, &r)
	return r.Status, r.Message, err
}

// Device trust types are shared with the server.
type (
	DeviceProof = model.DeviceProof
	JoinInfo    = model.JoinInfo
	DeviceTrust = model.DeviceTrust
)

// Challenge is a nonce to sign plus which proofs the server wants.
type Challenge struct {
	Nonce      string    `json:"nonce"`
	ExpiresAt  time.Time `json:"expires_at"`
	Entra      bool      `json:"entra_device"`
	DeviceCert bool      `json:"device_cert"`
	UserCert   bool      `json:"user_cert"`
	Issuers    []string  `json:"issuers,omitempty"` // base64 DER issuer names of acceptable certificates
	// Name rules certificates must match, e.g. "$hostname.cb-sisco.com" (see model.CertNameAllowed).
	DeviceNames []string `json:"device_names,omitempty"`
	UserNames   []string `json:"user_names,omitempty"`
}

// Challenge fetches a device-proof challenge. Older servers answer 404.
func (c *Client) Challenge(ctx context.Context) (Challenge, error) {
	var ch Challenge
	err := c.do(ctx, http.MethodGet, "/v1/auth/challenge", "", nil, &ch)
	return ch, err
}

// APIError is an error response from the server.
type APIError struct {
	Status  int    `json:"-"`
	Code    string `json:"error"`
	Message string `json:"message"`
	DuoTx   string `json:"duo_tx,omitempty"` // with code "duo_pending"
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("server returned %d", e.Status)
	}
	return e.Message
}

// HasCode reports whether err is an APIError with the given code.
func HasCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// HasStatus reports whether err is an APIError with the given HTTP status.
func HasStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

// IsReauth reports whether the session is over and the user must sign in again.
func IsReauth(err error) bool { return HasCode(err, "reauth_required") }

// IsServerAnswer reports whether err came from the server (as opposed to a
// network failure where the server could not be reached at all).
func IsServerAnswer(err error) bool {
	var ae *APIError
	return errors.As(err, &ae)
}

// Client calls the control server.
type Client struct {
	Base      string // e.g. https://vpn.example.com
	HTTP      *http.Client
	UserAgent string

	// Fallbacks are backup addresses of the same control servers (they share
	// the database, so a session works on any of them). A request that can't
	// reach Base at all is tried on each fallback in turn; the last address
	// that answered is tried first next time.
	Fallbacks []*Client

	mu     sync.Mutex
	active int
}

// Unreachable reports whether err means the server couldn't be reached
// (network failure, or a proxy such as Cloudflare saying the origin is
// down) rather than an answer from SecureTunnel itself.
func Unreachable(err error) bool {
	if err == nil {
		return false
	}
	var ae *APIError
	if !errors.As(err, &ae) {
		return !errors.Is(err, context.Canceled)
	}
	if ae.Code != "" {
		return false // a SecureTunnel answer
	}
	return ae.Status == 502 || ae.Status == 503 || ae.Status == 504 || (ae.Status >= 520 && ae.Status <= 530)
}

// each runs f on the active address, then the others, until one is reachable.
func (c *Client) each(f func(cl *Client) error) error {
	all := append([]*Client{c}, c.Fallbacks...)
	c.mu.Lock()
	start := c.active
	c.mu.Unlock()
	if start >= len(all) {
		start = 0
	}
	var err error
	for i := 0; i < len(all); i++ {
		idx := (start + i) % len(all)
		if err = f(all[idx]); !Unreachable(err) {
			c.mu.Lock()
			c.active = idx
			c.mu.Unlock()
			return err
		}
	}
	return err
}

// Active returns the address currently in use (Base or a fallback).
func (c *Client) Active() string {
	return c.activeClient().Base
}

func (c *Client) activeClient() *Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active > 0 && c.active <= len(c.Fallbacks) {
		return c.Fallbacks[c.active-1]
	}
	return c
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body, out any) error {
	return c.doWithHeaders(ctx, method, path, bearer, body, out, nil)
}

func (c *Client) doWithHeaders(ctx context.Context, method, path, bearer string, body, out any, headers http.Header) error {
	return c.each(func(cl *Client) error { return cl.doOnce(ctx, method, path, bearer, body, out, headers) })
}

func (c *Client) doOnce(ctx context.Context, method, path, bearer string, body, out any, headers http.Header) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.Base, "/")+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Message == "" {
			e.Message = strings.TrimSpace(string(data))
			if len(e.Message) > 200 || e.Message == "" {
				e.Message = fmt.Sprintf("server returned %d", resp.StatusCode)
			}
		}
		return e
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// LocalLogin signs a local account in and returns a short-lived connect token.
func (c *Client) LocalLogin(ctx context.Context, user, password, code string) (string, error) {
	var resp struct {
		Token string `json:"token"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/auth/local", "",
		map[string]string{"username": user, "password": password, "code": code}, &resp)
	return resp.Token, err
}

// Connect opens a session.
func (c *Client) Connect(ctx context.Context, token string, r ConnectRequest) (Placement, error) {
	var p Placement
	err := c.do(ctx, http.MethodPost, "/v1/sessions", token, r, &p)
	return p, err
}

// Diagnostics is the device report sent with each heartbeat, shown to admins.
type Diagnostics struct {
	// Data and speed through the tunnel.
	RxBytes uint64  `json:"rx_bytes"`
	TxBytes uint64  `json:"tx_bytes"`
	RxBps   float64 `json:"rx_bps"`
	TxBps   float64 `json:"tx_bps"`
	// Connection quality: pings to the gateway through the tunnel (older
	// apps and servers: heartbeat round trips to the control server).
	LatencyMs     int     `json:"latency_ms"`
	JitterMs      int     `json:"jitter_ms"`
	LossPct       float64 `json:"loss_pct"`
	LatencySource string  `json:"latency_source,omitempty"` // "gateway" or "control"
	ControlMs     int     `json:"control_ms,omitempty"`     // heartbeat round trip to the control server
	Drops15m  int     `json:"drops_15m,omitempty"` // connection drops in the last 15 minutes
	OfficeMode bool   `json:"office_mode,omitempty"` // on the office network: signed in, tunnel on standby
	// Physical network.
	Adapter   string `json:"adapter,omitempty"`
	NetKind   string `json:"net_kind,omitempty"`
	SSID      string `json:"ssid,omitempty"`
	SignalPct int    `json:"signal_pct,omitempty"`
	LinkMbps  int    `json:"link_mbps,omitempty"`
	LocalIP   string `json:"local_ip,omitempty"`
	ISPIP     string `json:"isp_ip,omitempty"`
	VPNIP     string `json:"vpn_ip,omitempty"`
	// Device.
	Hostname     string `json:"hostname,omitempty"`
	OS           string `json:"os,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
	WindowsUser  string `json:"windows_user,omitempty"` // the Windows account that owns the tunnel
	// App update state (Settings → Updates in the app): "downloading", "ready",
	// "scheduled", "installing"…; UpdateAt is when a scheduled install runs.
	UpdateState     string    `json:"update_state,omitempty"`
	UpdateVersion   string    `json:"update_version,omitempty"`
	UpdateAt        time.Time `json:"update_at,omitempty"`
	UpdatePostponed int       `json:"update_postponed,omitempty"`
	UptimeSec    int64  `json:"uptime_sec,omitempty"`
}

// Heartbeat keeps a session alive and returns the round-trip time. diag may be nil.
func (c *Client) Heartbeat(ctx context.Context, sessionID, resumeToken, bootID string, diag *Diagnostics) (Placement, time.Duration, error) {
	return c.heartbeat(ctx, sessionID, resumeToken, bootID, diag, nil)
}

// HeartbeatWithCommandAcks keeps a session alive and acknowledges commands the
// agent has handled. Older servers can still return commands in legacy mode.
func (c *Client) HeartbeatWithCommandAcks(ctx context.Context, sessionID, resumeToken, bootID string, diag *Diagnostics, acknowledged []string) (Placement, time.Duration, error) {
	ack := "-"
	if len(acknowledged) > 0 {
		ack = strings.Join(acknowledged, ",")
	}
	headers := http.Header{model.CommandAckHeader: {ack}}
	return c.heartbeat(ctx, sessionID, resumeToken, bootID, diag, headers)
}

func (c *Client) heartbeat(ctx context.Context, sessionID, resumeToken, bootID string, diag *Diagnostics, headers http.Header) (Placement, time.Duration, error) {
	var p Placement
	body := map[string]any{"boot_id": bootID}
	if diag != nil {
		body["diag"] = diag
	}
	start := time.Now()
	err := c.doWithHeaders(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/heartbeat", resumeToken, body, &p, headers)
	return p, time.Since(start), err
}

// Failover moves the session to another gateway.
func (c *Client) Failover(ctx context.Context, sessionID, resumeToken, bootID string) (Placement, error) {
	return c.FailoverTo(ctx, sessionID, resumeToken, bootID, "")
}

// FailoverTo moves the session to another gateway, preferring target ("" = best).
func (c *Client) FailoverTo(ctx context.Context, sessionID, resumeToken, bootID, target string) (Placement, error) {
	var p Placement
	body := map[string]string{"boot_id": bootID}
	if target != "" {
		body["target"] = target
	}
	err := c.do(ctx, http.MethodPost, "/v1/sessions/"+sessionID+"/failover", resumeToken, body, &p)
	return p, err
}

// Disconnect ends the session (the next connect needs a fresh sign-in).
func (c *Client) Disconnect(ctx context.Context, sessionID, resumeToken string) error {
	return c.do(ctx, http.MethodDelete, "/v1/sessions/"+sessionID, resumeToken, nil, nil)
}

// Watch waits (up to ~25 s) for the session to end. It returns nil if the
// session is still live, or an error for which IsReauth is true once it ends.
// It also returns early with commands=true when an admin queued a command
// for this session; the next heartbeat delivers it.
func (c *Client) Watch(ctx context.Context, sessionID, resumeToken string) (commands bool, err error) {
	var resp struct {
		Commands bool `json:"commands"`
	}
	err = c.do(ctx, http.MethodGet, "/v1/sessions/"+sessionID+"/watch", resumeToken, nil, &resp)
	return resp.Commands, err
}

// ClientVersion describes the current agent installer on the server.
type ClientVersion struct {
	Version string `json:"version"` // "" when no update is offered to this PC right now
	SHA256  string `json:"sha256"`
	URL     string `json:"url"`
	Size    int    `json:"size"`
	Held    string `json:"held,omitempty"`   // why a newer version is held back ("paused", "rollout")
	Latest  string `json:"latest,omitempty"` // that version
	Policy  *UpdatePolicy `json:"policy,omitempty"`
}

// UpdatePolicy is how and when the app installs updates (see
// model.UpdatePolicy; set on the admin site's App updates page).
type UpdatePolicy struct {
	Paused         bool   `json:"paused"`
	RolloutPercent int    `json:"rollout_percent"`
	InstallWhen    string `json:"install_when"` // disconnected | window | anytime
	WindowDays     []int  `json:"window_days"`  // 0 = Sunday
	WindowStart    string `json:"window_start"` // "HH:MM", PC local time
	WindowEnd      string `json:"window_end"`
	DeadlineDays   int    `json:"deadline_days"`
	NotifyUsers    bool   `json:"notify_users"`
	MaxPostpones   int    `json:"max_postpones"`
}

// InWindow reports whether t (local time) is inside the maintenance window.
// A window whose end is before its start runs past midnight; the day is the
// day it starts.
func (p UpdatePolicy) InWindow(t time.Time) bool {
	parse := func(s string) int {
		var h, m int
		if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil {
			return -1
		}
		return h*60 + m
	}
	start, end, now := parse(p.WindowStart), parse(p.WindowEnd), t.Hour()*60+t.Minute()
	if start < 0 || end < 0 {
		return false
	}
	day := int(t.Weekday())
	if end < start && now < end { // early-morning part of a window that began yesterday
		day = (day + 6) % 7
	}
	onDay := false
	for _, d := range p.WindowDays {
		if d == day {
			onDay = true
		}
	}
	if !onDay {
		return false
	}
	if start < end {
		return now >= start && now < end
	}
	return now >= start || now < end
}

// CheckUpdate asks for the version this PC should run. force (an admin push)
// skips pause and staged rollout.
func (c *Client) CheckUpdate(ctx context.Context, platform, deviceID string, force bool) (ClientVersion, error) {
	var v ClientVersion
	q := url.Values{}
	if platform != "" {
		q.Set("platform", platform)
	}
	if deviceID != "" {
		q.Set("device_id", deviceID)
	}
	if force {
		q.Set("force", "1")
	}
	err := c.do(ctx, http.MethodGet, "/v1/client/version?"+q.Encode(), "", nil, &v)
	return v, err
}

// LatestVersion asks the server which agent version is current.
func (c *Client) LatestVersion(ctx context.Context) (ClientVersion, error) {
	return c.LatestVersionFor(ctx, "")
}

// LatestVersionFor asks for the current agent of a platform ("" = Windows,
// "macos" = the Mac package).
func (c *Client) LatestVersionFor(ctx context.Context, platform string) (ClientVersion, error) {
	var v ClientVersion
	path := "/v1/client/version"
	if platform != "" {
		path += "?platform=" + url.QueryEscape(platform)
	}
	err := c.do(ctx, http.MethodGet, path, "", nil, &v)
	return v, err
}

// AuthConfig is how users sign in (GET /v1/client/auth-config).
type AuthConfig struct {
	Local bool `json:"local"`
	Entra *struct {
		TenantID    string `json:"tenant_id"`
		ClientID    string `json:"client_id"`
		Scope       string `json:"scope"`
		Authority   string `json:"authority"`
		PromptLogin bool   `json:"prompt_login"`
	} `json:"entra,omitempty"`
}

// AuthConfig fetches the sign-in options. Older servers without the endpoint
// answer 404; callers treat that as local accounts only.
func (c *Client) AuthConfig(ctx context.Context) (AuthConfig, error) {
	var v AuthConfig
	err := c.do(ctx, http.MethodGet, "/v1/client/auth-config", "", nil, &v)
	return v, err
}

// Download fetches a file from the server (path relative to the server URL).
func (c *Client) Download(ctx context.Context, path string, w io.Writer, maxBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.Base, "/")+path, nil)
	if err != nil {
		return err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	// Downloads can take longer than API calls.
	dl := *hc
	dl.Timeout = 10 * time.Minute
	resp, err := dl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &APIError{Status: resp.StatusCode, Message: fmt.Sprintf("download failed: server returned %d", resp.StatusCode)}
	}
	_, err = io.Copy(w, io.LimitReader(resp.Body, maxBytes))
	return err
}

// NewerVersion reports whether version a is newer than b ("1.2.3" format;
// anything unparsable, like "dev", is never newer and never upgraded).
func NewerVersion(a, b string) bool {
	pa, oka := parseVersion(a)
	pb, okb := parseVersion(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(strings.TrimPrefix(strings.TrimSpace(v), "v"), ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n := 0
		if p == "" {
			return out, false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return out, false
			}
			n = n*10 + int(ch-'0')
		}
		out[i] = n
	}
	return out, true
}

// Health checks /healthz.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", "", nil, nil)
}

// ProbeHealth checks the address in use without changing the active server or
// timing retries to backup addresses. The response must identify a healthy
// control server so an unrelated successful HTTP response is not a sample.
func (c *Client) ProbeHealth(ctx context.Context) error {
	var health struct {
		Status string `json:"status"`
	}
	headers := http.Header{"Cache-Control": {"no-cache"}}
	err := c.activeClient().doOnce(ctx, http.MethodGet, "/healthz", "", nil, &health, headers)
	if err != nil {
		return err
	}
	if health.Status != "ok" {
		return errors.New("control server health response was not OK")
	}
	return nil
}

// UploadLogs sends a zip of agent logs. sessionID/resumeToken may be empty
// (not connected); the server then accepts it only for a known device.
func (c *Client) UploadLogs(ctx context.Context, sessionID, resumeToken, deviceID, reason string, data []byte) (string, error) {
	var ref string
	err := c.each(func(cl *Client) error {
		var err error
		ref, err = cl.uploadLogsOnce(ctx, sessionID, resumeToken, deviceID, reason, data)
		return err
	})
	return ref, err
}

func (c *Client) uploadLogsOnce(ctx context.Context, sessionID, resumeToken, deviceID, reason string, data []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Base, "/")+"/v1/client/logs", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/zip")
	req.Header.Set("X-ST-Device", deviceID)
	req.Header.Set("X-ST-Reason", reason)
	if sessionID != "" && resumeToken != "" {
		req.Header.Set("X-ST-Session", sessionID)
		req.Header.Set("Authorization", "Bearer "+resumeToken)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(body, e)
		return "", e
	}
	var out struct {
		Ref string `json:"ref"`
	}
	_ = json.Unmarshal(body, &out)
	return out.Ref, nil
}

// WindowsSessions is what the app does on Windows sign-out, user switching
// and screen lock (see model.WindowsSessionPolicy for the options).
type WindowsSessions struct {
	OnSignOut       string `json:"on_sign_out"`       // disconnect | stay | device_tunnel
	OnSwitch        string `json:"on_switch"`         // disconnect | share | block
	SameUserSession string `json:"same_user_session"` // same | different
	LockMinutes     int    `json:"lock_minutes"`      // 0 = never
	UserMatch       string `json:"user_match"`        // allow | warn | block (enforced by the server)
	DisconnectBy    string `json:"disconnect_by"`     // anyone | owner
}

// WindowsSessionsOrDefault fills in the recommended behavior for anything unset.
func WindowsSessionsOrDefault(p *WindowsSessions) WindowsSessions {
	d := WindowsSessions{OnSignOut: "disconnect", OnSwitch: "disconnect", SameUserSession: "same", UserMatch: "allow", DisconnectBy: "anyone"}
	if p == nil {
		return d
	}
	out := *p
	if out.OnSignOut == "" {
		out.OnSignOut = d.OnSignOut
	}
	if out.OnSwitch == "" {
		out.OnSwitch = d.OnSwitch
	}
	if out.SameUserSession == "" {
		out.SameUserSession = d.SameUserSession
	}
	if out.UserMatch == "" {
		out.UserMatch = d.UserMatch
	}
	if out.DisconnectBy == "" {
		out.DisconnectBy = d.DisconnectBy
	}
	return out
}
