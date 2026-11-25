// Package model holds the types shared by the control server's packages.
package model

import (
	"errors"
	"net/netip"
	"strings"
	"time"
)

// State is a session's lifecycle state. See docs/ARCHITECTURE.md for the state machine.
type State string

const (
	// StateActive: the client is heartbeating normally.
	StateActive State = "active"
	// StateSuspended: heartbeats stopped (network drop, sleep). The peer stays on the
	// gateway and the client may resume without MFA until the grace window runs out.
	StateSuspended State = "suspended"
	// StateExpired: the grace window ran out or the device rebooted. Fresh MFA required.
	StateExpired State = "expired"
	// StateTerminated: the user disconnected, the session was replaced, or it hit its
	// absolute lifetime. Fresh MFA required.
	StateTerminated State = "terminated"
)

// Live reports whether the session still holds a peer slot on a gateway.
func (s State) Live() bool { return s == StateActive || s == StateSuspended }

// End reasons recorded on sessions.
const (
	ReasonUserDisconnect = "user_disconnect"
	ReasonGraceExpired   = "grace_expired"
	ReasonReboot         = "reboot"
	ReasonMaxLifetime    = "max_lifetime"
	ReasonReplaced        = "replaced"
	ReasonAdminDisconnect = "admin_disconnect"
)

// AuditEntry is one line of the audit log: admin actions and session events.
type AuditEntry struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`  // UPN of the user or admin, or "system"
	Action string    `json:"action"` // e.g. session.connect, admin.disconnect, gateway.disable
	Target string    `json:"target"` // session ID, gateway ID, ...
	Detail string    `json:"detail"`
}

// HostMetrics is a point-in-time health sample of a server (control server or gateway).
type HostMetrics struct {
	At         time.Time `json:"at"`
	Hostname   string    `json:"hostname"`
	CPUPercent float64   `json:"cpu_percent"`
	CPUCores   int       `json:"cpu_cores"`
	Load1      float64   `json:"load1"`
	Load5      float64   `json:"load5"`
	Load15     float64   `json:"load15"`
	MemTotal   uint64    `json:"mem_total"`
	MemUsed    uint64    `json:"mem_used"`
	DiskTotal  uint64    `json:"disk_total"`
	DiskUsed   uint64    `json:"disk_used"`
	UptimeSec  int64     `json:"uptime_sec"`

	// Gateways only: WireGuard traffic and peers with a recent handshake.
	NetRxBps   float64 `json:"net_rx_bps,omitempty"`
	NetTxBps   float64 `json:"net_tx_bps,omitempty"`
	Handshakes int     `json:"handshakes,omitempty"`
}

// PlacementPolicy decides which gateways take new sessions. A gateway whose
// latest metrics break any limit is skipped while others are within limits.
type PlacementPolicy struct {
	MaxCPUPercent float64 `json:"max_cpu_percent"`  // skip at or above this CPU %
	MaxMemPercent float64 `json:"max_mem_percent"`  // skip at or above this memory %
	MinFreeDiskGB float64 `json:"min_free_disk_gb"` // skip below this much free disk
}

// Validate checks the limits are sensible.
func (p PlacementPolicy) Validate() error {
	switch {
	case p.MaxCPUPercent < 1 || p.MaxCPUPercent > 100:
		return errors.New("CPU limit must be between 1 and 100%")
	case p.MaxMemPercent < 1 || p.MaxMemPercent > 100:
		return errors.New("memory limit must be between 1 and 100%")
	case p.MinFreeDiskGB < 0 || p.MinFreeDiskGB > 100000:
		return errors.New("free disk must be between 0 and 100000 GB")
	}
	return nil
}

// SpeedTestPolicy controls the agents' speed tests. It is sent to agents in
// every heartbeat response.
type SpeedTestPolicy struct {
	IntervalHours int    `json:"interval_hours"` // automatic test interval; 0 = only on demand
	SizeMB        int    `json:"size_mb"`        // download size per test (upload is a quarter)
	Host          string `json:"host"`           // internet speed-test host, reached outside the tunnel
}

// Validate checks the policy.
func (p SpeedTestPolicy) Validate() error {
	switch {
	case p.IntervalHours < 0 || p.IntervalHours > 24*30:
		return errors.New("interval must be between 0 (off) and 720 hours")
	case p.SizeMB < 1 || p.SizeMB > 100:
		return errors.New("test size must be between 1 and 100 MB")
	case p.Host == "" || strings.ContainsAny(p.Host, "/:@ ?#"):
		return errors.New("enter a host name only, like speed.cloudflare.com")
	}
	return nil
}

// DefaultSpeedTestPolicy is used until an admin saves one.
var DefaultSpeedTestPolicy = SpeedTestPolicy{IntervalHours: 24, SizeMB: 25, Host: "speed.cloudflare.com"}

// SpeedTest is one speed test result reported by an agent.
type SpeedTest struct {
	ID        int64     `json:"id"`
	At        time.Time `json:"at"`
	SessionID string    `json:"session_id"`
	UPN       string    `json:"upn"`
	DeviceID  string    `json:"device_id"`
	Kind      string    `json:"kind"` // "internet" (outside the tunnel) or "vpn"
	DownBps   float64   `json:"down_bps"`
	UpBps     float64   `json:"up_bps"`
	LatencyMs int       `json:"latency_ms"`
	Network   string    `json:"network"` // e.g. "Wi-Fi HomeNet"
	Auto      bool      `json:"auto"`
}

// Roles for local accounts.
const (
	RoleAdmin    = "admin"    // full admin site access + VPN
	RoleHelpdesk = "helpdesk" // view everything, disconnect sessions + VPN
	RoleUser     = "user"     // VPN only
)

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { return r == RoleAdmin || r == RoleHelpdesk || r == RoleUser }

// User is a local account (used while Entra is not configured, and as break-glass).
type User struct {
	Username     string    `json:"username"`
	DisplayName  string    `json:"display_name"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	TOTPSecret   string    `json:"-"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`

	// Source is "local" (password account) or "entra" (settings for an Entra
	// user, keyed by UPN; they sign in with Microsoft, never with a password).
	Source string `json:"source"`
	// PolicyGroup is a policy group ID picked on the admin site ("" = automatic).
	PolicyGroup string `json:"policy_group"`

	// Country access on top of the default list (see CountryPolicy).
	AllowedCountries []string  `json:"allowed_countries"`
	TravelCountries  []string  `json:"travel_countries"`
	TravelUntil      time.Time `json:"travel_until"`
}

// CommandAckHeader opts a heartbeat into acknowledged command delivery.
// Its value is a comma-separated list of IDs, or "-" with no acknowledgments.
const CommandAckHeader = "X-SecureTunnel-Command-Acks"

// Command is an action an admin sends to a connected agent.
type Command struct {
	ID   string    `json:"id"`
	Type string    `json:"type"` // "speedtest", "diagnostics" or "message"
	Text string    `json:"text,omitempty"`
	From string    `json:"from,omitempty"` // admin username (shown with messages)
	At   time.Time `json:"at"`
}

// SessionFilter selects sessions for the admin site.
type SessionFilter struct {
	State string // "live", "ended" or "" for all
	Query string // matches UPN, device ID or tunnel IP
	Limit int
}

// Identity is the verified user behind a connect request.
type Identity struct {
	UserOID  string
	UPN      string
	Name     string
	TenantID string
	AuthTime time.Time
}

// Gateway is a WireGuard gateway the control server can place sessions on.
type Gateway struct {
	ID          string       `json:"id"`
	Site        string       `json:"site"`
	Endpoint    string       `json:"endpoint"`               // host:port, WireGuard UDP
	TCPEndpoint string       `json:"tcp_endpoint,omitempty"` // TCP/443 fallback (phase 4)
	PublicKey   string       `json:"public_key"`             // WireGuard public key, base64
	Pool        netip.Prefix `json:"pool"`                   // client tunnel IPs owned by this gateway
	Capacity    int          `json:"capacity"`               // max concurrent peers
	TokenHash   string       `json:"token_hash"`             // hex SHA-256 of the gateway's API token
	Enabled     bool         `json:"enabled"`

	// Reported by the gateway agent.
	LastHealth  time.Time   `json:"-"`
	ActivePeers int         `json:"-"`
	Metrics     HostMetrics `json:"-"`
}

// Session is one connected (or recently connected) client tunnel.
type Session struct {
	ID              string
	UserOID         string
	UPN             string
	TenantID        string
	DeviceID        string
	BootID          string
	Platform        string
	WGPublicKey     string
	GatewayID       string
	TunnelIP        netip.Addr
	State           State
	ResumeTokenHash []byte
	AuthTime        time.Time
	CreatedAt       time.Time
	LastSeen        time.Time
	ExpiresAt       time.Time // absolute lifetime; fresh MFA after this
	EndedAt         time.Time
	EndReason       string
	ClientIP        string
	ClientVersion   string // agent version, from its User-Agent (empty for other clients)
	Diag            string // latest diagnostics JSON from the agent's heartbeat
	DiagAt          time.Time
	Country         string // ISO code the session connected from ("" if unknown)
	DeviceName      string // computer name (DeviceID is the machine ID)
	Kind            string // SessionUser ("" in old rows) or SessionDevice
}

// Session kinds. A device session is the pre-logon tunnel a PC opens with its
// device certificate before anyone signs in; it reaches only the subnets in
// DeviceTunnelPolicy.
const (
	SessionUser   = "user"
	SessionDevice = "device"
)

// IsDevice reports whether this is a pre-logon device tunnel session.
func (s Session) IsDevice() bool { return s.Kind == SessionDevice }
