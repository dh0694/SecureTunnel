// Package store persists gateways and sessions. Postgres is the production store;
// Memory is for tests and single-node development only.
package store

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"securetunnel/server/internal/model"
)

// ErrNotFound means the record does not exist, or (for session updates) is no longer live.
var ErrNotFound = errors.New("not found")

// ErrExists means a record with that key already exists.
var ErrExists = errors.New("already exists")

var (
	ErrDeviceBlocked      = errors.New("device blocked")
	ErrGatewayUnavailable = errors.New("gateway unavailable")
	ErrGatewayInUse       = errors.New("gateway in use")
	ErrGatewayPoolOverlap = errors.New("gateway pool overlaps another gateway")
)

// SweepResult counts the sessions a Sweep changed.
type SweepResult struct {
	Suspended  int
	Expired    int
	Terminated int
}

// Store is the persistence interface used by the session service and API.
// Every method must be safe to call concurrently from several control servers.
type Store interface {
	// UpsertGateway creates or updates a gateway. On update it keeps the existing
	// Enabled flag, so a gateway an admin disabled stays disabled after a restart.
	UpsertGateway(ctx context.Context, g model.Gateway) error
	ListGateways(ctx context.Context) ([]model.Gateway, error)
	RecordGatewayHealth(ctx context.Context, gatewayID string, activePeers int, at time.Time) error
	SetGatewayEnabled(ctx context.Context, gatewayID string, enabled bool) error
	// SetGatewayPool changes the address range and optionally ends any sessions
	// still on the gateway in the same transaction. It returns the number affected.
	SetGatewayPool(ctx context.Context, gatewayID string, pool netip.Prefix, endRemaining bool, at time.Time) (int, error)
	// SetGatewayMetrics stores the gateway host's latest metrics sample.
	SetGatewayMetrics(ctx context.Context, gatewayID string, m model.HostMetrics) error

	// ListSessions returns sessions for the admin site, most recently seen first.
	ListSessions(ctx context.Context, f model.SessionFilter) ([]model.Session, error)
	// SessionStartsSince returns the creation times of sessions created at or after t.
	SessionStartsSince(ctx context.Context, t time.Time) ([]time.Time, error)

	// GetPlacementPolicy returns the saved policy; ok is false if none was saved.
	GetPlacementPolicy(ctx context.Context) (p model.PlacementPolicy, ok bool, err error)
	SetPlacementPolicy(ctx context.Context, p model.PlacementPolicy) error

	// GetSetting loads a JSON setting into v; ok is false if it was never saved.
	GetSetting(ctx context.Context, key string, v any) (ok bool, err error)
	SetSetting(ctx context.Context, key string, v any) error

	AddSpeedTest(ctx context.Context, t model.SpeedTest) error
	// ListSpeedTests returns results newest first, optionally for one device.
	ListSpeedTests(ctx context.Context, deviceID string, limit int) ([]model.SpeedTest, error)

	AddAudit(ctx context.Context, e model.AuditEntry) error
	ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error)

	// Local accounts. Usernames are stored lower-case.
	CreateUser(ctx context.Context, u model.User) error // ErrExists if taken
	GetUser(ctx context.Context, username string) (model.User, error)
	ListUsers(ctx context.Context) ([]model.User, error)
	UpdateUser(ctx context.Context, u model.User) error
	DeleteUser(ctx context.Context, username string) error
	CountUsers(ctx context.Context) (int, error)

	// CreateSession atomically ends any live session for the same device
	// (reason "replaced"), allocates s.TunnelIP from pool, and inserts s.
	CreateSession(ctx context.Context, s *model.Session, pool netip.Prefix) error
	GetSession(ctx context.Context, id string) (model.Session, error)
	// MoveSession reassigns a live session to another gateway with a new address.
	MoveSession(ctx context.Context, id, gatewayID string, pool netip.Prefix, at time.Time) (netip.Addr, error)
	// Touch marks a live session active and seen at the given time.
	Touch(ctx context.Context, id string, at time.Time) error
	// SeeDevice records a connect attempt from a device. A new device is
	// created with newStatus; an existing one keeps its status and gets its
	// name, user, platform, version and last-seen time updated. It returns the
	// device as stored.
	SeeDevice(ctx context.Context, d model.Device, newStatus string) (model.Device, error)
	ListDevices(ctx context.Context, status string) ([]model.Device, error)
	// SetDeviceStatus enforces the caller's ability to manage blocks and ends
	// every live session atomically when the device is blocked.
	SetDeviceStatus(ctx context.Context, id, status, by string, manageBlocks bool, at time.Time) error
	// SetControlHost records a control server's latest metrics (HA view).
	SetControlHost(ctx context.Context, label string, m model.HostMetrics, at time.Time) error
	// ListControlHosts returns every control server that has reported.
	ListControlHosts(ctx context.Context) ([]ControlHost, error)
	// AddLogUpload stores a log bundle and keeps only the newest 5 per device.
	AddLogUpload(ctx context.Context, l model.LogUpload) error
	// ListLogUploads lists uploads (without data), newest first; deviceID "" = all.
	ListLogUploads(ctx context.Context, deviceID string, limit int) ([]model.LogUpload, error)
	// GetLogUpload returns one upload with its data.
	GetLogUpload(ctx context.Context, id string) (model.LogUpload, error)
	// SetDeviceTrust stores the latest device trust check.
	SetDeviceTrust(ctx context.Context, id string, t model.DeviceTrust) error
	DeleteDevice(ctx context.Context, id string) error
	// ApprovePending approves every pending device and returns how many.
	ApprovePending(ctx context.Context, by string, at time.Time) (int, error)

	// AddCommand queues a command for a live session's agent.
	AddCommand(ctx context.Context, sessionID string, c model.Command) error
	// HasCommands reports whether commands are waiting for the session.
	HasCommands(ctx context.Context, sessionID string) (bool, error)
	// TakeCommands returns and clears the session's queued commands.
	TakeCommands(ctx context.Context, sessionID string) ([]model.Command, error)
	// PendingCommands clears acknowledged IDs and returns the remaining queued commands.
	PendingCommands(ctx context.Context, sessionID string, acknowledged []string) ([]model.Command, error)
	// SetSessionDiag stores the latest diagnostics report for a session.
	SetSessionDiag(ctx context.Context, id, diag string, at time.Time) error
	// EndSession moves a live session to state (expired or terminated).
	EndSession(ctx context.Context, id string, state model.State, reason string, at time.Time) error
	// LiveCounts returns the number of live sessions on each gateway.
	LiveCounts(ctx context.Context) (map[string]int, error)
	// LivePeers returns the live sessions placed on a gateway.
	LivePeers(ctx context.Context, gatewayID string) ([]model.Session, error)

	// Sweep suspends active sessions last seen before suspendBefore, expires live
	// sessions last seen before expireBefore, and terminates live sessions past
	// their absolute lifetime.
	Sweep(ctx context.Context, now, suspendBefore, expireBefore time.Time) (SweepResult, error)
}

// ControlHost is a control server as last reported to the database.
type ControlHost struct {
	Label   string
	Metrics model.HostMetrics
	SeenAt  time.Time
}
