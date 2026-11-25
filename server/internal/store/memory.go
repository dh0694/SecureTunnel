package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"securetunnel/server/internal/ipam"
	"securetunnel/server/internal/model"
)

// Memory is an in-process Store for tests and local development. It is not HA.
type Memory struct {
	mu       sync.Mutex
	controls map[string]ControlHost
	logs     []model.LogUpload
	gateways map[string]model.Gateway
	sessions map[string]model.Session
	audit    []model.AuditEntry
	users    map[string]model.User
	policy   *model.PlacementPolicy
	settings map[string][]byte
	speeds   []model.SpeedTest
	commands map[string][]model.Command
	devices  map[string]model.Device
}

func (m *Memory) GetSetting(_ context.Context, key string, v any) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.settings[key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, v)
}

func (m *Memory) SetSetting(_ context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.settings == nil {
		m.settings = map[string][]byte{}
	}
	m.settings[key] = b
	return nil
}

func (m *Memory) AddSpeedTest(_ context.Context, t model.SpeedTest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t.ID = int64(len(m.speeds) + 1)
	m.speeds = append(m.speeds, t)
	return nil
}

func (m *Memory) ListSpeedTests(_ context.Context, deviceID string, limit int) ([]model.SpeedTest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.SpeedTest
	for i := len(m.speeds) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		if deviceID == "" || m.speeds[i].DeviceID == deviceID {
			out = append(out, m.speeds[i])
		}
	}
	return out, nil
}

func (m *Memory) GetPlacementPolicy(_ context.Context) (model.PlacementPolicy, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.policy == nil {
		return model.PlacementPolicy{}, false, nil
	}
	return *m.policy, true, nil
}

func (m *Memory) SetPlacementPolicy(_ context.Context, p model.PlacementPolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policy = &p
	return nil
}

func (m *Memory) CreateUser(_ context.Context, u model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u.Username = strings.ToLower(u.Username)
	if _, ok := m.users[u.Username]; ok {
		return ErrExists
	}
	m.users[u.Username] = u
	return nil
}

func (m *Memory) GetUser(_ context.Context, username string) (model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[strings.ToLower(username)]
	if !ok {
		return model.User{}, ErrNotFound
	}
	return u, nil
}

func (m *Memory) ListUsers(_ context.Context) ([]model.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, nil
}

func (m *Memory) UpdateUser(_ context.Context, u model.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u.Username = strings.ToLower(u.Username)
	if _, ok := m.users[u.Username]; !ok {
		return ErrNotFound
	}
	m.users[u.Username] = u
	return nil
}

func (m *Memory) DeleteUser(_ context.Context, username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	username = strings.ToLower(username)
	if _, ok := m.users[username]; !ok {
		return ErrNotFound
	}
	delete(m.users, username)
	return nil
}

func (m *Memory) CountUsers(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.users), nil
}

func (m *Memory) SetGatewayEnabled(_ context.Context, id string, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gateways[id]
	if !ok {
		return ErrNotFound
	}
	g.Enabled = enabled
	m.gateways[id] = g
	return nil
}

func (m *Memory) SetGatewayMetrics(_ context.Context, id string, hm model.HostMetrics) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gateways[id]
	if !ok {
		return ErrNotFound
	}
	g.Metrics = hm
	m.gateways[id] = g
	return nil
}

func (m *Memory) ListSessions(_ context.Context, f model.SessionFilter) ([]model.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	q := strings.ToLower(strings.TrimSpace(f.Query))
	var out []model.Session
	for _, s := range m.sessions {
		if (f.State == "live" && !s.State.Live()) || (f.State == "ended" && s.State.Live()) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(s.UPN), q) &&
			!strings.Contains(strings.ToLower(s.DeviceID), q) && s.TunnelIP.String() != q {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *Memory) SessionStartsSince(_ context.Context, t time.Time) ([]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []time.Time
	for _, s := range m.sessions {
		if !s.CreatedAt.Before(t) {
			out = append(out, s.CreatedAt)
		}
	}
	return out, nil
}

func (m *Memory) AddAudit(_ context.Context, e model.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e.ID = int64(len(m.audit) + 1)
	m.audit = append(m.audit, e)
	return nil
}

func (m *Memory) ListAudit(_ context.Context, limit int) ([]model.AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.AuditEntry
	for i := len(m.audit) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, m.audit[i])
	}
	return out, nil
}

// NewMemory returns an empty Memory store.
func NewMemory() *Memory {
	return &Memory{gateways: map[string]model.Gateway{}, sessions: map[string]model.Session{}, users: map[string]model.User{}}
}

func (m *Memory) UpsertGateway(_ context.Context, g model.Gateway) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.gateways[g.ID]; ok {
		g.LastHealth, g.ActivePeers, g.Enabled, g.Metrics, g.Pool = old.LastHealth, old.ActivePeers, old.Enabled, old.Metrics, old.Pool
	}
	m.gateways[g.ID] = g
	return nil
}

func (m *Memory) ListGateways(_ context.Context) ([]model.Gateway, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.Gateway, 0, len(m.gateways))
	for _, g := range m.gateways {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) RecordGatewayHealth(_ context.Context, id string, peers int, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gateways[id]
	if !ok {
		return ErrNotFound
	}
	g.LastHealth, g.ActivePeers = at, peers
	m.gateways[id] = g
	return nil
}

func (m *Memory) usedIPs(gatewayID string) map[netip.Addr]bool {
	used := map[netip.Addr]bool{}
	for _, s := range m.sessions {
		if s.GatewayID == gatewayID && s.State.Live() {
			used[s.TunnelIP] = true
		}
	}
	return used
}

func (m *Memory) CreateSession(_ context.Context, s *model.Session, pool netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.devices[s.DeviceID].Status == model.DeviceBlocked {
		return ErrDeviceBlocked
	}
	if g := m.gateways[s.GatewayID]; !g.Enabled || g.Pool != pool {
		return ErrGatewayUnavailable
	}
	used := m.usedIPs(s.GatewayID)
	for _, old := range m.sessions {
		if old.DeviceID == s.DeviceID && old.GatewayID == s.GatewayID && old.State.Live() {
			delete(used, old.TunnelIP)
		}
	}
	ip, err := ipam.Allocate(pool, used)
	if err != nil {
		return err
	}
	for id, old := range m.sessions {
		if old.DeviceID == s.DeviceID && old.State.Live() {
			old.State, old.EndReason, old.EndedAt = model.StateTerminated, model.ReasonReplaced, s.CreatedAt
			m.sessions[id] = old
		}
	}
	s.TunnelIP = ip
	m.sessions[s.ID] = *s
	return nil
}

func (m *Memory) GetSession(_ context.Context, id string) (model.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return model.Session{}, ErrNotFound
	}
	return s, nil
}

func (m *Memory) MoveSession(_ context.Context, id, gatewayID string, pool netip.Prefix, at time.Time) (netip.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || !s.State.Live() {
		return netip.Addr{}, ErrNotFound
	}
	if g := m.gateways[gatewayID]; !g.Enabled || g.Pool != pool {
		return netip.Addr{}, ErrGatewayUnavailable
	}
	ip, err := ipam.Allocate(pool, m.usedIPs(gatewayID))
	if err != nil {
		return netip.Addr{}, err
	}
	s.GatewayID, s.TunnelIP, s.State, s.LastSeen = gatewayID, ip, model.StateActive, at
	m.sessions[id] = s
	return ip, nil
}

func (m *Memory) Touch(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || !s.State.Live() {
		return ErrNotFound
	}
	s.State, s.LastSeen = model.StateActive, at
	m.sessions[id] = s
	return nil
}

func (m *Memory) SeeDevice(_ context.Context, d model.Device, newStatus string) (model.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.devices == nil {
		m.devices = map[string]model.Device{}
	}
	old, ok := m.devices[d.ID]
	if !ok {
		d.Status = newStatus
		m.devices[d.ID] = d
		return d, nil
	}
	old.Name, old.Platform, old.LastUser, old.AgentVersion, old.LastSeen = d.Name, d.Platform, d.LastUser, d.AgentVersion, d.LastSeen
	m.devices[d.ID] = old
	return old, nil
}

func (m *Memory) ListDevices(_ context.Context, status string) ([]model.Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.Device{}
	for _, d := range m.devices {
		if status == "" || d.Status == status {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

func (m *Memory) SetDeviceStatus(_ context.Context, id, status, by string, manageBlocks bool, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return ErrNotFound
	}
	if !manageBlocks && (d.Status == model.DeviceBlocked || status != model.DeviceApproved) {
		return ErrDeviceBlocked
	}
	d.Status, d.DecidedBy, d.DecidedAt = status, by, at
	m.devices[id] = d
	if status == model.DeviceBlocked {
		for sid, se := range m.sessions {
			if se.DeviceID == id && se.State.Live() {
				se.State, se.EndReason, se.EndedAt = model.StateTerminated, model.ReasonAdminDisconnect, at
				m.sessions[sid] = se
			}
		}
	}
	return nil
}

func (m *Memory) SetDeviceTrust(_ context.Context, id string, t model.DeviceTrust) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok {
		return ErrNotFound
	}
	d.Trust = &t
	m.devices[id] = d
	return nil
}

func (m *Memory) DeleteDevice(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.devices[id]; !ok {
		return ErrNotFound
	}
	delete(m.devices, id)
	return nil
}

func (m *Memory) ApprovePending(_ context.Context, by string, at time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, d := range m.devices {
		if d.Status == model.DevicePending {
			d.Status, d.DecidedBy, d.DecidedAt = model.DeviceApproved, by, at
			m.devices[id] = d
			n++
		}
	}
	return n, nil
}

func (m *Memory) AddCommand(_ context.Context, id string, c model.Command) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || !s.State.Live() {
		return ErrNotFound
	}
	if m.commands == nil {
		m.commands = map[string][]model.Command{}
	}
	if len(m.commands[id]) >= 20 {
		return errors.New("too many queued commands")
	}
	m.commands[id] = append(m.commands[id], c)
	return nil
}

func (m *Memory) HasCommands(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.commands[id]) > 0, nil
}

func (m *Memory) TakeCommands(_ context.Context, id string) ([]model.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.commands[id]
	delete(m.commands, id)
	return c, nil
}

func (m *Memory) PendingCommands(_ context.Context, id string, acknowledged []string) ([]model.Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	commands := m.commands[id]
	if len(acknowledged) > 0 && len(commands) > 0 {
		commands = slices.DeleteFunc(commands, func(c model.Command) bool {
			return slices.Contains(acknowledged, c.ID)
		})
		if len(commands) == 0 {
			delete(m.commands, id)
		} else {
			m.commands[id] = commands
		}
	}
	return slices.Clone(commands), nil
}

func (m *Memory) SetSessionDiag(_ context.Context, id, diag string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return ErrNotFound
	}
	s.Diag, s.DiagAt = diag, at
	m.sessions[id] = s
	return nil
}

func (m *Memory) EndSession(_ context.Context, id string, state model.State, reason string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || !s.State.Live() {
		return ErrNotFound
	}
	s.State, s.EndReason, s.EndedAt = state, reason, at
	m.sessions[id] = s
	return nil
}

func (m *Memory) LiveCounts(_ context.Context) (map[string]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]int{}
	for _, s := range m.sessions {
		if s.State.Live() {
			out[s.GatewayID]++
		}
	}
	return out, nil
}

func (m *Memory) LivePeers(_ context.Context, gatewayID string) ([]model.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Session
	for _, s := range m.sessions {
		if s.GatewayID == gatewayID && s.State.Live() {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *Memory) Sweep(_ context.Context, now, suspendBefore, expireBefore time.Time) (SweepResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var r SweepResult
	for id, s := range m.sessions {
		if !s.State.Live() {
			continue
		}
		switch {
		case now.After(s.ExpiresAt):
			s.State, s.EndReason, s.EndedAt = model.StateTerminated, model.ReasonMaxLifetime, now
			r.Terminated++
		case s.LastSeen.Before(expireBefore):
			s.State, s.EndReason, s.EndedAt = model.StateExpired, model.ReasonGraceExpired, now
			r.Expired++
		case s.State == model.StateActive && s.LastSeen.Before(suspendBefore):
			s.State = model.StateSuspended
			r.Suspended++
		default:
			continue
		}
		m.sessions[id] = s
	}
	return r, nil
}

func (m *Memory) SetControlHost(_ context.Context, label string, hm model.HostMetrics, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.controls == nil {
		m.controls = map[string]ControlHost{}
	}
	m.controls[label] = ControlHost{Label: label, Metrics: hm, SeenAt: at}
	return nil
}

func (m *Memory) ListControlHosts(_ context.Context) ([]ControlHost, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []ControlHost{}
	for _, c := range m.controls {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

func (m *Memory) AddLogUpload(_ context.Context, l model.LogUpload) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logs = append([]model.LogUpload{l}, m.logs...)
	n := 0
	kept := m.logs[:0]
	for _, x := range m.logs {
		if x.DeviceID == l.DeviceID {
			n++
			if n > 5 {
				continue
			}
		}
		kept = append(kept, x)
	}
	m.logs = kept
	return nil
}

func (m *Memory) ListLogUploads(_ context.Context, deviceID string, limit int) ([]model.LogUpload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []model.LogUpload{}
	for _, l := range m.logs {
		if deviceID == "" || l.DeviceID == deviceID {
			l.Data = nil
			out = append(out, l)
		}
	}
	return out, nil
}

func (m *Memory) GetLogUpload(_ context.Context, id string) (model.LogUpload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, l := range m.logs {
		if l.ID == id {
			return l, nil
		}
	}
	return model.LogUpload{}, ErrNotFound
}

// SetGatewayPool changes a gateway's tunnel address range.
func (m *Memory) SetGatewayPool(_ context.Context, id string, pool netip.Prefix, endRemaining bool, at time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gateways[id]
	if !ok {
		return 0, ErrNotFound
	}
	if g.Pool == pool {
		return 0, nil
	}
	for otherID, other := range m.gateways {
		if otherID != id && other.Pool.Overlaps(pool) {
			return 0, ErrGatewayPoolOverlap
		}
	}
	var count int
	for sid, se := range m.sessions {
		if se.GatewayID != id || !se.State.Live() {
			continue
		}
		count++
		if endRemaining {
			se.State, se.EndReason, se.EndedAt = model.StateTerminated, model.ReasonAdminDisconnect, at
			m.sessions[sid] = se
		}
	}
	if count > 0 && !endRemaining {
		return count, ErrGatewayInUse
	}
	g.Pool = pool
	m.gateways[id] = g
	return count, nil
}
