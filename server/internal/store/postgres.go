package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"securetunnel/server/internal/ipam"
	"securetunnel/server/internal/model"
)

//go:embed schema.sql
var schemaSQL string

// Postgres is the production Store. Point it at the Patroni-managed primary
// (e.g. through HAProxy or a libpq multi-host URL with target_session_attrs=read-write).
type Postgres struct {
	pool *pgxpool.Pool
}

// OpenPostgres connects and applies the schema.
func OpenPostgres(ctx context.Context, url string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() { p.pool.Close() }

// Ping checks the database is reachable (used by /healthz).
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

const liveStates = `('active','suspended')`

func (p *Postgres) UpsertGateway(ctx context.Context, g model.Gateway) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO gateways (id, site, endpoint, tcp_endpoint, public_key, pool, capacity, token_hash, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (id) DO UPDATE SET site=$2, endpoint=$3, tcp_endpoint=$4, public_key=$5,
			capacity=$7, token_hash=$8`, // the pool is only seeded: after that it's edited on the admin site
		g.ID, g.Site, g.Endpoint, g.TCPEndpoint, g.PublicKey, g.Pool.String(), g.Capacity, g.TokenHash, g.Enabled)
	return err
}

func (p *Postgres) ListGateways(ctx context.Context) ([]model.Gateway, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, site, endpoint, tcp_endpoint, public_key, pool, capacity, token_hash, enabled, last_health, active_peers, metrics
		FROM gateways ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Gateway
	for rows.Next() {
		var g model.Gateway
		var pool, metrics string
		if err := rows.Scan(&g.ID, &g.Site, &g.Endpoint, &g.TCPEndpoint, &g.PublicKey, &pool, &g.Capacity,
			&g.TokenHash, &g.Enabled, &g.LastHealth, &g.ActivePeers, &metrics); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(metrics), &g.Metrics)
		if g.Pool, err = netip.ParsePrefix(pool); err != nil {
			return nil, fmt.Errorf("gateway %s: bad pool %q", g.ID, pool)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (p *Postgres) RecordGatewayHealth(ctx context.Context, id string, peers int, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `UPDATE gateways SET last_health=$2, active_peers=$3 WHERE id=$1`, id, at, peers)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) SetGatewayMetrics(ctx context.Context, id string, m model.HostMetrics) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx, `UPDATE gateways SET metrics=$2 WHERE id=$1`, id, string(b))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) GetPlacementPolicy(ctx context.Context) (model.PlacementPolicy, bool, error) {
	var v string
	err := p.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key='placement_policy'`).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.PlacementPolicy{}, false, nil
	}
	if err != nil {
		return model.PlacementPolicy{}, false, err
	}
	var pol model.PlacementPolicy
	if err := json.Unmarshal([]byte(v), &pol); err != nil {
		return model.PlacementPolicy{}, false, err
	}
	return pol, true, nil
}

func (p *Postgres) SetPlacementPolicy(ctx context.Context, pol model.PlacementPolicy) error {
	b, err := json.Marshal(pol)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('placement_policy', $1)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, string(b))
	return err
}

func (p *Postgres) GetSetting(ctx context.Context, key string, v any) (bool, error) {
	var s string
	err := p.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key=$1`, key).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(s), v)
}

func (p *Postgres) SetSetting(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, string(b))
	return err
}

func (p *Postgres) AddSpeedTest(ctx context.Context, t model.SpeedTest) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO speed_tests (at, session_id, upn, device_id, kind, down_bps, up_bps, latency_ms, network, auto)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		t.At, t.SessionID, t.UPN, t.DeviceID, t.Kind, t.DownBps, t.UpBps, t.LatencyMs, t.Network, t.Auto)
	return err
}

func (p *Postgres) ListSpeedTests(ctx context.Context, deviceID string, limit int) ([]model.SpeedTest, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := p.pool.Query(ctx, `SELECT id, at, session_id, upn, device_id, kind, down_bps, up_bps, latency_ms, network, auto
		FROM speed_tests WHERE ($1 = '' OR device_id = $1) ORDER BY at DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SpeedTest
	for rows.Next() {
		var t model.SpeedTest
		if err := rows.Scan(&t.ID, &t.At, &t.SessionID, &t.UPN, &t.DeviceID, &t.Kind, &t.DownBps, &t.UpBps, &t.LatencyMs, &t.Network, &t.Auto); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DatabaseSize returns the size of the current database in bytes.
func (p *Postgres) DatabaseSize(ctx context.Context) (int64, error) {
	var n int64
	err := p.pool.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&n)
	return n, err
}

func (p *Postgres) SetGatewayEnabled(ctx context.Context, id string, enabled bool) error {
	tag, err := p.pool.Exec(ctx, `UPDATE gateways SET enabled=$2 WHERE id=$1`, id, enabled)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) ListSessions(ctx context.Context, f model.SessionFilter) ([]model.Session, error) {
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := p.pool.Query(ctx, `SELECT `+sessionCols+` FROM sessions
		WHERE ($1 = '' OR ($1 = 'live' AND state IN `+liveStates+`) OR ($1 = 'ended' AND state NOT IN `+liveStates+`))
		  AND ($2 = '' OR upn ILIKE '%' || $2 || '%' OR device_id ILIKE '%' || $2 || '%' OR tunnel_ip = $2)
		ORDER BY last_seen DESC LIMIT $3`, f.State, strings.TrimSpace(f.Query), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) SessionStartsSince(ctx context.Context, t time.Time) ([]time.Time, error) {
	rows, err := p.pool.Query(ctx, `SELECT created_at FROM sessions WHERE created_at >= $1`, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []time.Time
	for rows.Next() {
		var at time.Time
		if err := rows.Scan(&at); err != nil {
			return nil, err
		}
		out = append(out, at)
	}
	return out, rows.Err()
}

func (p *Postgres) AddAudit(ctx context.Context, e model.AuditEntry) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO audit_log (at, actor, action, target, detail) VALUES ($1,$2,$3,$4,$5)`,
		e.At, e.Actor, e.Action, e.Target, e.Detail)
	return err
}

func (p *Postgres) ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := p.pool.Query(ctx, `SELECT id, at, actor, action, target, detail FROM audit_log ORDER BY at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

const userCols = `username, display_name, password_hash, role, totp_secret, disabled, created_at, last_login, allowed_countries, travel_countries, travel_until, source, policy_group`

func scanUser(row pgx.Row) (model.User, error) {
	var u model.User
	var allowed, travel string
	err := row.Scan(&u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.TOTPSecret, &u.Disabled, &u.CreatedAt, &u.LastLogin,
		&allowed, &travel, &u.TravelUntil, &u.Source, &u.PolicyGroup)
	if errors.Is(err, pgx.ErrNoRows) {
		return u, ErrNotFound
	}
	u.AllowedCountries, u.TravelCountries = splitList(allowed), splitList(travel)
	return u, err
}

func (p *Postgres) CreateUser(ctx context.Context, u model.User) error {
	tag, err := p.pool.Exec(ctx, `INSERT INTO users (`+userCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		ON CONFLICT (username) DO NOTHING`,
		strings.ToLower(u.Username), u.DisplayName, u.PasswordHash, u.Role, u.TOTPSecret, u.Disabled, u.CreatedAt, u.LastLogin,
		strings.Join(u.AllowedCountries, ","), strings.Join(u.TravelCountries, ","), u.TravelUntil, userSource(u), u.PolicyGroup)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrExists
	}
	return nil
}

func (p *Postgres) GetUser(ctx context.Context, username string) (model.User, error) {
	return scanUser(p.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE username=$1`, strings.ToLower(username)))
}

func (p *Postgres) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (p *Postgres) UpdateUser(ctx context.Context, u model.User) error {
	tag, err := p.pool.Exec(ctx, `UPDATE users SET display_name=$2, password_hash=$3, role=$4, totp_secret=$5,
		disabled=$6, last_login=$7, allowed_countries=$8, travel_countries=$9, travel_until=$10, policy_group=$11 WHERE username=$1`,
		strings.ToLower(u.Username), u.DisplayName, u.PasswordHash, u.Role, u.TOTPSecret, u.Disabled, u.LastLogin,
		strings.Join(u.AllowedCountries, ","), strings.Join(u.TravelCountries, ","), u.TravelUntil, u.PolicyGroup)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteUser(ctx context.Context, username string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE username=$1`, strings.ToLower(username))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func userSource(u model.User) string {
	if u.Source == "" {
		return "local"
	}
	return u.Source
}

func splitList(s string) []string {
	out := []string{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// lockGateway serialises address allocation per gateway across all control servers.
func lockGateway(ctx context.Context, tx pgx.Tx, gatewayID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('gw:' || $1))`, gatewayID)
	return err
}

func checkPlacementGateway(ctx context.Context, tx pgx.Tx, id string, pool netip.Prefix) error {
	var current string
	var enabled bool
	err := tx.QueryRow(ctx, "SELECT pool, enabled FROM gateways WHERE id=$1 FOR UPDATE", id).Scan(&current, &enabled)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (!enabled || current != pool.String())) {
		return ErrGatewayUnavailable
	}
	return err
}

func usedIPs(ctx context.Context, tx pgx.Tx, gatewayID string) (map[netip.Addr]bool, error) {
	rows, err := tx.Query(ctx, `SELECT tunnel_ip FROM sessions WHERE gateway_id=$1 AND state IN `+liveStates, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if a, err := netip.ParseAddr(s); err == nil {
			used[a] = true
		}
	}
	return used, rows.Err()
}

func (p *Postgres) CreateSession(ctx context.Context, s *model.Session, pool netip.Prefix) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	var status string
	err = tx.QueryRow(ctx, "SELECT status FROM devices WHERE id=$1 FOR UPDATE", s.DeviceID).Scan(&status)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if status == model.DeviceBlocked {
		return ErrDeviceBlocked
	}
	if err := lockGateway(ctx, tx, s.GatewayID); err != nil {
		return err
	}
	if err := checkPlacementGateway(ctx, tx, s.GatewayID, pool); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE sessions SET state='terminated', end_reason=$2, ended_at=$3
		WHERE device_id=$1 AND state IN `+liveStates, s.DeviceID, model.ReasonReplaced, s.CreatedAt); err != nil {
		return err
	}
	used, err := usedIPs(ctx, tx, s.GatewayID)
	if err != nil {
		return err
	}
	ip, err := ipam.Allocate(pool, used)
	if err != nil {
		return err
	}
	s.TunnelIP = ip
	if _, err := tx.Exec(ctx, `
		INSERT INTO sessions (id, user_oid, upn, tenant_id, device_id, boot_id, platform, wg_public_key,
			gateway_id, tunnel_ip, state, resume_token_hash, auth_time, created_at, last_seen, expires_at, client_ip, client_version, country, device_name, kind)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		s.ID, s.UserOID, s.UPN, s.TenantID, s.DeviceID, s.BootID, s.Platform, s.WGPublicKey,
		s.GatewayID, ip.String(), string(s.State), s.ResumeTokenHash, s.AuthTime, s.CreatedAt, s.LastSeen,
		s.ExpiresAt, s.ClientIP, s.ClientVersion, s.Country, s.DeviceName, sessionKind(s.Kind)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func sessionKind(k string) string {
	if k == "" {
		return model.SessionUser
	}
	return k
}

const sessionCols = `id, user_oid, upn, tenant_id, device_id, boot_id, platform, wg_public_key, gateway_id,
	tunnel_ip, state, resume_token_hash, auth_time, created_at, last_seen, expires_at, ended_at, end_reason, client_ip, client_version, diag, diag_at, country, device_name, kind`

func scanSession(row pgx.Row) (model.Session, error) {
	var s model.Session
	var ip, state string
	var ended, diagAt *time.Time
	if err := row.Scan(&s.ID, &s.UserOID, &s.UPN, &s.TenantID, &s.DeviceID, &s.BootID, &s.Platform,
		&s.WGPublicKey, &s.GatewayID, &ip, &state, &s.ResumeTokenHash, &s.AuthTime, &s.CreatedAt,
		&s.LastSeen, &s.ExpiresAt, &ended, &s.EndReason, &s.ClientIP, &s.ClientVersion, &s.Diag, &diagAt, &s.Country, &s.DeviceName, &s.Kind); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return s, ErrNotFound
		}
		return s, err
	}
	s.State = model.State(state)
	s.TunnelIP, _ = netip.ParseAddr(ip)
	if ended != nil {
		s.EndedAt = *ended
	}
	if diagAt != nil {
		s.DiagAt = *diagAt
	}
	return s, nil
}

func (p *Postgres) GetSession(ctx context.Context, id string) (model.Session, error) {
	return scanSession(p.pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id=$1`, id))
}

func (p *Postgres) MoveSession(ctx context.Context, id, gatewayID string, pool netip.Prefix, at time.Time) (netip.Addr, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := lockGateway(ctx, tx, gatewayID); err != nil {
		return netip.Addr{}, err
	}
	if err := checkPlacementGateway(ctx, tx, gatewayID, pool); err != nil {
		return netip.Addr{}, err
	}
	used, err := usedIPs(ctx, tx, gatewayID)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := ipam.Allocate(pool, used)
	if err != nil {
		return netip.Addr{}, err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE sessions SET gateway_id=$2, tunnel_ip=$3, state='active', last_seen=$4
		WHERE id=$1 AND state IN `+liveStates, id, gatewayID, ip.String(), at)
	if err != nil {
		return netip.Addr{}, err
	}
	if tag.RowsAffected() == 0 {
		return netip.Addr{}, ErrNotFound
	}
	return ip, tx.Commit(ctx)
}

func (p *Postgres) Touch(ctx context.Context, id string, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE sessions SET state='active', last_seen=GREATEST(last_seen, $2)
		WHERE id=$1 AND state IN `+liveStates, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const deviceCols = `id, name, status, platform, last_user, agent_version, first_seen, last_seen, decided_by, decided_at, trust`

func scanDevice(row pgx.Row) (model.Device, error) {
	var d model.Device
	var trust string
	err := row.Scan(&d.ID, &d.Name, &d.Status, &d.Platform, &d.LastUser, &d.AgentVersion, &d.FirstSeen, &d.LastSeen, &d.DecidedBy, &d.DecidedAt, &trust)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err == nil && trust != "" {
		var t model.DeviceTrust
		if json.Unmarshal([]byte(trust), &t) == nil {
			d.Trust = &t
		}
	}
	return d, err
}

func (p *Postgres) SeeDevice(ctx context.Context, d model.Device, newStatus string) (model.Device, error) {
	return scanDevice(p.pool.QueryRow(ctx, `INSERT INTO devices (id, name, status, platform, last_user, agent_version, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, platform=EXCLUDED.platform, last_user=EXCLUDED.last_user,
			agent_version=EXCLUDED.agent_version, last_seen=EXCLUDED.last_seen
		RETURNING `+deviceCols, d.ID, d.Name, newStatus, d.Platform, d.LastUser, d.AgentVersion, d.LastSeen))
}

func (p *Postgres) ListDevices(ctx context.Context, status string) ([]model.Device, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+deviceCols+` FROM devices WHERE ($1 = '' OR status = $1) ORDER BY last_seen DESC LIMIT 5000`, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Device{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (p *Postgres) SetDeviceStatus(ctx context.Context, id, status, by string, manageBlocks bool, at time.Time) error {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var previous string
	err = tx.QueryRow(ctx, "SELECT status FROM devices WHERE id=$1 FOR UPDATE", id).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if !manageBlocks && (previous == model.DeviceBlocked || status != model.DeviceApproved) {
		return ErrDeviceBlocked
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET status=$2, decided_by=$3, decided_at=$4 WHERE id=$1`, id, status, by, at); err != nil {
		return err
	}
	if status == model.DeviceBlocked {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET state='terminated', end_reason=$2, ended_at=$3
			WHERE device_id=$1 AND state IN `+liveStates, id, model.ReasonAdminDisconnect, at); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (p *Postgres) SetDeviceTrust(ctx context.Context, id string, t model.DeviceTrust) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx, `UPDATE devices SET trust=$2 WHERE id=$1`, id, string(b))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) DeleteDevice(ctx context.Context, id string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM devices WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) ApprovePending(ctx context.Context, by string, at time.Time) (int, error) {
	tag, err := p.pool.Exec(ctx, `UPDATE devices SET status='approved', decided_by=$1, decided_at=$2 WHERE status='pending'`, by, at)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (p *Postgres) AddCommand(ctx context.Context, id string, c model.Command) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tag, err := p.pool.Exec(ctx, `INSERT INTO session_commands (id, session_id, body, created_at)
		SELECT $1, $2, $3, $4 WHERE EXISTS (SELECT 1 FROM sessions WHERE id=$2 AND state IN `+liveStates+`)
		AND (SELECT count(*) FROM session_commands WHERE session_id=$2) < 20`, c.ID, id, string(b), c.At)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) HasCommands(ctx context.Context, id string) (bool, error) {
	var ok bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM session_commands WHERE session_id=$1)`, id).Scan(&ok)
	return ok, err
}

func (p *Postgres) TakeCommands(ctx context.Context, id string) ([]model.Command, error) {
	rows, err := p.pool.Query(ctx, `DELETE FROM session_commands WHERE session_id=$1 RETURNING body`, id)
	if err != nil {
		return nil, err
	}
	return scanCommands(rows)
}

func (p *Postgres) PendingCommands(ctx context.Context, id string, acknowledged []string) ([]model.Command, error) {
	if len(acknowledged) > 0 {
		if _, err := p.pool.Exec(ctx, `DELETE FROM session_commands WHERE session_id=$1 AND id = ANY($2::text[])`, id, acknowledged); err != nil {
			return nil, err
		}
	}
	rows, err := p.pool.Query(ctx, `SELECT body FROM session_commands WHERE session_id=$1`, id)
	if err != nil {
		return nil, err
	}
	return scanCommands(rows)
}

func scanCommands(rows pgx.Rows) ([]model.Command, error) {
	defer rows.Close()
	var out []model.Command
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		var c model.Command
		if json.Unmarshal([]byte(b), &c) == nil {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, rows.Err()
}

func (p *Postgres) SetSessionDiag(ctx context.Context, id, diag string, at time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE sessions SET diag=$2, diag_at=$3 WHERE id=$1`, id, diag, at)
	return err
}

func (p *Postgres) EndSession(ctx context.Context, id string, state model.State, reason string, at time.Time) error {
	tag, err := p.pool.Exec(ctx, `
		UPDATE sessions SET state=$2, end_reason=$3, ended_at=$4
		WHERE id=$1 AND state IN `+liveStates, id, string(state), reason, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) LiveCounts(ctx context.Context) (map[string]int, error) {
	rows, err := p.pool.Query(ctx, `SELECT gateway_id, count(*) FROM sessions WHERE state IN `+liveStates+` GROUP BY gateway_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func (p *Postgres) LivePeers(ctx context.Context, gatewayID string) ([]model.Session, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+sessionCols+` FROM sessions
		WHERE gateway_id=$1 AND state IN `+liveStates+` ORDER BY id`, gatewayID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) Sweep(ctx context.Context, now, suspendBefore, expireBefore time.Time) (SweepResult, error) {
	var r SweepResult
	steps := []struct {
		n   *int
		sql string
		arg []any
	}{
		{&r.Terminated, `UPDATE sessions SET state='terminated', end_reason=$2, ended_at=$1
			WHERE state IN ` + liveStates + ` AND expires_at < $1`, []any{now, model.ReasonMaxLifetime}},
		{&r.Expired, `UPDATE sessions SET state='expired', end_reason=$3, ended_at=$1
			WHERE state IN ` + liveStates + ` AND last_seen < $2`, []any{now, expireBefore, model.ReasonGraceExpired}},
		{&r.Suspended, `UPDATE sessions SET state='suspended'
			WHERE state='active' AND last_seen < $1`, []any{suspendBefore}},
	}
	for _, st := range steps {
		tag, err := p.pool.Exec(ctx, st.sql, st.arg...)
		if err != nil {
			return r, err
		}
		*st.n = int(tag.RowsAffected())
	}
	return r, nil
}

func (p *Postgres) SetControlHost(ctx context.Context, label string, m model.HostMetrics, at time.Time) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO control_hosts (label, metrics, seen_at) VALUES ($1, $2, $3)
		ON CONFLICT (label) DO UPDATE SET metrics=EXCLUDED.metrics, seen_at=EXCLUDED.seen_at`, label, string(b), at)
	return err
}

func (p *Postgres) ListControlHosts(ctx context.Context) ([]ControlHost, error) {
	rows, err := p.pool.Query(ctx, `SELECT label, metrics, seen_at FROM control_hosts WHERE seen_at > now() - interval '1 day' ORDER BY label`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ControlHost{}
	for rows.Next() {
		var c ControlHost
		var js string
		if err := rows.Scan(&c.Label, &js, &c.SeenAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(js), &c.Metrics)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) AddLogUpload(ctx context.Context, l model.LogUpload) error {
	if _, err := p.pool.Exec(ctx, `INSERT INTO device_logs (id, at, ref, device_id, device_name, upn, verified, reason, size, data)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, l.ID, l.At, l.Ref, l.DeviceID, l.DeviceName, l.UPN, l.Verified, l.Reason, l.Size, l.Data); err != nil {
		return err
	}
	_, err := p.pool.Exec(ctx, `DELETE FROM device_logs WHERE device_id=$1 AND id NOT IN
		(SELECT id FROM device_logs WHERE device_id=$1 ORDER BY at DESC LIMIT 5)`, l.DeviceID)
	return err
}

func (p *Postgres) ListLogUploads(ctx context.Context, deviceID string, limit int) ([]model.LogUpload, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := p.pool.Query(ctx, `SELECT id, at, ref, device_id, device_name, upn, verified, reason, size FROM device_logs
		WHERE ($1 = '' OR device_id = $1) ORDER BY at DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.LogUpload{}
	for rows.Next() {
		var l model.LogUpload
		if err := rows.Scan(&l.ID, &l.At, &l.Ref, &l.DeviceID, &l.DeviceName, &l.UPN, &l.Verified, &l.Reason, &l.Size); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (p *Postgres) GetLogUpload(ctx context.Context, id string) (model.LogUpload, error) {
	var l model.LogUpload
	err := p.pool.QueryRow(ctx, `SELECT id, at, ref, device_id, device_name, upn, verified, reason, size, data FROM device_logs WHERE id=$1`, id).
		Scan(&l.ID, &l.At, &l.Ref, &l.DeviceID, &l.DeviceName, &l.UPN, &l.Verified, &l.Reason, &l.Size, &l.Data)
	if errors.Is(err, pgx.ErrNoRows) {
		return l, ErrNotFound
	}
	return l, err
}

// DBStats is what the System page shows about the database.
type DBStats struct {
	Version     string    `json:"version"`
	StartedAt   time.Time `json:"started_at"`
	SizeBytes   int64     `json:"size_bytes"`
	Connections int       `json:"connections"`     // open connections to this database (all control servers)
	MaxConns    int       `json:"max_connections"` // server limit
	PoolOpen    int32     `json:"pool_open"`       // this control server's pool
	PoolBusy    int32     `json:"pool_busy"`
	PoolMax     int32     `json:"pool_max"`
	CacheHit    float64   `json:"cache_hit_percent"`
	Commits     int64     `json:"commits"`
	Rollbacks   int64     `json:"rollbacks"`
	Deadlocks   int64     `json:"deadlocks"`
	PingMs      float64   `json:"ping_ms"`
	Users       int64     `json:"users"`
	Devices     int64     `json:"devices"`
	Sessions    int64     `json:"active_sessions"`
	AuditRows   int64     `json:"audit_rows"`
}

// DatabaseStats gathers health and size figures for the System page.
func (p *Postgres) DatabaseStats(ctx context.Context) (DBStats, error) {
	var s DBStats
	t0 := time.Now()
	if err := p.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int)); err != nil {
		return s, err
	}
	s.PingMs = float64(time.Since(t0).Microseconds()) / 1000
	err := p.pool.QueryRow(ctx, `
		SELECT current_setting('server_version'), pg_postmaster_start_time(),
		       pg_database_size(current_database()),
		       (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()),
		       current_setting('max_connections')::int,
		       COALESCE(d.blks_hit * 100.0 / NULLIF(d.blks_hit + d.blks_read, 0), 100),
		       d.xact_commit, d.xact_rollback, d.deadlocks,
		       (SELECT count(*) FROM users), (SELECT count(*) FROM devices),
		       (SELECT count(*) FROM sessions WHERE state IN ('active','suspended')),
		       (SELECT count(*) FROM audit_log)
		FROM pg_stat_database d WHERE d.datname = current_database()`).Scan(
		&s.Version, &s.StartedAt, &s.SizeBytes, &s.Connections, &s.MaxConns, &s.CacheHit,
		&s.Commits, &s.Rollbacks, &s.Deadlocks, &s.Users, &s.Devices, &s.Sessions, &s.AuditRows)
	if err != nil {
		return s, err
	}
	if i := strings.IndexByte(s.Version, ' '); i > 0 {
		s.Version = s.Version[:i] // "16.4 (Debian ...)" → "16.4"
	}
	st := p.pool.Stat()
	s.PoolOpen, s.PoolBusy, s.PoolMax = st.TotalConns(), st.AcquiredConns(), st.MaxConns()
	return s, nil
}

func (p *Postgres) SetGatewayPool(ctx context.Context, id string, pool netip.Prefix, endRemaining bool, at time.Time) (int, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('gateway-pools'))"); err != nil {
		return 0, err
	}
	if err := lockGateway(ctx, tx, id); err != nil {
		return 0, err
	}
	var current string
	err = tx.QueryRow(ctx, "SELECT pool FROM gateways WHERE id=$1 FOR UPDATE", id).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil || current == pool.String() {
		return 0, err
	}
	var overlaps bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM gateways WHERE id<>$1 AND pool::cidr && $2::text::cidr)", id, pool.String()).Scan(&overlaps); err != nil {
		return 0, err
	}
	if overlaps {
		return 0, ErrGatewayPoolOverlap
	}
	var count int
	if endRemaining {
		tag, err := tx.Exec(ctx, `UPDATE sessions SET state='terminated', end_reason=$2, ended_at=$3
			WHERE gateway_id=$1 AND state IN `+liveStates, id, model.ReasonAdminDisconnect, at)
		if err != nil {
			return 0, err
		}
		count = int(tag.RowsAffected())
	} else {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE gateway_id=$1 AND state IN `+liveStates, id).Scan(&count); err != nil {
			return 0, err
		}
		if count > 0 {
			return count, ErrGatewayInUse
		}
	}
	if _, err := tx.Exec(ctx, "UPDATE gateways SET pool=$2 WHERE id=$1", id, pool.String()); err != nil {
		return 0, err
	}
	return count, tx.Commit(ctx)
}
