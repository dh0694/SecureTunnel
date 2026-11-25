-- SecureTunnel control server schema. Applied at startup; every statement is idempotent.

CREATE TABLE IF NOT EXISTS gateways (
    id            text PRIMARY KEY,
    site          text        NOT NULL,
    endpoint      text        NOT NULL,
    tcp_endpoint  text        NOT NULL DEFAULT '',
    public_key    text        NOT NULL,
    pool          text        NOT NULL,
    capacity      integer     NOT NULL,
    token_hash    text        NOT NULL,
    enabled       boolean     NOT NULL DEFAULT true,
    last_health   timestamptz NOT NULL DEFAULT 'epoch',
    active_peers  integer     NOT NULL DEFAULT 0
);

ALTER TABLE gateways ADD COLUMN IF NOT EXISTS metrics text NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS sessions (
    id                 text PRIMARY KEY,
    user_oid           text        NOT NULL,
    upn                text        NOT NULL,
    tenant_id          text        NOT NULL,
    device_id          text        NOT NULL,
    boot_id            text        NOT NULL,
    platform           text        NOT NULL,
    wg_public_key      text        NOT NULL,
    gateway_id         text        NOT NULL REFERENCES gateways(id),
    tunnel_ip          text        NOT NULL,
    state              text        NOT NULL,
    resume_token_hash  bytea       NOT NULL,
    auth_time          timestamptz NOT NULL,
    created_at         timestamptz NOT NULL,
    last_seen          timestamptz NOT NULL,
    expires_at         timestamptz NOT NULL,
    ended_at           timestamptz,
    end_reason         text        NOT NULL DEFAULT '',
    client_ip          text        NOT NULL DEFAULT ''
);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_version text NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS diag text NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS diag_at timestamptz;

-- A tunnel address and a WireGuard key can each belong to only one live session.
CREATE UNIQUE INDEX IF NOT EXISTS sessions_live_ip
    ON sessions (gateway_id, tunnel_ip) WHERE state IN ('active', 'suspended');
CREATE UNIQUE INDEX IF NOT EXISTS sessions_live_wgkey
    ON sessions (wg_public_key) WHERE state IN ('active', 'suspended');
CREATE INDEX IF NOT EXISTS sessions_live_device
    ON sessions (device_id) WHERE state IN ('active', 'suspended');
CREATE INDEX IF NOT EXISTS sessions_live_seen
    ON sessions (last_seen) WHERE state IN ('active', 'suspended');
CREATE INDEX IF NOT EXISTS sessions_user
    ON sessions (user_oid, created_at DESC);
CREATE INDEX IF NOT EXISTS sessions_created
    ON sessions (created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id      bigserial PRIMARY KEY,
    at      timestamptz NOT NULL,
    actor   text        NOT NULL,
    action  text        NOT NULL,
    target  text        NOT NULL DEFAULT '',
    detail  text        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_at ON audit_log (at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key    text PRIMARY KEY,
    value  text NOT NULL
);

CREATE TABLE IF NOT EXISTS speed_tests (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL,
    session_id  text        NOT NULL DEFAULT '',
    upn         text        NOT NULL,
    device_id   text        NOT NULL,
    kind        text        NOT NULL,
    down_bps    double precision NOT NULL,
    up_bps      double precision NOT NULL,
    latency_ms  integer     NOT NULL,
    network     text        NOT NULL DEFAULT '',
    auto        boolean     NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS speed_tests_device ON speed_tests (device_id, at DESC);

CREATE TABLE IF NOT EXISTS users (
    username       text PRIMARY KEY,
    display_name   text        NOT NULL DEFAULT '',
    password_hash  text        NOT NULL,
    role           text        NOT NULL,
    totp_secret    text        NOT NULL DEFAULT '',
    disabled       boolean     NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL,
    last_login     timestamptz NOT NULL DEFAULT 'epoch'
);

-- Per-user country access (see model.CountryPolicy).
ALTER TABLE users ADD COLUMN IF NOT EXISTS allowed_countries text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS travel_countries text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS travel_until timestamptz NOT NULL DEFAULT 'epoch';

-- Country each session connected from.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS country text NOT NULL DEFAULT '';

-- Commands from admins waiting for an agent (speed test, diagnostics, message).
CREATE TABLE IF NOT EXISTS session_commands (
    id          text PRIMARY KEY,
    session_id  text        NOT NULL,
    body        text        NOT NULL,
    created_at  timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS session_commands_session ON session_commands (session_id);

-- Devices that have tried to connect, and their approval status.
CREATE TABLE IF NOT EXISTS devices (
    id             text PRIMARY KEY,
    name           text        NOT NULL DEFAULT '',
    status         text        NOT NULL,
    platform       text        NOT NULL DEFAULT '',
    last_user      text        NOT NULL DEFAULT '',
    agent_version  text        NOT NULL DEFAULT '',
    first_seen     timestamptz NOT NULL,
    last_seen      timestamptz NOT NULL,
    decided_by     text        NOT NULL DEFAULT '',
    decided_at     timestamptz NOT NULL DEFAULT 'epoch'
);
CREATE INDEX IF NOT EXISTS devices_status ON devices (status, last_seen DESC);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_name text NOT NULL DEFAULT '';

-- "local" accounts have passwords; "entra" rows hold settings for Entra users.
ALTER TABLE users ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'local';

-- Latest device trust check (Entra identity, compliance, certificates) as JSON.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS trust text NOT NULL DEFAULT '';

-- Policy group picked for this user on the admin site ('' = automatic).
ALTER TABLE users ADD COLUMN IF NOT EXISTS policy_group text NOT NULL DEFAULT '';

-- Control servers report here so the admin site can show all of them (HA).
CREATE TABLE IF NOT EXISTS control_hosts (
    label    text PRIMARY KEY,
    metrics  text        NOT NULL,
    seen_at  timestamptz NOT NULL
);

-- Log bundles sent from agents for troubleshooting (newest 5 per device kept).
CREATE TABLE IF NOT EXISTS device_logs (
    id           text PRIMARY KEY,
    at           timestamptz NOT NULL,
    ref          text        NOT NULL,
    device_id    text        NOT NULL,
    device_name  text        NOT NULL DEFAULT '',
    upn          text        NOT NULL DEFAULT '',
    verified     boolean     NOT NULL DEFAULT false,
    reason       text        NOT NULL DEFAULT '',
    size         integer     NOT NULL,
    data         bytea       NOT NULL
);
CREATE INDEX IF NOT EXISTS device_logs_device ON device_logs (device_id, at DESC);

-- 'user' (a signed-in user) or 'device' (pre-logon device tunnel, device certificate only).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'user';
