-- PQANON-CP/1 schema (§15). Target: PostgreSQL 16.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email          TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,               -- Argon2id (PHC string)
    identity_id    TEXT UNIQUE,
    ml_dsa_pub     BYTEA,
    ed_pub         BYTEA,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS nodes (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL,
    address        TEXT NOT NULL,
    public_key     BYTEA NOT NULL,               -- ML-DSA-65 pubkey
    ed_pub         BYTEA NOT NULL,               -- Ed25519 pubkey
    mix_pubkey     BYTEA,                         -- X25519 pubkey for mix role
    status         TEXT DEFAULT 'offline',
    stake_sats     BIGINT DEFAULT 0,
    delay_mean_ms  INT DEFAULT 50,
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connections (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID REFERENCES users(id) ON DELETE CASCADE,
    node_id        UUID REFERENCES nodes(id) ON DELETE SET NULL,
    route          TEXT CHECK (route IN ('fast','anon')),
    bytes_in       BIGINT DEFAULT 0,
    bytes_out      BIGINT DEFAULT 0,
    started_at     TIMESTAMPTZ DEFAULT NOW(),
    ended_at       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS routing_rules (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID REFERENCES users(id) ON DELETE CASCADE,
    domain         TEXT NOT NULL,
    route          TEXT CHECK (route IN ('fast','anon')),
    priority       INT DEFAULT 0
);

CREATE TABLE IF NOT EXISTS revoked_identities (
    identity_id    TEXT PRIMARY KEY,
    reason         TEXT,
    revoked_at     TIMESTAMPTZ DEFAULT NOW(),
    signature      BYTEA NOT NULL                -- ML-DSA-65 over (identity_id || reason || revoked_at)
);

CREATE TABLE IF NOT EXISTS cover_traffic_log (
    id             BIGSERIAL PRIMARY KEY,
    node_id        UUID REFERENCES nodes(id) ON DELETE CASCADE,
    rate_pps       NUMERIC NOT NULL,
    recorded       TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_connections_active ON connections(ended_at) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_conn_user          ON connections(user_id);
CREATE INDEX IF NOT EXISTS idx_nodes_status       ON nodes(status);
