-- PQANON-CP/1 schema (§15). Target: PostgreSQL 16.
--
-- This file is embedded into the control-plane binary (migrate.go) and applied
-- idempotently at startup, so the schema exists no matter how Postgres is
-- provisioned. It is kept byte-identical to db/schema.sql, which docker-compose
-- mounts into the database's init directory; schema_embed_test.go fails the
-- build if the two ever diverge.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email          TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,               -- Argon2id (PHC string)
    identity_id    TEXT UNIQUE,
    ml_dsa_pub     BYTEA,
    ed_pub         BYTEA,
    role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin','support')),
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

CREATE TABLE IF NOT EXISTS user_settings (
    user_id    UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings   JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

CREATE TABLE IF NOT EXISTS api_keys (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    key_prefix     TEXT NOT NULL,                -- first 8 chars, shown in the UI
    key_hash       TEXT NOT NULL,                -- SHA-256 of the full key
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL PRIMARY KEY,
    user_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    action         TEXT NOT NULL,
    detail         TEXT,
    ip             TEXT,
    at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_connections_active ON connections(ended_at) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_conn_user          ON connections(user_id);
CREATE INDEX IF NOT EXISTS idx_nodes_status       ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_apikeys_user       ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user         ON audit_log(user_id, at DESC);
