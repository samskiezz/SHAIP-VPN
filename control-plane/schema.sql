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

-- Untraceable payments (§20): orders carry no identity, and spent_tokens is the
-- double-spend guard for redeemed e-cash nonces.
CREATE TABLE IF NOT EXISTS pay_orders (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    denom          TEXT NOT NULL,
    rail           TEXT NOT NULL,
    address        TEXT NOT NULL,
    meta           TEXT NOT NULL DEFAULT '',
    amount_atomic  BIGINT NOT NULL,
    amount_label   TEXT NOT NULL DEFAULT '',
    uri            TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'awaiting_payment'
                   CHECK (status IN ('awaiting_payment','paid','collected','expired')),
    blinded_tokens JSONB NOT NULL DEFAULT '[]'::jsonb,
    blind_sigs     JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paid_at        TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pay_orders_open ON pay_orders(status) WHERE status = 'awaiting_payment';

CREATE TABLE IF NOT EXISTS spent_tokens (
    denom       TEXT NOT NULL,
    nonce_hash  TEXT NOT NULL,
    spent_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (denom, nonce_hash)
);

-- One-click device enrollment (docs/enrollment.md): an issued token is claimed
-- at most once and binds one device's Ed25519 identity key to the account.
-- Revoked devices are published in the signed CRL so tunnel servers refuse them.
CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_id       TEXT PRIMARY KEY,                -- hex of the token's 16-byte id
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issued_at      TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    claimed_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS devices (
    id             TEXT PRIMARY KEY,                -- hex of the 16-byte device id
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL DEFAULT '',
    ed_pub         BYTEA NOT NULL UNIQUE,           -- the device's Ed25519 identity key
    token_id       TEXT NOT NULL REFERENCES enroll_tokens(token_id),
    cert_expires   TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMPTZ
);

-- Node staking (docs/staking.md). Stake is bonded by paying a real charge, is
-- locked through an unbonding period during which it stays slashable, and is
-- slashed only on cryptographic proof of equivocation (two conflicting signed
-- descriptors for one epoch). nodes.stake_sats is the bonded total, kept in step
-- with this ledger; only bonded, unjailed nodes enter the signed directory.
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS owner_id      UUID REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS role          TEXT NOT NULL DEFAULT 'mix';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS capacity_mbps INT  NOT NULL DEFAULT 100;
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS region        TEXT NOT NULL DEFAULT '';
ALTER TABLE nodes ADD COLUMN IF NOT EXISTS jailed_at     TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS stake_bonds (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id        UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    amount_sats    BIGINT NOT NULL CHECK (amount_sats > 0),
    rail           TEXT NOT NULL,
    address        TEXT NOT NULL,
    meta           TEXT NOT NULL DEFAULT '',
    amount_label   TEXT NOT NULL DEFAULT '',
    uri            TEXT NOT NULL DEFAULT '',
    status         TEXT NOT NULL DEFAULT 'awaiting_payment'
                   CHECK (status IN ('awaiting_payment','active')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    credited_at    TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS stake_unbondings (
    id             BIGSERIAL PRIMARY KEY,
    node_id        UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    amount_sats    BIGINT NOT NULL CHECK (amount_sats >= 0),
    release_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS slash_events (
    node_id        UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    epoch          BIGINT NOT NULL,
    slashed_sats   BIGINT NOT NULL,
    evidence       TEXT NOT NULL,                  -- the two conflicting descriptors
    at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (node_id, epoch)                   -- one slash per equivocation
);

CREATE INDEX IF NOT EXISTS idx_connections_active ON connections(ended_at) WHERE ended_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_conn_user          ON connections(user_id);
CREATE INDEX IF NOT EXISTS idx_nodes_status       ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_apikeys_user       ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user         ON audit_log(user_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_user       ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_revoked    ON devices(revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bonds_node         ON stake_bonds(node_id);
CREATE INDEX IF NOT EXISTS idx_unbondings_node    ON stake_unbondings(node_id, release_at);
