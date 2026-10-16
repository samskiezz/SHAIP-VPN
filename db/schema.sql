-- PQANON-CP/1 schema (§15). Target: PostgreSQL 16.
--
-- This file is embedded into the control-plane binary (migrate.go) and applied
-- idempotently at startup, so the schema exists no matter how Postgres is
-- provisioned. It is kept byte-identical to db/schema.sql, which docker-compose
-- mounts into the database's init directory; schema_embed_test.go fails the
-- build if the two ever diverge.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Nothing in this schema identifies a customer (docs/privacy-policy.md). An
-- account is a random account number and a password hash: no email, no name,
-- no IP address. Times on customer records are UTC days, not moments, so they
-- can't be matched against network logs kept elsewhere. There is no table of
-- connections, traffic or destinations.

CREATE TABLE IF NOT EXISTS users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_number TEXT UNIQUE NOT NULL,          -- 16 random digits: the login
    password_hash  TEXT NOT NULL,                 -- Argon2id (PHC string)
    role           TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin','support')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT date_trunc('day', now(), 'UTC')
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
    created_at     TIMESTAMPTZ NOT NULL DEFAULT date_trunc('day', now(), 'UTC'),
    last_used_at   TIMESTAMPTZ
);

-- An account's own security log: what was done (a device enrolled, a key
-- created), on which day. Never from where: there is no address column.
CREATE TABLE IF NOT EXISTS audit_log (
    id             BIGSERIAL PRIMARY KEY,
    user_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    action         TEXT NOT NULL,
    detail         TEXT,
    at             TIMESTAMPTZ NOT NULL DEFAULT date_trunc('day', now(), 'UTC')
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
    created_at     TIMESTAMPTZ NOT NULL DEFAULT date_trunc('day', now(), 'UTC'),
    paid_at        TIMESTAMPTZ,
    expires_at     TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pay_orders_open ON pay_orders(status) WHERE status = 'awaiting_payment';

CREATE TABLE IF NOT EXISTS spent_tokens (
    denom       TEXT NOT NULL,
    nonce_hash  TEXT NOT NULL,
    spent_at    TIMESTAMPTZ NOT NULL DEFAULT date_trunc('day', now(), 'UTC'),
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
    name           TEXT NOT NULL DEFAULT 'device',  -- a platform label, never free text
    ed_pub         BYTEA NOT NULL UNIQUE,           -- the device's Ed25519 identity key
    token_id       TEXT NOT NULL REFERENCES enroll_tokens(token_id),
    cert_expires   TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT date_trunc('day', now(), 'UTC'),
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

CREATE INDEX IF NOT EXISTS idx_nodes_status       ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_apikeys_user       ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_user_seq     ON audit_log(user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_devices_user       ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_revoked    ON devices(revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bonds_node         ON stake_bonds(node_id);
CREATE INDEX IF NOT EXISTS idx_unbondings_node    ON stake_unbondings(node_id, release_at);

-- ---------------------------------------------------------------------------
-- Databases created before the no-personal-data rule held customer data this
-- version never collects. These statements remove it, and are no-ops on a
-- database that never had it. Upgrading an existing database with real
-- accounts: read "Upgrading" in docs/privacy-policy.md first, because accounts
-- that predate account numbers are given one here that nobody has been told.
-- ---------------------------------------------------------------------------

-- Accounts: a random account number replaces the email address. The VPN
-- identity keys some accounts pinned are dropped too; devices enroll instead.
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_number TEXT UNIQUE;
UPDATE users SET account_number = lpad(((((
        'x' || encode(gen_random_bytes(8), 'hex'))::bit(64)::bigint & 9223372036854775807)
        % 10000000000000000)::text), 16, '0')
 WHERE account_number IS NULL;
ALTER TABLE users ALTER COLUMN account_number SET NOT NULL;
ALTER TABLE users DROP COLUMN IF EXISTS email;
ALTER TABLE users DROP COLUMN IF EXISTS identity_id;
ALTER TABLE users DROP COLUMN IF EXISTS ml_dsa_pub;
ALTER TABLE users DROP COLUMN IF EXISTS ed_pub;

-- A per-account connection log, per-account domain lists, and free-form
-- per-account settings: none of these is kept any more.
DROP TABLE IF EXISTS connections;
DROP TABLE IF EXISTS routing_rules;
DROP TABLE IF EXISTS user_settings;

-- The security log keeps no address, no anonymous redemption times, and no
-- device names (old entries carried the name after the id).
ALTER TABLE audit_log DROP COLUMN IF EXISTS ip;
DELETE FROM audit_log WHERE user_id IS NULL AND action = 'token.redeem';
UPDATE audit_log SET detail = split_part(detail, ' ', 1)
 WHERE action = 'device.enroll' AND detail LIKE '% %';
DROP INDEX IF EXISTS idx_audit_user;               -- was (user_id, at): see idx_audit_user_seq

-- Device names were free text (some clients sent the OS's device name, which
-- often contains the owner's name). Only the platform it names remains, as
-- deviceLabel does for new devices.
UPDATE devices SET name = CASE
        WHEN name ILIKE '%iphone%'  THEN 'iPhone'
        WHEN name ILIKE '%ipad%'    THEN 'iPad'
        WHEN name ILIKE '%android%' THEN 'Android'
        WHEN name ILIKE '%windows%' THEN 'Windows'
        WHEN name ILIKE '%linux%'   THEN 'Linux'
        WHEN name ILIKE '%mac%'     THEN 'Mac'
        ELSE 'device' END
 WHERE name NOT IN ('iPhone', 'iPad', 'Android', 'Windows', 'Linux', 'Mac', 'device');

-- Moments become days, and the defaults that wrote moments write days.
DO $$
DECLARE c record;
BEGIN
    FOR c IN SELECT * FROM (VALUES
        ('users', 'created_at', true), ('api_keys', 'created_at', true),
        ('api_keys', 'last_used_at', false), ('audit_log', 'at', true),
        ('enroll_tokens', 'issued_at', false), ('enroll_tokens', 'claimed_at', false),
        ('devices', 'created_at', true), ('devices', 'revoked_at', false),
        ('devices', 'cert_expires', false), ('spent_tokens', 'spent_at', true),
        ('pay_orders', 'created_at', true), ('pay_orders', 'paid_at', false)) AS t(tbl, col, dflt)
    LOOP
        EXECUTE format('UPDATE %I SET %I = date_trunc(''day'', %I, ''UTC'') '
                       'WHERE %I <> date_trunc(''day'', %I, ''UTC'')',
                       c.tbl, c.col, c.col, c.col, c.col);
        IF c.dflt THEN
            EXECUTE format('ALTER TABLE %I ALTER COLUMN %I SET DEFAULT date_trunc(''day'', now(), ''UTC'')',
                           c.tbl, c.col);
        END IF;
    END LOOP;
END $$;
UPDATE enroll_tokens SET expires_at = date_trunc('day', expires_at, 'UTC') + interval '1 day'
 WHERE expires_at <> date_trunc('day', expires_at, 'UTC');
UPDATE pay_orders SET expires_at = date_trunc('day', expires_at, 'UTC') + interval '1 day'
 WHERE expires_at <> date_trunc('day', expires_at, 'UTC');
