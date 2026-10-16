package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"pqanon/control-plane/staking"
)

// PgStore is the Postgres-backed Store (schema in db/schema.sql).
type PgStore struct {
	pool *pgxpool.Pool
}

// NewPgStore connects to Postgres using the given URL and applies the embedded
// schema idempotently, so the control plane self-provisions its tables on first
// boot rather than relying on an out-of-band migration step.
func NewPgStore(ctx context.Context, url string) (*PgStore, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := applySchema(ctx, pool); err != nil {
		// Non-fatal: the tables may already exist from the compose init mount,
		// or the role may lack CREATE EXTENSION. Log loudly and continue so an
		// already-provisioned database still works, but a genuine misconfig is
		// visible rather than silently swallowed.
		log.Printf("WARNING: applying schema failed (%v); assuming the database is already provisioned", err)
	}
	return &PgStore{pool: pool}, nil
}

func (s *PgStore) Close() { s.pool.Close() }

func (s *PgStore) CreateUser(ctx context.Context, u *User) error {
	if u.Role == "" {
		u.Role = "user"
	}
	u.CreatedAt = day(time.Now())
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (account_number, password_hash, role, created_at)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		u.AccountNumber, u.PasswordHash, u.Role, u.CreatedAt).Scan(&u.ID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrAccountNumberTaken
	}
	return err
}

const userColumns = `id, account_number, password_hash, COALESCE(role,'user'), created_at`

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.AccountNumber, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) || isBadUUID(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PgStore) GetUserByAccount(ctx context.Context, number string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE account_number = $1`, number))
}

func (s *PgStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

func (s *PgStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// nodeColumns is the node projection shared by every node query.
const nodeColumns = `id, name, address, public_key, ed_pub, COALESCE(mix_pubkey, ''::bytea), role,
	capacity_mbps, region, COALESCE(owner_id::text, ''), status, stake_sats, jailed_at,
	delay_mean_ms, created_at`

func scanNode(row pgx.Row) (*Node, error) {
	var n Node
	if err := row.Scan(&n.ID, &n.Name, &n.Address, &n.PublicKey, &n.EdPub, &n.MixPub, &n.Role,
		&n.CapacityMbps, &n.Region, &n.OwnerID, &n.Status, &n.StakeSats, &n.JailedAt,
		&n.DelayMeanMs, &n.CreatedAt); err != nil {
		return nil, err
	}
	n.PublicKeyHex = hex.EncodeToString(n.PublicKey)
	n.EdPubHex = hex.EncodeToString(n.EdPub)
	n.MixPubHex = hex.EncodeToString(n.MixPub)
	return &n, nil
}

func (s *PgStore) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+nodeColumns+` FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

// CreateNode inserts a node and reports its generated id (until this returned
// it, POST /api/nodes answered with an empty id in Postgres mode).
func (s *PgStore) CreateNode(ctx context.Context, n *Node) error {
	if n.Status == "" {
		n.Status = "offline"
	}
	if n.Role == "" {
		n.Role = "mix"
	}
	if n.CapacityMbps == 0 {
		n.CapacityMbps = 100
	}
	var owner any
	if n.OwnerID != "" {
		owner = n.OwnerID
	}
	nonNil := func(b []byte) []byte {
		if b == nil {
			return []byte{}
		}
		return b
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO nodes (name, address, public_key, ed_pub, mix_pubkey, role, capacity_mbps,
		                    region, owner_id, status, stake_sats, delay_mean_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, created_at`,
		n.Name, n.Address, nonNil(n.PublicKey), nonNil(n.EdPub), n.MixPub, n.Role, n.CapacityMbps,
		n.Region, owner, n.Status, n.StakeSats, maxInt(n.DelayMeanMs, 50)).Scan(&n.ID, &n.CreatedAt)
	if err != nil {
		return err
	}
	n.EdPubHex = hex.EncodeToString(n.EdPub)
	n.MixPubHex = hex.EncodeToString(n.MixPub)
	return nil
}

func (s *PgStore) DeleteNode(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM nodes WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) GetNode(ctx context.Context, id string) (*Node, error) {
	n, err := scanNode(s.pool.QueryRow(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) || isBadUUID(err) {
		return nil, ErrNotFound
	}
	return n, err
}

// isBadUUID reports a malformed id: for a lookup that simply means "no such row".
func isBadUUID(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "22P02"
}

// isFKViolation reports a foreign-key violation (the referenced row is missing).
func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func (s *PgStore) CreateAPIKey(ctx context.Context, k *APIKey) error {
	k.CreatedAt = day(time.Now())
	return s.pool.QueryRow(ctx,
		`INSERT INTO api_keys (user_id, name, key_prefix, key_hash, created_at)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		k.UserID, k.Name, k.Prefix, k.KeyHash, k.CreatedAt).Scan(&k.ID)
}

func (s *PgStore) ListAPIKeys(ctx context.Context, userID string) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, name, key_prefix, key_hash, created_at, last_used_at
		 FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]APIKey, 0)
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Prefix, &k.KeyHash, &k.CreatedAt, &k.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *PgStore) DeleteAPIKey(ctx context.Context, id, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM api_keys WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) AppendAudit(ctx context.Context, e *AuditEntry) error {
	var uid any
	if e.UserID != "" {
		uid = e.UserID
	}
	e.At = day(time.Now())
	return s.pool.QueryRow(ctx,
		`INSERT INTO audit_log (user_id, action, detail, at)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		uid, e.Action, e.Detail, e.At).Scan(&e.ID)
}

func (s *PgStore) ListAudit(ctx context.Context, userID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	out := make([]AuditEntry, 0)
	if userID == "" {
		return out, nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id::text, action, COALESCE(detail,''), at
		 FROM audit_log WHERE user_id = $1 ORDER BY id DESC LIMIT $2`, userID, limit)
	if isBadUUID(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Detail, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PgStore) CreatePayOrder(ctx context.Context, o *PayOrder) error {
	bt, _ := json.Marshal(o.BlindedTokens)
	bs, _ := json.Marshal(o.BlindSigs)
	coarsenOrder(o, time.Now())
	return s.pool.QueryRow(ctx,
		`INSERT INTO pay_orders
		   (denom, rail, address, meta, amount_atomic, amount_label, uri, status,
		    blinded_tokens, blind_sigs, created_at, paid_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		 RETURNING id`,
		o.Denom, o.Rail, o.Address, o.Meta, int64(o.AmountAtomic), o.AmountLabel, o.URI,
		o.Status, string(bt), string(bs), o.CreatedAt, o.PaidAt, o.ExpiresAt).Scan(&o.ID)
}

func (s *PgStore) GetPayOrder(ctx context.Context, id string) (*PayOrder, error) {
	var o PayOrder
	var amt int64
	var bt, bs []byte
	err := s.pool.QueryRow(ctx,
		`SELECT id, denom, rail, address, meta, amount_atomic, amount_label, uri, status,
		        blinded_tokens, blind_sigs, created_at, paid_at, expires_at
		 FROM pay_orders WHERE id = $1`, id).
		Scan(&o.ID, &o.Denom, &o.Rail, &o.Address, &o.Meta, &amt, &o.AmountLabel, &o.URI, &o.Status,
			&bt, &bs, &o.CreatedAt, &o.PaidAt, &o.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	o.AmountAtomic = uint64(amt)
	_ = json.Unmarshal(bt, &o.BlindedTokens)
	_ = json.Unmarshal(bs, &o.BlindSigs)
	return &o, nil
}

func (s *PgStore) UpdatePayOrder(ctx context.Context, o *PayOrder) error {
	bs, _ := json.Marshal(o.BlindSigs)
	if o.PaidAt != nil {
		paid := day(*o.PaidAt)
		o.PaidAt = &paid
	}
	tag, err := s.pool.Exec(ctx,
		`UPDATE pay_orders
		   SET address = $2, meta = $3, amount_label = $4, uri = $5,
		       status = $6, paid_at = $7, blind_sigs = $8
		 WHERE id = $1`,
		o.ID, o.Address, o.Meta, o.AmountLabel, o.URI, o.Status, o.PaidAt, string(bs))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) SpendToken(ctx context.Context, denom, nonceHash string) error {
	// Atomic double-spend guard: the unique PK makes a second insert a no-op.
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO spent_tokens (denom, nonce_hash, spent_at) VALUES ($1, $2, $3)
		 ON CONFLICT (denom, nonce_hash) DO NOTHING`, denom, nonceHash, day(time.Now()))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrSpent
	}
	return nil
}

func (s *PgStore) ListRevoked(ctx context.Context) ([]RevokedIdentity, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT identity_id, reason, revoked_at, signature FROM revoked_identities`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RevokedIdentity
	for rows.Next() {
		var r RevokedIdentity
		if err := rows.Scan(&r.IdentityID, &r.Reason, &r.RevokedAt, &r.Signature); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PgStore) CreateEnrollToken(ctx context.Context, t *EnrollToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO enroll_tokens (token_id, user_id, issued_at, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		t.TokenID, t.UserID, day(t.IssuedAt), dayCeil(t.ExpiresAt))
	return err
}

// ClaimEnrollment consumes the token and inserts the device in one
// transaction. The row lock (FOR UPDATE) serializes concurrent claims of the
// same token, so exactly one succeeds; any failure rolls back both writes.
func (s *PgStore) ClaimEnrollment(ctx context.Context, tokenID string, now time.Time, d *Device) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) // no-op once committed

	var owner string
	var claimed *time.Time
	var expires time.Time
	err = tx.QueryRow(ctx,
		`SELECT user_id::text, claimed_at, expires_at FROM enroll_tokens
		 WHERE token_id = $1 FOR UPDATE`, tokenID).Scan(&owner, &claimed, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	switch {
	case owner != d.UserID:
		return ErrNotFound
	case claimed != nil:
		return ErrTokenClaimed
	case now.After(expires):
		return ErrTokenExpired
	}
	today := day(now)
	if _, err := tx.Exec(ctx,
		`UPDATE enroll_tokens SET claimed_at = $2 WHERE token_id = $1`, tokenID, today); err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO devices (id, user_id, name, ed_pub, token_id, cert_expires, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		d.ID, d.UserID, d.Name, d.EdPub, tokenID, d.CertExpires, today)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "devices_ed_pub_key" {
			return ErrDeviceKeyInUse
		}
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	d.TokenID = tokenID
	d.CreatedAt = today
	d.EdPubHex = hex.EncodeToString(d.EdPub)
	return nil
}

func (s *PgStore) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	return s.queryDevices(ctx,
		`SELECT id, user_id::text, name, ed_pub, token_id, cert_expires, created_at, revoked_at
		 FROM devices WHERE user_id = $1 ORDER BY created_at DESC`, userID)
}

func (s *PgStore) RevokeDevice(ctx context.Context, id, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE devices SET revoked_at = COALESCE(revoked_at, $3)
		 WHERE id = $1 AND user_id = $2`, id, userID, day(time.Now()))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) ListRevokedDevices(ctx context.Context) ([]Device, error) {
	return s.queryDevices(ctx,
		`SELECT id, user_id::text, name, ed_pub, token_id, cert_expires, created_at, revoked_at
		 FROM devices WHERE revoked_at IS NOT NULL ORDER BY id`)
}

func (s *PgStore) queryDevices(ctx context.Context, sql string, args ...any) ([]Device, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Device, 0)
	for rows.Next() {
		var d Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &d.EdPub, &d.TokenID,
			&d.CertExpires, &d.CreatedAt, &d.RevokedAt); err != nil {
			return nil, err
		}
		d.EdPubHex = hex.EncodeToString(d.EdPub)
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---- staking ---------------------------------------------------------------

const bondColumns = `id, node_id, amount_sats, rail, address, meta, amount_label, uri, status, created_at, credited_at`

func scanBond(row pgx.Row) (*StakeBond, error) {
	var b StakeBond
	err := row.Scan(&b.ID, &b.NodeID, &b.AmountSats, &b.Rail, &b.Quote.Address, &b.Quote.Meta,
		&b.Quote.AmountLabel, &b.Quote.URI, &b.Status, &b.CreatedAt, &b.CreditedAt)
	return &b, err
}

func (s *PgStore) CreateBond(ctx context.Context, b *StakeBond) error {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	if b.Status == "" {
		b.Status = "awaiting_payment"
	}
	err := s.pool.QueryRow(ctx,
		`INSERT INTO stake_bonds (id, node_id, amount_sats, rail, address, meta, amount_label, uri, status)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING created_at`,
		b.ID, b.NodeID, b.AmountSats, b.Rail, b.Quote.Address, b.Quote.Meta, b.Quote.AmountLabel,
		b.Quote.URI, b.Status).Scan(&b.CreatedAt)
	if isFKViolation(err) || isBadUUID(err) {
		return ErrNotFound
	}
	return err
}

func (s *PgStore) GetBond(ctx context.Context, id string) (*StakeBond, error) {
	b, err := scanBond(s.pool.QueryRow(ctx, `SELECT `+bondColumns+` FROM stake_bonds WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) || isBadUUID(err) {
		return nil, ErrNotFound
	}
	return b, err
}

func (s *PgStore) ListBonds(ctx context.Context, nodeID string) ([]StakeBond, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+bondColumns+` FROM stake_bonds WHERE node_id = $1 ORDER BY created_at`, nodeID)
	if isBadUUID(err) {
		return []StakeBond{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]StakeBond, 0)
	for rows.Next() {
		b, err := scanBond(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

func (s *PgStore) ListAwaitingBonds(ctx context.Context) ([]StakeBond, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+bondColumns+` FROM stake_bonds
		 WHERE status = 'awaiting_payment' AND created_at > $1 ORDER BY created_at LIMIT 10000`,
		time.Now().Add(-BondWatchWindow))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]StakeBond, 0)
	for rows.Next() {
		b, err := scanBond(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// CreditBond flips the bond to active and adds it to the node's stake in one
// transaction. The conditional UPDATE makes crediting exactly-once even under
// concurrent status checks.
func (s *PgStore) CreditBond(ctx context.Context, id string, now time.Time) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var nodeID string
	var amount int64
	err = tx.QueryRow(ctx,
		`UPDATE stake_bonds SET status = 'active', credited_at = $2
		 WHERE id = $1 AND status = 'awaiting_payment' RETURNING node_id, amount_sats`, id, now).
		Scan(&nodeID, &amount)
	if errors.Is(err, pgx.ErrNoRows) {
		// Check on the transaction's own connection: taking a second pool
		// connection while holding this one deadlocks once concurrent claims
		// exhaust the pool.
		var one int
		if gerr := tx.QueryRow(ctx, `SELECT 1 FROM stake_bonds WHERE id = $1`, id).Scan(&one); gerr != nil {
			if errors.Is(gerr, pgx.ErrNoRows) || isBadUUID(gerr) {
				return false, ErrNotFound
			}
			return false, gerr
		}
		return false, nil // already credited
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE nodes SET stake_sats = stake_sats + $2 WHERE id = $1`, nodeID, amount); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func (s *PgStore) Unbond(ctx context.Context, nodeID string, amount int64, releaseAt time.Time) error {
	if amount <= 0 {
		return ErrInsufficientStake
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx,
		`UPDATE nodes SET stake_sats = stake_sats - $2 WHERE id = $1 AND stake_sats >= $2`, nodeID, amount)
	if isBadUUID(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Same connection as the transaction (see CreditBond).
		var one int
		if gerr := tx.QueryRow(ctx, `SELECT 1 FROM nodes WHERE id = $1`, nodeID).Scan(&one); gerr != nil {
			if errors.Is(gerr, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return gerr
		}
		return ErrInsufficientStake
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO stake_unbondings (node_id, amount_sats, release_at) VALUES ($1, $2, $3)`,
		nodeID, amount, releaseAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PgStore) ListUnbondings(ctx context.Context, nodeID string) ([]Unbonding, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, node_id, amount_sats, release_at, created_at FROM stake_unbondings
		 WHERE node_id = $1 ORDER BY id`, nodeID)
	if isBadUUID(err) {
		return []Unbonding{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Unbonding, 0)
	for rows.Next() {
		var u Unbonding
		if err := rows.Scan(&u.ID, &u.NodeID, &u.AmountSats, &u.ReleaseAt, &u.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Slash records the (node, epoch) event first — its primary key makes a repeat
// a no-op — then cuts the bonded stake and every unreleased unbonding and
// jails the node, all in one transaction.
func (s *PgStore) Slash(ctx context.Context, nodeID string, epoch uint64, percent int, evidence string, now time.Time) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx,
		`INSERT INTO slash_events (node_id, epoch, slashed_sats, evidence, at) VALUES ($1, $2, 0, $3, $4)
		 ON CONFLICT (node_id, epoch) DO NOTHING`, nodeID, int64(epoch), evidence, now)
	if isFKViolation(err) || isBadUUID(err) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, ErrAlreadySlashed
	}
	var bonded int64
	if err := tx.QueryRow(ctx, `SELECT stake_sats FROM nodes WHERE id = $1 FOR UPDATE`, nodeID).Scan(&bonded); err != nil {
		return 0, err
	}
	total := staking.SlashCut(bonded, percent)
	if _, err := tx.Exec(ctx,
		`UPDATE nodes SET stake_sats = stake_sats - $2, jailed_at = COALESCE(jailed_at, $3) WHERE id = $1`,
		nodeID, total, now); err != nil {
		return 0, err
	}
	// Collect first: pgx cannot run statements while a result set is open.
	type entry struct {
		id     int64
		amount int64
	}
	var pending []entry
	rows, err := tx.Query(ctx,
		`SELECT id, amount_sats FROM stake_unbondings WHERE node_id = $1 AND release_at > $2 FOR UPDATE`,
		nodeID, now)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.amount); err != nil {
			rows.Close()
			return 0, err
		}
		pending = append(pending, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, e := range pending {
		c := staking.SlashCut(e.amount, percent)
		if _, err := tx.Exec(ctx, `UPDATE stake_unbondings SET amount_sats = amount_sats - $2 WHERE id = $1`, e.id, c); err != nil {
			return 0, err
		}
		total += c
	}
	if _, err := tx.Exec(ctx,
		`UPDATE slash_events SET slashed_sats = $3 WHERE node_id = $1 AND epoch = $2`,
		nodeID, int64(epoch), total); err != nil {
		return 0, err
	}
	return total, tx.Commit(ctx)
}

func (s *PgStore) ListSlashes(ctx context.Context, nodeID string) ([]SlashEvent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT node_id, epoch, slashed_sats, evidence, at FROM slash_events
		 WHERE node_id = $1 ORDER BY epoch`, nodeID)
	if isBadUUID(err) {
		return []SlashEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]SlashEvent, 0)
	for rows.Next() {
		var e SlashEvent
		var ep int64
		if err := rows.Scan(&e.NodeID, &ep, &e.SlashedSats, &e.Evidence, &e.At); err != nil {
			return nil, err
		}
		e.Epoch = uint64(ep)
		out = append(out, e)
	}
	return out, rows.Err()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
