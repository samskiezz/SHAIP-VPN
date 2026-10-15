package main

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PgStore is the Postgres-backed Store (schema in db/schema.sql).
type PgStore struct {
	pool *pgxpool.Pool
}

// NewPgStore connects to Postgres using the given URL.
func NewPgStore(ctx context.Context, url string) (*PgStore, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &PgStore{pool: pool}, nil
}

func (s *PgStore) Close() { s.pool.Close() }

func (s *PgStore) CreateUser(ctx context.Context, u *User) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (email, password_hash, identity_id, ml_dsa_pub, ed_pub)
		 VALUES ($1, $2, $3, $4, $5)`,
		u.Email, u.PasswordHash, u.IdentityID, u.MlDsaPub, u.EdPub)
	return err
}

func (s *PgStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, identity_id, ml_dsa_pub, ed_pub, created_at
		 FROM users WHERE email = $1`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IdentityID, &u.MlDsaPub, &u.EdPub, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PgStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, identity_id, ml_dsa_pub, ed_pub, created_at
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IdentityID, &u.MlDsaPub, &u.EdPub, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PgStore) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *PgStore) ListRoutingRules(ctx context.Context, userID string) ([]RoutingRule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, domain, route, priority
		 FROM routing_rules WHERE user_id = $1
		 ORDER BY priority DESC, domain`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]RoutingRule, 0)
	for rows.Next() {
		var r RoutingRule
		if err := rows.Scan(&r.ID, &r.UserID, &r.Domain, &r.Route, &r.Priority); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PgStore) CreateRoutingRule(ctx context.Context, r *RoutingRule) error {
	return s.pool.QueryRow(ctx,
		`INSERT INTO routing_rules (user_id, domain, route, priority)
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		r.UserID, r.Domain, r.Route, r.Priority).Scan(&r.ID)
}

func (s *PgStore) DeleteRoutingRule(ctx context.Context, id, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM routing_rules WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PgStore) ListNodes(ctx context.Context) ([]Node, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, address, public_key, status, stake_sats, delay_mean_ms, created_at
		 FROM nodes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.Address, &n.PublicKey,
			&n.Status, &n.StakeSats, &n.DelayMeanMs, &n.CreatedAt); err != nil {
			return nil, err
		}
		n.PublicKeyHex = hex.EncodeToString(n.PublicKey)
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *PgStore) CreateNode(ctx context.Context, n *Node) error {
	if n.Status == "" {
		n.Status = "offline"
	}
	_, err := s.pool.Exec(ctx,
		`INSERT INTO nodes (name, address, public_key, ed_pub, status, stake_sats, delay_mean_ms)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		n.Name, n.Address, n.PublicKey, n.PublicKey, n.Status, n.StakeSats, maxInt(n.DelayMeanMs, 50))
	return err
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

func (s *PgStore) ListActiveConnections(ctx context.Context) ([]Connection, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, user_id, node_id, route, bytes_in, bytes_out, started_at, ended_at
		 FROM connections WHERE ended_at IS NULL ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Connection
	for rows.Next() {
		var c Connection
		var ended *time.Time
		if err := rows.Scan(&c.ID, &c.UserID, &c.NodeID, &c.Route,
			&c.BytesIn, &c.BytesOut, &c.StartedAt, &ended); err != nil {
			return nil, err
		}
		c.EndedAt = ended
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PgStore) CountActiveConnections(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM connections WHERE ended_at IS NULL`).Scan(&n)
	return n, err
}

func (s *PgStore) EndConnection(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE connections SET ended_at = NOW() WHERE id = $1 AND ended_at IS NULL`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
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

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
