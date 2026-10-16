package main

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("not found")

// User is a registered account with pinned public identity keys.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	IdentityID   string    `json:"identity_id"`
	MlDsaPub     []byte    `json:"-"`
	EdPub        []byte    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// APIKey is a personal access token for the REST API. Only the hash is stored;
// the full secret is shown once at creation.
type APIKey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"-"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	KeyHash    string     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// AuditEntry is one row of the security audit log.
type AuditEntry struct {
	ID     int64     `json:"id"`
	UserID string    `json:"user_id,omitempty"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
	IP     string    `json:"ip,omitempty"`
	At     time.Time `json:"at"`
}

// ErrSpent is returned when a token nonce has already been redeemed.
var ErrSpent = errors.New("token already spent")

// PayOrder is one untraceable purchase: a denomination, a payment address, and
// the buyer's blinded tokens (and, after collection, the blind signatures). It
// carries no identity — nothing links it to a person or to the tokens once they
// are unblinded and redeemed.
type PayOrder struct {
	ID            string     `json:"id"`
	Denom         string     `json:"denom"`
	Rail          string     `json:"rail"`
	Address       string     `json:"address"`
	Meta          string     `json:"-"`
	AmountAtomic  uint64     `json:"amount_atomic"` // Monero piconero (canonical record)
	AmountLabel   string     `json:"amount_label"`  // what to pay, in the chosen coin
	URI           string     `json:"uri,omitempty"`
	Status        string     `json:"status"`
	BlindedTokens [][]byte   `json:"-"`
	BlindSigs     [][]byte   `json:"-"`
	CreatedAt     time.Time  `json:"created_at"`
	PaidAt        *time.Time `json:"paid_at,omitempty"`
	ExpiresAt     time.Time  `json:"expires_at"`
}

// Node is a tunnel/mix server participating in the network.
type Node struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Address      string    `json:"address"`
	PublicKey    []byte    `json:"-"`
	PublicKeyHex string    `json:"public_key"`
	Status       string    `json:"status"`
	StakeSats    int64     `json:"stake_sats"`
	DelayMeanMs  int       `json:"delay_mean_ms"`
	CreatedAt    time.Time `json:"created_at"`
}

// Connection is an active or historical tunnel session.
type Connection struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	NodeID    string     `json:"node_id"`
	Route     string     `json:"route"`
	BytesIn   int64      `json:"bytes_in"`
	BytesOut  int64      `json:"bytes_out"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

// RevokedIdentity is a CRL entry.
type RevokedIdentity struct {
	IdentityID string    `json:"identity_id"`
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
	Signature  []byte    `json:"-"`
}

// RoutingRule is a per-user fast/anon policy for a destination domain (§13).
// Higher priority wins when multiple rules match.
type RoutingRule struct {
	ID       string `json:"id"`
	UserID   string `json:"-"`
	Domain   string `json:"domain"`
	Route    string `json:"route"`
	Priority int    `json:"priority"`
}

// Store is the persistence interface. Two implementations exist: an in-memory
// store (default, so the control plane boots with no database) and a Postgres
// store (used when DATABASE_URL is set).
type Store interface {
	CreateUser(ctx context.Context, u *User) error
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	CountUsers(ctx context.Context) (int, error)

	ListNodes(ctx context.Context) ([]Node, error)
	GetNode(ctx context.Context, id string) (*Node, error)
	CreateNode(ctx context.Context, n *Node) error
	DeleteNode(ctx context.Context, id string) error

	ListActiveConnections(ctx context.Context) ([]Connection, error)
	GetConnection(ctx context.Context, id string) (*Connection, error)
	CountActiveConnections(ctx context.Context) (int, error)
	EndConnection(ctx context.Context, id string) error

	CreateAPIKey(ctx context.Context, k *APIKey) error
	ListAPIKeys(ctx context.Context, userID string) ([]APIKey, error)
	DeleteAPIKey(ctx context.Context, id, userID string) error

	AppendAudit(ctx context.Context, e *AuditEntry) error
	ListAudit(ctx context.Context, userID string, limit int) ([]AuditEntry, error)

	CreatePayOrder(ctx context.Context, o *PayOrder) error
	GetPayOrder(ctx context.Context, id string) (*PayOrder, error)
	UpdatePayOrder(ctx context.Context, o *PayOrder) error
	// SpendToken records a redeemed nonce, returning ErrSpent if already spent.
	SpendToken(ctx context.Context, denom, nonceHash string) error

	ListRoutingRules(ctx context.Context, userID string) ([]RoutingRule, error)
	CreateRoutingRule(ctx context.Context, r *RoutingRule) error
	DeleteRoutingRule(ctx context.Context, id, userID string) error

	// GetSettings returns a user's stored settings JSON, or ErrNotFound.
	GetSettings(ctx context.Context, userID string) ([]byte, error)
	SetSettings(ctx context.Context, userID string, raw []byte) error

	ListRevoked(ctx context.Context) ([]RevokedIdentity, error)

	Close()
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

type MemStore struct {
	mu      sync.RWMutex
	users   map[string]*User // keyed by email
	nodes   map[string]*Node // keyed by id
	conns    map[string]*Connection
	rules    map[string]*RoutingRule // keyed by rule id
	settings map[string][]byte       // keyed by user id
	revoked  map[string]*RevokedIdentity
	apiKeys  map[string]*APIKey // keyed by key id
	audit    []AuditEntry
	auditSeq int64
	orders   map[string]*PayOrder // keyed by order id
	spent    map[string]bool      // keyed by denom|nonce_hash
}

func NewMemStore() *MemStore {
	return &MemStore{
		users:    make(map[string]*User),
		nodes:    make(map[string]*Node),
		conns:    make(map[string]*Connection),
		rules:    make(map[string]*RoutingRule),
		settings: make(map[string][]byte),
		revoked:  make(map[string]*RevokedIdentity),
		apiKeys:  make(map[string]*APIKey),
		orders:   make(map[string]*PayOrder),
		spent:    make(map[string]bool),
	}
}

func (m *MemStore) Close() {}

func (m *MemStore) CreateUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.Email]; ok {
		return errors.New("email already registered")
	}
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.Role == "" {
		u.Role = "user"
	}
	u.CreatedAt = time.Now().UTC()
	cp := *u
	m.users[u.Email] = &cp
	return nil
}

func (m *MemStore) GetUserByEmail(_ context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[email]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (m *MemStore) GetUserByID(_ context.Context, id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.users {
		if u.ID == id {
			cp := *u
			return &cp, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) CountUsers(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
}

func (m *MemStore) ListRoutingRules(_ context.Context, userID string) ([]RoutingRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]RoutingRule, 0)
	for _, r := range m.rules {
		if r.UserID == userID {
			out = append(out, *r)
		}
	}
	// Highest priority first, then domain, for a stable order.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].Domain < out[j].Domain
	})
	return out, nil
}

func (m *MemStore) CreateRoutingRule(_ context.Context, r *RoutingRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	cp := *r
	m.rules[r.ID] = &cp
	return nil
}

func (m *MemStore) DeleteRoutingRule(_ context.Context, id, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rules[id]
	if !ok || r.UserID != userID {
		return ErrNotFound
	}
	delete(m.rules, id)
	return nil
}

func (m *MemStore) GetSettings(_ context.Context, userID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	raw, ok := m.settings[userID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(raw))
	copy(cp, raw)
	return cp, nil
}

func (m *MemStore) SetSettings(_ context.Context, userID string, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(raw))
	copy(cp, raw)
	m.settings[userID] = cp
	return nil
}

func (m *MemStore) ListNodes(_ context.Context) ([]Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		out = append(out, *n)
	}
	return out, nil
}

func (m *MemStore) CreateNode(_ context.Context, n *Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n.ID == "" {
		n.ID = uuid.NewString()
	}
	if n.Status == "" {
		n.Status = "offline"
	}
	n.CreatedAt = time.Now().UTC()
	cp := *n
	m.nodes[n.ID] = &cp
	return nil
}

func (m *MemStore) DeleteNode(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[id]; !ok {
		return ErrNotFound
	}
	delete(m.nodes, id)
	return nil
}

func (m *MemStore) ListActiveConnections(_ context.Context) ([]Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Connection, 0, len(m.conns))
	for _, c := range m.conns {
		if c.EndedAt == nil {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (m *MemStore) CountActiveConnections(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n := 0
	for _, c := range m.conns {
		if c.EndedAt == nil {
			n++
		}
	}
	return n, nil
}

func (m *MemStore) EndConnection(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.conns[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now().UTC()
	c.EndedAt = &now
	return nil
}

func (m *MemStore) GetNode(_ context.Context, id string) (*Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.nodes[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *n
	return &cp, nil
}

func (m *MemStore) GetConnection(_ context.Context, id string) (*Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.conns[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *MemStore) CreateAPIKey(_ context.Context, k *APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k.ID == "" {
		k.ID = uuid.NewString()
	}
	k.CreatedAt = time.Now().UTC()
	cp := *k
	m.apiKeys[k.ID] = &cp
	return nil
}

func (m *MemStore) ListAPIKeys(_ context.Context, userID string) ([]APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]APIKey, 0)
	for _, k := range m.apiKeys {
		if k.UserID == userID {
			out = append(out, *k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) DeleteAPIKey(_ context.Context, id, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.apiKeys[id]
	if !ok || k.UserID != userID {
		return ErrNotFound
	}
	delete(m.apiKeys, id)
	return nil
}

func (m *MemStore) AppendAudit(_ context.Context, e *AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auditSeq++
	e.ID = m.auditSeq
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}
	m.audit = append(m.audit, *e)
	return nil
}

func (m *MemStore) ListAudit(_ context.Context, userID string, limit int) ([]AuditEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	out := make([]AuditEntry, 0, limit)
	// Newest first.
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		if userID == "" || m.audit[i].UserID == userID {
			out = append(out, m.audit[i])
		}
	}
	return out, nil
}

func (m *MemStore) CreatePayOrder(_ context.Context, o *PayOrder) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if o.ID == "" {
		o.ID = uuid.NewString()
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now().UTC()
	}
	cp := *o
	m.orders[o.ID] = &cp
	return nil
}

func (m *MemStore) GetPayOrder(_ context.Context, id string) (*PayOrder, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.orders[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *o
	return &cp, nil
}

func (m *MemStore) UpdatePayOrder(_ context.Context, o *PayOrder) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orders[o.ID]; !ok {
		return ErrNotFound
	}
	cp := *o
	m.orders[o.ID] = &cp
	return nil
}

func (m *MemStore) SpendToken(_ context.Context, denom, nonceHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := denom + "|" + nonceHash
	if m.spent[key] {
		return ErrSpent
	}
	m.spent[key] = true
	return nil
}

func (m *MemStore) ListRevoked(_ context.Context) ([]RevokedIdentity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]RevokedIdentity, 0, len(m.revoked))
	for _, r := range m.revoked {
		out = append(out, *r)
	}
	return out, nil
}

// SeedDemo inserts a couple of nodes so a fresh in-memory instance isn't empty.
func (m *MemStore) SeedDemo() {
	_ = m.CreateNode(context.Background(), &Node{
		Name: "tokyo-01", Address: "203.0.113.10:443", Status: "online",
		StakeSats: 1_000_000, DelayMeanMs: 50,
	})
	_ = m.CreateNode(context.Background(), &Node{
		Name: "frankfurt-01", Address: "198.51.100.20:443", Status: "online",
		StakeSats: 750_000, DelayMeanMs: 50,
	})
}
