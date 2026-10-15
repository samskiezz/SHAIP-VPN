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
	CreatedAt    time.Time `json:"created_at"`
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
	CreateNode(ctx context.Context, n *Node) error
	DeleteNode(ctx context.Context, id string) error

	ListActiveConnections(ctx context.Context) ([]Connection, error)
	CountActiveConnections(ctx context.Context) (int, error)
	EndConnection(ctx context.Context, id string) error

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
}

func NewMemStore() *MemStore {
	return &MemStore{
		users:    make(map[string]*User),
		nodes:    make(map[string]*Node),
		conns:    make(map[string]*Connection),
		rules:    make(map[string]*RoutingRule),
		settings: make(map[string][]byte),
		revoked:  make(map[string]*RevokedIdentity),
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
