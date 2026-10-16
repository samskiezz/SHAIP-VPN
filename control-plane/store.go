package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"pqanon/control-plane/staking"
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

// Enrollment errors. ClaimEnrollment returns exactly one of these (or
// ErrNotFound) and changes nothing when it does.
var (
	ErrTokenClaimed   = errors.New("enrollment token already used")
	ErrTokenExpired   = errors.New("enrollment token expired")
	ErrDeviceKeyInUse = errors.New("device key already enrolled")
)

// EnrollToken records an issued enrollment token so it can be claimed once.
type EnrollToken struct {
	TokenID   string // hex of the token's 16-byte id
	UserID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	ClaimedAt *time.Time
}

// Device is an enrolled device: its Ed25519 identity key, bound to an account
// by a device certificate.
type Device struct {
	ID          string     `json:"id"` // hex of the 16-byte device id
	UserID      string     `json:"-"`
	Name        string     `json:"name"`
	EdPub       []byte     `json:"-"`
	EdPubHex    string     `json:"ed_pub"`
	TokenID     string     `json:"-"`
	CertExpires time.Time  `json:"cert_expires"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// Node is a tunnel/mix server participating in the network.
type Node struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Address      string `json:"address"`
	PublicKey    []byte `json:"-"`
	PublicKeyHex string `json:"public_key"`
	// EdPub is the node's Ed25519 key: it signs the node's per-epoch
	// descriptors, so it is what slashing evidence is verified against.
	EdPub        []byte `json:"-"`
	EdPubHex     string `json:"ed_pub,omitempty"`
	MixPub       []byte `json:"-"` // X25519 onion key (mix role)
	MixPubHex    string `json:"mix_pub,omitempty"`
	Role         string `json:"role"`
	CapacityMbps int    `json:"capacity_mbps"`
	Region       string `json:"region"`
	OwnerID      string `json:"-"`
	Status       string `json:"status"`
	// StakeSats is the bonded stake: paid bonds, minus unbonded and slashed
	// amounts. It is never set directly by an API caller.
	StakeSats   int64      `json:"stake_sats"`
	JailedAt    *time.Time `json:"jailed_at,omitempty"`
	DelayMeanMs int        `json:"delay_mean_ms"`
	CreatedAt   time.Time  `json:"created_at"`
}

// BondWatchWindow bounds how long an unpaid bond is still checked for payment.
const BondWatchWindow = 7 * 24 * time.Hour

// Staking errors.
var (
	ErrInsufficientStake = errors.New("insufficient bonded stake")
	ErrAlreadySlashed    = errors.New("node already slashed for this epoch")
)

// StakeBond is one payment that bonds stake to a node. It counts only once its
// charge is paid (status "active").
type StakeBond struct {
	ID         string     `json:"id"`
	NodeID     string     `json:"node_id"`
	AmountSats int64      `json:"amount_sats"`
	Rail       string     `json:"rail"`
	Quote      RailQuote  `json:"-"`
	Status     string     `json:"status"` // awaiting_payment | active
	CreatedAt  time.Time  `json:"created_at"`
	CreditedAt *time.Time `json:"credited_at,omitempty"`
}

// Unbonding is stake leaving a node. It stays slashable until ReleaseAt.
type Unbonding struct {
	ID         int64     `json:"id"`
	NodeID     string    `json:"-"`
	AmountSats int64     `json:"amount_sats"`
	ReleaseAt  time.Time `json:"release_at"`
	CreatedAt  time.Time `json:"created_at"`
}

// SlashEvent records one slash: at most one per (node, epoch).
type SlashEvent struct {
	NodeID      string    `json:"-"`
	Epoch       uint64    `json:"epoch"`
	SlashedSats int64     `json:"slashed_sats"`
	Evidence    string    `json:"evidence"`
	At          time.Time `json:"at"`
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

	CreateEnrollToken(ctx context.Context, t *EnrollToken) error
	// ClaimEnrollment atomically consumes the token and records the device. It
	// fails with ErrNotFound (unknown token, or one issued to another account),
	// ErrTokenClaimed, ErrTokenExpired, or ErrDeviceKeyInUse — and then changes
	// nothing, so a failed claim never burns the token.
	ClaimEnrollment(ctx context.Context, tokenID string, now time.Time, d *Device) error
	ListDevices(ctx context.Context, userID string) ([]Device, error)
	// RevokeDevice marks one of the user's devices revoked. Revoking twice keeps
	// the first timestamp. ErrNotFound if the device is not theirs.
	RevokeDevice(ctx context.Context, id, userID string) error
	ListRevokedDevices(ctx context.Context) ([]Device, error)

	CreateBond(ctx context.Context, b *StakeBond) error
	GetBond(ctx context.Context, id string) (*StakeBond, error)
	ListBonds(ctx context.Context, nodeID string) ([]StakeBond, error)
	// ListAwaitingBonds returns unpaid bonds from the last BondWatchWindow, for
	// the bond watcher (older unpaid charges have long expired on their rail).
	ListAwaitingBonds(ctx context.Context) ([]StakeBond, error)
	// CreditBond activates an awaiting bond and adds it to the node's bonded
	// stake, exactly once: a second call reports false and changes nothing.
	CreditBond(ctx context.Context, id string, now time.Time) (bool, error)
	// Unbond moves amount from bonded stake into an unbonding entry released at
	// releaseAt, or fails with ErrInsufficientStake and changes nothing.
	Unbond(ctx context.Context, nodeID string, amount int64, releaseAt time.Time) error
	ListUnbondings(ctx context.Context, nodeID string) ([]Unbonding, error)
	// Slash atomically removes percent of the node's bonded stake and of every
	// unbonding entry not yet released, jails the node, and records the event.
	// It returns the amount slashed, or ErrAlreadySlashed for a repeat (node,
	// epoch), changing nothing.
	Slash(ctx context.Context, nodeID string, epoch uint64, percent int, evidence string, now time.Time) (int64, error)
	ListSlashes(ctx context.Context, nodeID string) ([]SlashEvent, error)

	Close()
}

// ---------------------------------------------------------------------------
// In-memory store
// ---------------------------------------------------------------------------

type MemStore struct {
	mu       sync.RWMutex
	users    map[string]*User // keyed by email
	nodes    map[string]*Node // keyed by id
	conns    map[string]*Connection
	rules    map[string]*RoutingRule // keyed by rule id
	settings map[string][]byte       // keyed by user id
	revoked  map[string]*RevokedIdentity
	apiKeys  map[string]*APIKey // keyed by key id
	audit    []AuditEntry
	auditSeq int64
	orders   map[string]*PayOrder    // keyed by order id
	spent    map[string]bool         // keyed by denom|nonce_hash
	enroll   map[string]*EnrollToken // keyed by token id
	devices  map[string]*Device      // keyed by device id
	bonds    map[string]*StakeBond   // keyed by bond id
	unbonds  []Unbonding
	unbondSq int64
	slashes  map[string]*SlashEvent // keyed by node id|epoch
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
		enroll:   make(map[string]*EnrollToken),
		devices:  make(map[string]*Device),
		bonds:    make(map[string]*StakeBond),
		slashes:  make(map[string]*SlashEvent),
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
	// Mirror the database column defaults so both stores behave alike.
	if n.Role == "" {
		n.Role = "mix"
	}
	if n.CapacityMbps == 0 {
		n.CapacityMbps = 100
	}
	n.EdPubHex = hex.EncodeToString(n.EdPub)
	n.MixPubHex = hex.EncodeToString(n.MixPub)
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

func (m *MemStore) CreateEnrollToken(_ context.Context, t *EnrollToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.enroll[t.TokenID]; ok {
		return errors.New("enrollment token id already exists")
	}
	cp := *t
	m.enroll[t.TokenID] = &cp
	return nil
}

func (m *MemStore) ClaimEnrollment(_ context.Context, tokenID string, now time.Time, d *Device) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.enroll[tokenID]
	if !ok || t.UserID != d.UserID {
		return ErrNotFound
	}
	if t.ClaimedAt != nil {
		return ErrTokenClaimed
	}
	if now.After(t.ExpiresAt) {
		return ErrTokenExpired
	}
	for _, x := range m.devices {
		if bytes.Equal(x.EdPub, d.EdPub) {
			return ErrDeviceKeyInUse
		}
	}
	claimed := now.UTC()
	t.ClaimedAt = &claimed
	d.TokenID = tokenID
	d.CreatedAt = claimed
	d.EdPubHex = hex.EncodeToString(d.EdPub)
	cp := *d
	m.devices[d.ID] = &cp
	return nil
}

func (m *MemStore) ListDevices(_ context.Context, userID string) ([]Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Device, 0)
	for _, d := range m.devices {
		if d.UserID == userID {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) RevokeDevice(_ context.Context, id, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.devices[id]
	if !ok || d.UserID != userID {
		return ErrNotFound
	}
	if d.RevokedAt == nil {
		now := time.Now().UTC()
		d.RevokedAt = &now
	}
	return nil
}

func (m *MemStore) ListRevokedDevices(_ context.Context) ([]Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Device, 0)
	for _, d := range m.devices {
		if d.RevokedAt != nil {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) CreateBond(_ context.Context, b *StakeBond) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.nodes[b.NodeID]; !ok {
		return ErrNotFound
	}
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	if b.Status == "" {
		b.Status = "awaiting_payment"
	}
	b.CreatedAt = time.Now().UTC()
	cp := *b
	m.bonds[b.ID] = &cp
	return nil
}

func (m *MemStore) GetBond(_ context.Context, id string) (*StakeBond, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.bonds[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *b
	return &cp, nil
}

func (m *MemStore) ListBonds(_ context.Context, nodeID string) ([]StakeBond, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]StakeBond, 0)
	for _, b := range m.bonds {
		if b.NodeID == nodeID {
			out = append(out, *b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) ListAwaitingBonds(_ context.Context) ([]StakeBond, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	since := time.Now().Add(-BondWatchWindow)
	out := make([]StakeBond, 0)
	for _, b := range m.bonds {
		if b.Status == "awaiting_payment" && b.CreatedAt.After(since) {
			out = append(out, *b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) CreditBond(_ context.Context, id string, now time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.bonds[id]
	if !ok {
		return false, ErrNotFound
	}
	if b.Status != "awaiting_payment" {
		return false, nil
	}
	n, ok := m.nodes[b.NodeID]
	if !ok {
		return false, ErrNotFound
	}
	t := now.UTC()
	b.Status, b.CreditedAt = "active", &t
	n.StakeSats += b.AmountSats
	return true, nil
}

func (m *MemStore) Unbond(_ context.Context, nodeID string, amount int64, releaseAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return ErrNotFound
	}
	if amount <= 0 || n.StakeSats < amount {
		return ErrInsufficientStake
	}
	n.StakeSats -= amount
	m.unbondSq++
	m.unbonds = append(m.unbonds, Unbonding{
		ID: m.unbondSq, NodeID: nodeID, AmountSats: amount, ReleaseAt: releaseAt.UTC(), CreatedAt: time.Now().UTC(),
	})
	return nil
}

func (m *MemStore) ListUnbondings(_ context.Context, nodeID string) ([]Unbonding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Unbonding, 0)
	for _, u := range m.unbonds {
		if u.NodeID == nodeID {
			out = append(out, u)
		}
	}
	return out, nil
}

func (m *MemStore) Slash(_ context.Context, nodeID string, epoch uint64, percent int, evidence string, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.nodes[nodeID]
	if !ok {
		return 0, ErrNotFound
	}
	key := nodeID + "|" + strconv.FormatUint(epoch, 10)
	if _, done := m.slashes[key]; done {
		return 0, ErrAlreadySlashed
	}
	cut := staking.SlashCut(n.StakeSats, percent)
	n.StakeSats -= cut
	total := cut
	for i := range m.unbonds {
		u := &m.unbonds[i]
		if u.NodeID == nodeID && u.ReleaseAt.After(now) {
			c := staking.SlashCut(u.AmountSats, percent)
			u.AmountSats -= c
			total += c
		}
	}
	if n.JailedAt == nil {
		t := now.UTC()
		n.JailedAt = &t
	}
	m.slashes[key] = &SlashEvent{NodeID: nodeID, Epoch: epoch, SlashedSats: total, Evidence: evidence, At: now.UTC()}
	return total, nil
}

func (m *MemStore) ListSlashes(_ context.Context, nodeID string) ([]SlashEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SlashEvent, 0)
	for _, s := range m.slashes {
		if s.NodeID == nodeID {
			out = append(out, *s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Epoch < out[j].Epoch })
	return out, nil
}

// SeedDemo inserts a couple of nodes so a fresh in-memory instance isn't empty.
// They carry no stake: stake only ever comes from paid bonds.
func (m *MemStore) SeedDemo() {
	_ = m.CreateNode(context.Background(), &Node{
		Name: "tokyo-01", Address: "203.0.113.10:443", Status: "online", DelayMeanMs: 50,
	})
	_ = m.CreateNode(context.Background(), &Node{
		Name: "frankfurt-01", Address: "198.51.100.20:443", Status: "online", DelayMeanMs: 50,
	})
}
