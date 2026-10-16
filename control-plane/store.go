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

// User is an account. It holds nothing about the person behind it: the login is
// a random account number the server generates, and the password is kept only
// as an Argon2id hash. There is no email, name or phone number to collect.
type User struct {
	ID            string    `json:"id"`
	AccountNumber string    `json:"-"` // 16 digits; the login, shown to its owner only
	PasswordHash  string    `json:"-"`
	Role          string    `json:"role"`
	CreatedAt     time.Time `json:"created_at"` // the UTC day, see day()
}

// ErrAccountNumberTaken is returned by CreateUser when the account number is
// already in use (a 1-in-10^16 coincidence; the caller draws a new number).
var ErrAccountNumberTaken = errors.New("account number already in use")

// ErrOwnsNodes is returned by DeleteAccount for an account that still runs
// nodes: their bonded stake needs an owner, so the nodes go first.
var ErrOwnsNodes = errors.New("account still owns nodes")

// day is t's UTC calendar day. Every record about an account (when it was made,
// when a device was enrolled or revoked, an audit entry, a key) stores the day,
// never the moment: a moment could be lined up against network records kept
// elsewhere, such as a hosting provider's flow logs, to tie an account to the
// address it was used from. A day can't.
func day(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }

// dayCeil rounds t up to a UTC day boundary: a coarse expiry that never falls
// before t. It is idempotent, so re-storing a coarse value doesn't move it.
func dayCeil(t time.Time) time.Time {
	d := day(t)
	if d.Equal(t) {
		return d
	}
	return d.Add(24 * time.Hour)
}

// coarsenOrder reduces an order's times to days. An order names nobody, but the
// moment one was opened or paid could still be matched against network records
// to find who opened it; the day can't.
func coarsenOrder(o *PayOrder, created time.Time) {
	o.CreatedAt = day(created)
	o.ExpiresAt = dayCeil(o.ExpiresAt)
	if o.PaidAt != nil {
		paid := day(*o.PaidAt)
		o.PaidAt = &paid
	}
}

// APIKey is a personal access token for the REST API, sent as
// "Authorization: Bearer pqa_…". Only its SHA-256 is stored; the secret is
// shown once at creation. When a key is used is not recorded.
type APIKey struct {
	ID        string    `json:"id"`
	UserID    string    `json:"-"`
	Name      string    `json:"name"`
	Prefix    string    `json:"prefix"`
	KeyHash   string    `json:"-"`
	CreatedAt time.Time `json:"created_at"` // the UTC day
}

// AuditEntry is one row of an account's security log: what was done, never
// from where. There is no address field to fill. At is the UTC day; ID orders
// the entries within a day.
type AuditEntry struct {
	ID     int64     `json:"id"`
	UserID string    `json:"-"`
	Action string    `json:"action"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// ErrSpent is returned when a token nonce has already been redeemed.
var ErrSpent = errors.New("token already spent")

// ErrCompExhausted is returned when a comp (discount) code has no uses left.
var ErrCompExhausted = errors.New("code has no uses left")

// CompCode is an operator-issued discount/comp code that grants plan access
// without a crypto payment (a free trial, a promo, or a test pass). Only a
// hash of the code is stored, never the code itself, and a claim is
// identity-free like a token redemption: the only state is the use counter, so
// a code reveals nothing about who claimed it.
type CompCode struct {
	CodeHash     string    `json:"-"`
	Plan         string    `json:"plan"`
	DurationDays int       `json:"duration_days"`
	MaxUses      int       `json:"max_uses"`
	Uses         int       `json:"uses"`
	CreatedAt    time.Time `json:"created_at"`
}

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
// The stores keep only days: IssuedAt and ClaimedAt are the UTC day, ExpiresAt
// the end of the expiry's day. The token's exact expiry is inside the signed
// token itself, which handleEnrollClaim checks before it ever reaches the store.
type EnrollToken struct {
	TokenID   string // hex of the token's 16-byte id
	UserID    string
	IssuedAt  time.Time
	ExpiresAt time.Time
	ClaimedAt *time.Time
}

// Device is an enrolled device: its Ed25519 identity key, bound to an account
// by a device certificate. Name is a platform label from a fixed list (see
// deviceLabel), never free text. CreatedAt and RevokedAt are UTC days.
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

// RevokedIdentity is a CRL entry.
type RevokedIdentity struct {
	IdentityID string    `json:"identity_id"`
	Reason     string    `json:"reason"`
	RevokedAt  time.Time `json:"revoked_at"`
	Signature  []byte    `json:"-"`
}

// Store is the persistence interface. Two implementations exist: an in-memory
// store (default, so the control plane boots with no database) and a Postgres
// store (used when DATABASE_URL is set).
type Store interface {
	// CreateUser stores a new account, or fails with ErrAccountNumberTaken.
	CreateUser(ctx context.Context, u *User) error
	// GetUserByAccount looks an account up by its normalized account number.
	GetUserByAccount(ctx context.Context, number string) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	CountUsers(ctx context.Context) (int, error)
	// DeleteAccount erases an account and everything stored about it: its API
	// keys, enrollment tokens, devices and security log. Its devices stay
	// refused: their ids (and nothing else) move to the CRL until their
	// certificates expire. ErrOwnsNodes if it still owns nodes, ErrNotFound if
	// there is no such account; either way nothing changes.
	DeleteAccount(ctx context.Context, userID string, now time.Time) error

	ListNodes(ctx context.Context) ([]Node, error)
	GetNode(ctx context.Context, id string) (*Node, error)
	CreateNode(ctx context.Context, n *Node) error
	DeleteNode(ctx context.Context, id string) error

	CreateAPIKey(ctx context.Context, k *APIKey) error
	// GetAPIKeyByHash finds the key with this SHA-256 (hex), or ErrNotFound.
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKey, error)
	ListAPIKeys(ctx context.Context, userID string) ([]APIKey, error)
	DeleteAPIKey(ctx context.Context, id, userID string) error

	AppendAudit(ctx context.Context, e *AuditEntry) error
	ListAudit(ctx context.Context, userID string, limit int) ([]AuditEntry, error)

	CreatePayOrder(ctx context.Context, o *PayOrder) error
	GetPayOrder(ctx context.Context, id string) (*PayOrder, error)
	UpdatePayOrder(ctx context.Context, o *PayOrder) error
	// SpendToken records a redeemed nonce, returning ErrSpent if already spent.
	SpendToken(ctx context.Context, denom, nonceHash string) error

	// CreateCompCode stores an operator-issued discount/comp code (hashed).
	CreateCompCode(ctx context.Context, c *CompCode) error
	// ClaimCompCode atomically consumes one use of a code, returning it, or
	// ErrNotFound (unknown) / ErrCompExhausted (no uses left).
	ClaimCompCode(ctx context.Context, codeHash string) (*CompCode, error)

	ListRevoked(ctx context.Context) ([]RevokedIdentity, error)

	CreateEnrollToken(ctx context.Context, t *EnrollToken) error
	// ClaimEnrollment atomically consumes the token and records the device. It
	// fails with ErrNotFound (unknown token, or one issued to another account),
	// ErrTokenClaimed, ErrTokenExpired, or ErrDeviceKeyInUse — and then changes
	// nothing, so a failed claim never burns the token.
	ClaimEnrollment(ctx context.Context, tokenID string, now time.Time, d *Device) error
	ListDevices(ctx context.Context, userID string) ([]Device, error)
	// RevokeDevice marks one of the user's devices revoked. Revoking twice keeps
	// the first day. ErrNotFound if the device is not theirs.
	RevokeDevice(ctx context.Context, id, userID string) error
	// ListRevokedDevices returns the ids and revocation days of every refused
	// device: revoked ones, and those of deleted accounts whose certificates
	// have not expired yet. Only ID and RevokedAt are filled in.
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
	users    map[string]*User // keyed by account number
	nodes    map[string]*Node // keyed by id
	revoked  map[string]*RevokedIdentity
	apiKeys  map[string]*APIKey // keyed by key id
	audit    []AuditEntry
	auditSeq int64
	orders   map[string]*PayOrder    // keyed by order id
	spent    map[string]bool         // keyed by denom|nonce_hash
	enroll   map[string]*EnrollToken // keyed by token id
	devices  map[string]*Device      // keyed by device id
	crlOnly  map[string]*Device      // deleted accounts' devices: id, revoked, cert expiry only
	bonds    map[string]*StakeBond   // keyed by bond id
	unbonds  []Unbonding
	unbondSq int64
	slashes  map[string]*SlashEvent // keyed by node id|epoch
	comp     map[string]*CompCode   // keyed by code hash
}

func NewMemStore() *MemStore {
	return &MemStore{
		users:   make(map[string]*User),
		nodes:   make(map[string]*Node),
		revoked: make(map[string]*RevokedIdentity),
		apiKeys: make(map[string]*APIKey),
		orders:  make(map[string]*PayOrder),
		spent:   make(map[string]bool),
		enroll:  make(map[string]*EnrollToken),
		devices: make(map[string]*Device),
		crlOnly: make(map[string]*Device),
		bonds:   make(map[string]*StakeBond),
		slashes: make(map[string]*SlashEvent),
		comp:    make(map[string]*CompCode),
	}
}

func (m *MemStore) Close() {}

func (m *MemStore) CreateUser(_ context.Context, u *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[u.AccountNumber]; ok {
		return ErrAccountNumberTaken
	}
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if u.Role == "" {
		u.Role = "user"
	}
	u.CreatedAt = day(time.Now())
	cp := *u
	m.users[u.AccountNumber] = &cp
	return nil
}

func (m *MemStore) GetUserByAccount(_ context.Context, number string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[number]
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

func (m *MemStore) DeleteAccount(_ context.Context, userID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	number := ""
	for n, u := range m.users {
		if u.ID == userID {
			number = n
		}
	}
	if number == "" {
		return ErrNotFound
	}
	for _, n := range m.nodes {
		if n.OwnerID == userID {
			return ErrOwnsNodes
		}
	}
	for id, d := range m.devices {
		if d.UserID != userID {
			continue
		}
		revoked := day(now)
		if d.RevokedAt != nil {
			revoked = *d.RevokedAt
		}
		if d.CertExpires.After(now) {
			m.crlOnly[id] = &Device{ID: id, RevokedAt: &revoked, CertExpires: d.CertExpires}
		}
		delete(m.devices, id)
	}
	for id, k := range m.apiKeys {
		if k.UserID == userID {
			delete(m.apiKeys, id)
		}
	}
	for id, t := range m.enroll {
		if t.UserID == userID {
			delete(m.enroll, id)
		}
	}
	kept := m.audit[:0]
	for _, e := range m.audit {
		if e.UserID != userID {
			kept = append(kept, e)
		}
	}
	m.audit = kept
	delete(m.users, number)
	return nil
}

func (m *MemStore) CountUsers(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.users), nil
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

func (m *MemStore) CreateAPIKey(_ context.Context, k *APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if k.ID == "" {
		k.ID = uuid.NewString()
	}
	k.CreatedAt = day(time.Now())
	cp := *k
	m.apiKeys[k.ID] = &cp
	return nil
}

func (m *MemStore) GetAPIKeyByHash(_ context.Context, hash string) (*APIKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range m.apiKeys {
		if k.KeyHash == hash {
			cp := *k
			return &cp, nil
		}
	}
	return nil, ErrNotFound
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
	e.At = day(time.Now())
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
	if userID == "" {
		return out, nil
	}
	// Newest first.
	for i := len(m.audit) - 1; i >= 0 && len(out) < limit; i-- {
		if m.audit[i].UserID == userID {
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
	coarsenOrder(o, time.Now())
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
	old, ok := m.orders[o.ID]
	if !ok {
		return ErrNotFound
	}
	o.CreatedAt, o.ExpiresAt = old.CreatedAt, old.ExpiresAt
	coarsenOrder(o, old.CreatedAt)
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

func (m *MemStore) CreateCompCode(_ context.Context, c *CompCode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.comp[c.CodeHash]; ok {
		return errors.New("comp code already exists")
	}
	cp := *c
	cp.CreatedAt = day(time.Now())
	m.comp[c.CodeHash] = &cp
	return nil
}

func (m *MemStore) ClaimCompCode(_ context.Context, codeHash string) (*CompCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.comp[codeHash]
	if !ok {
		return nil, ErrNotFound
	}
	if c.Uses >= c.MaxUses {
		return nil, ErrCompExhausted
	}
	c.Uses++
	out := *c
	return &out, nil
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
	cp.IssuedAt, cp.ExpiresAt, cp.ClaimedAt = day(t.IssuedAt), dayCeil(t.ExpiresAt), nil
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
	claimed := day(now)
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
		today := day(time.Now())
		d.RevokedAt = &today
	}
	return nil
}

func (m *MemStore) ListRevokedDevices(_ context.Context) ([]Device, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Device, 0)
	for _, d := range m.devices {
		if d.RevokedAt != nil {
			out = append(out, Device{ID: d.ID, RevokedAt: d.RevokedAt})
		}
	}
	now := time.Now()
	for _, d := range m.crlOnly {
		if d.CertExpires.After(now) {
			out = append(out, Device{ID: d.ID, RevokedAt: d.RevokedAt})
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
