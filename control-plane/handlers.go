package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"shaip/control-plane/keystore"
)

// Server bundles the dependencies the HTTP handlers need.
type Server struct {
	store  Store
	tokens *TokenSigner
	// crlSigner signs the CRL distributed to tunnel servers (§7). Tunnel servers
	// pin crlPub, so it must be stable: resolve it from a key file or HSM.
	crlPub    ed25519.PublicKey
	crlSigner crypto.Signer
	// One-click enrollment: tokens are signed by the enrollment authority and
	// device certificates by the device CA. Clients pin enrollPub; tunnel
	// servers pin deviceCAPub.
	enrollSigner   crypto.Signer
	enrollPub      ed25519.PublicKey
	deviceCASigner crypto.Signer
	deviceCAPub    ed25519.PublicKey
	// Staking rules, and this control plane as a directory authority.
	stake     StakeParams
	directory *DirectoryAuthority
	// Untraceable payments (§20): the e-cash mint and the payment rails.
	mint        *Mint
	rails       map[string]PaymentRail // by name: "monero", "btcpay", "dev"
	defaultRail string
	devSettle   bool // enable the dev settle endpoint (never in production)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- auth ---

// Accounts are anonymous (docs/privacy-policy.md). Registering takes only a
// password; the server answers with a random account number, which is the
// login. Nothing about the person is asked for or stored, and a request that
// sends more (an "email" field, say) has it ignored: the decoders below have
// nowhere to put it.
const (
	accountDigits  = 16
	minPasswordLen = 8
	maxPasswordLen = 1024 // bounds the Argon2id input
	maxAuthBody    = 4 << 10
)

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAuthBody)).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if len(body.Password) < minPasswordLen || len(body.Password) > maxPasswordLen {
		errJSON(w, http.StatusBadRequest, "password must be 8 to 1024 characters")
		return
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "hash error")
		return
	}
	// A clash is a 1-in-10^16 event per existing account; retry a few times.
	for attempt := 0; attempt < 5; attempt++ {
		number, err := newAccountNumber()
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "rng failure")
			return
		}
		err = s.store.CreateUser(r.Context(), &User{AccountNumber: number, PasswordHash: hash})
		if errors.Is(err, ErrAccountNumberTaken) {
			continue
		}
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "could not create the account")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{
			"status":         "registered",
			"account_number": formatAccountNumber(number),
			"note":           "This number is your login. Write it down: it is shown once and cannot be recovered.",
		})
		return
	}
	errJSON(w, http.StatusServiceUnavailable, "could not allocate an account number; try again")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccountNumber string `json:"account_number"`
		Password      string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAuthBody)).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	var u *User
	number, ok := normalizeAccountNumber(body.AccountNumber)
	if ok && len(body.Password) <= maxPasswordLen {
		u, _ = s.store.GetUserByAccount(r.Context(), number)
	}
	if u == nil {
		// Do the work anyway, so timing doesn't reveal whether an account exists.
		_, _ = verifyPassword(body.Password, dummyHash)
		errJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if ok, err := verifyPassword(body.Password, u.PasswordHash); err != nil || !ok {
		errJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok, err := s.tokens.Issue(u.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "token error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// newAccountNumber draws 16 uniformly random decimal digits (about 53 bits).
func newAccountNumber() (string, error) {
	limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(accountDigits), nil)
	n, err := crand.Int(crand.Reader, limit)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", accountDigits, n.Uint64()), nil
}

// normalizeAccountNumber accepts the number with or without the spaces or
// dashes it is displayed with, and reports whether it is 16 digits.
func normalizeAccountNumber(in string) (string, bool) {
	var b strings.Builder
	for _, c := range in {
		switch {
		case c >= '0' && c <= '9':
			if b.Len() == accountDigits {
				return "", false
			}
			b.WriteRune(c)
		case c == ' ' || c == '-':
		default:
			return "", false
		}
	}
	return b.String(), b.Len() == accountDigits
}

// formatAccountNumber groups the digits in fours, as the UI shows them.
func formatAccountNumber(n string) string {
	var b strings.Builder
	for i, c := range n {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// dummyHash is a valid Argon2id hash of a random value, used to equalize login
// timing for unknown users.
var dummyHash, _ = hashPassword("shaip-timing-equalizer")

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	fail := func(w http.ResponseWriter) {
		mAuthFailures.Inc()
		errJSON(w, http.StatusUnauthorized, "unauthorized")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			fail(w)
			return
		}
		tok := strings.TrimPrefix(auth, "Bearer ")
		if tok == "" {
			fail(w)
			return
		}
		var subject string
		if strings.HasPrefix(tok, apiKeyPrefix) {
			// A personal API key: looked up by the SHA-256 of the whole
			// secret, so only a holder of the full key matches.
			sum := sha256.Sum256([]byte(tok))
			k, err := s.store.GetAPIKeyByHash(r.Context(), hex.EncodeToString(sum[:]))
			if err != nil {
				fail(w)
				return
			}
			subject = k.UserID
		} else {
			claims, err := s.tokens.Verify(tok)
			if err != nil {
				fail(w)
				return
			}
			subject = claims.Subject
		}
		ctx := context.WithValue(r.Context(), ctxUserKey{}, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type ctxUserKey struct{}

// --- nodes ---

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, nodes)
}

// validNodeRoles are the roles a directory lists.
var validNodeRoles = map[string]bool{"mix": true, "entry": true, "exit": true, "gateway": true}

// handleCreateNode registers a node under the caller as its operator. Stake is
// never self-declared: it accrues only from paid bonds (POST /api/stake/{id}/bond).
func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string `json:"name"`
		Address      string `json:"address"`
		PublicKey    string `json:"public_key"`
		EdPub        string `json:"ed_pub"`  // the node's Ed25519 key (signs its descriptors)
		MixPub       string `json:"mix_pub"` // X25519 onion key, for the mix role
		Role         string `json:"role"`
		CapacityMbps int    `json:"capacity_mbps"`
		Region       string `json:"region"`
		StakeSats    int64  `json:"stake_sats"`
		DelayMeanMs  int    `json:"delay_mean_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.Name == "" || body.Address == "" {
		errJSON(w, http.StatusBadRequest, "name and address required")
		return
	}
	// The directory's canonical form is whitespace-delimited.
	if strings.ContainsAny(body.Name+body.Address, " \t\r\n") {
		errJSON(w, http.StatusBadRequest, "name and address may not contain whitespace")
		return
	}
	if body.StakeSats != 0 {
		errJSON(w, http.StatusBadRequest, "stake_sats cannot be set directly; bond stake via POST /api/stake/{id}/bond")
		return
	}
	pub, err := hex.DecodeString(body.PublicKey)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "public_key must be hex")
		return
	}
	edPub, err := hex.DecodeString(body.EdPub)
	if err != nil || (len(edPub) != 0 && len(edPub) != ed25519.PublicKeySize) {
		errJSON(w, http.StatusBadRequest, "ed_pub must be a hex Ed25519 public key")
		return
	}
	mixPub, err := hex.DecodeString(body.MixPub)
	if err != nil || (len(mixPub) != 0 && len(mixPub) != 32) {
		errJSON(w, http.StatusBadRequest, "mix_pub must be a hex X25519 public key")
		return
	}
	role := body.Role
	if role == "" {
		role = "mix"
	}
	if !validNodeRoles[role] {
		errJSON(w, http.StatusBadRequest, "role must be mix, entry, exit, or gateway")
		return
	}
	region := strings.ToUpper(strings.TrimSpace(body.Region))
	if region != "" && (len(region) != 2 || strings.Trim(region, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") != "") {
		errJSON(w, http.StatusBadRequest, "region must be an ISO 3166 alpha-2 code")
		return
	}
	if body.CapacityMbps < 0 {
		errJSON(w, http.StatusBadRequest, "capacity_mbps must be positive")
		return
	}
	n := &Node{
		Name: body.Name, Address: body.Address, PublicKey: pub,
		PublicKeyHex: body.PublicKey, EdPub: edPub, MixPub: mixPub, Role: role,
		CapacityMbps: body.CapacityMbps, Region: region, OwnerID: userID(r),
		DelayMeanMs: body.DelayMeanMs,
	}
	if err := s.store.CreateNode(r.Context(), n); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "id": n.ID})
}

// handleDeleteNode removes a node; only its operator (or an admin) may. A node
// still holding stake can't go: its bonded and unbonding stake must stay
// slashable until released, and deleting the node would erase that stake,
// its unbondings and its slash record with it. Nor can one with a bond still
// awaiting payment, which would then have nowhere to be credited.
func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	n, ok := s.operatorNode(w, r)
	if !ok {
		return
	}
	ctx, now := r.Context(), time.Now()
	if n.StakeSats > 0 {
		errJSON(w, http.StatusConflict, "this node has bonded stake: unbond it and wait for the unbonding period first")
		return
	}
	unbondings, err := s.store.ListUnbondings(ctx, n.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, u := range unbondings {
		if u.AmountSats > 0 && u.ReleaseAt.After(now) {
			errJSON(w, http.StatusConflict, "this node's stake is still unbonding (and slashable) until "+u.ReleaseAt.UTC().Format(time.RFC3339))
			return
		}
	}
	bonds, err := s.store.ListBonds(ctx, n.ID)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, b := range bonds {
		if b.Status == "awaiting_payment" && b.CreatedAt.After(now.Add(-BondWatchWindow)) {
			errJSON(w, http.StatusConflict, "a bond for this node is still awaiting payment")
			return
		}
	}
	if err := s.store.DeleteNode(ctx, n.ID); err != nil {
		if errors.Is(err, ErrNotFound) {
			errJSON(w, http.StatusNotFound, "not found")
			return
		}
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- dashboard / mixnet ---

// handleDashboard reports the network, never a customer: nothing here is
// counted per account or per connection.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	online, meanDelay := s.mixnetHealth(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"nodes_online": online,
		"nodes_total":  len(nodes),
		"latency_ms":   meanDelay,
	})
}

func (s *Server) handleMixnetStatus(w http.ResponseWriter, r *http.Request) {
	online, meanDelay := s.mixnetHealth(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"online_nodes":    online,
		"cover_rate_pps":  1.0, // configured target cover rate (§10.4)
		"mean_latency_ms": meanDelay,
	})
}

// mixnetHealth returns the number of online nodes and a representative anon-path
// latency (mean per-hop delay across a 5-hop path), computed from real node
// data. Returns (0, 0) when no nodes are online.
func (s *Server) mixnetHealth(ctx context.Context) (online int, meanLatencyMs int) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return 0, 0
	}
	delaySum := 0
	for _, n := range nodes {
		if n.Status == "online" {
			online++
			delaySum += n.DelayMeanMs
		}
	}
	if online == 0 {
		return 0, 0
	}
	return online, (delaySum / online) * 5 // 5-hop anon path
}

// --- CRL (§7) ---

// handleCRL serves the signed certificate revocation list: revoked identity_ids
// and revoked enrolled devices. The signature is Ed25519 over the payload bytes,
// which are also served verbatim as `crl_b64` so a verifier in any language
// checks exactly the signed bytes instead of re-serializing JSON. (A production
// CRL also carries an ML-DSA-65 signature; the signing key wiring for the PQ
// half is the same pattern.)
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	revoked, err := s.store.ListRevoked(r.Context())
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	ids := make([]map[string]any, 0, len(revoked))
	for _, rv := range revoked {
		ids = append(ids, map[string]any{
			"identity_id": rv.IdentityID,
			"reason":      rv.Reason,
			"revoked_at":  rv.RevokedAt.UTC().Format(time.RFC3339),
		})
	}
	devs, err := s.store.ListRevokedDevices(r.Context())
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	revokedDevices := make([]map[string]any, 0, len(devs))
	for _, d := range devs {
		revokedDevices = append(revokedDevices, map[string]any{
			"device_id":  d.ID,
			"revoked_at": d.RevokedAt.UTC().Format(time.RFC3339),
		})
	}
	payload, _ := json.Marshal(map[string]any{
		"issued_at":       time.Now().UTC().Format(time.RFC3339),
		"revoked":         ids,
		"revoked_devices": revokedDevices,
	})
	sig, err := keystore.Sign(s.crlSigner, payload)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "crl signing failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"crl":           json.RawMessage(payload),
		"crl_b64":       base64.StdEncoding.EncodeToString(payload),
		"ed25519_sig":   hex.EncodeToString(sig),
		"ed25519_pub":   hex.EncodeToString(s.crlPub),
		"signature_alg": "Ed25519 (ML-DSA-65 co-signature: see §7)",
	})
}
