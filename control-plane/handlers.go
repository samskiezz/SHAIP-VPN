package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Server bundles the dependencies the HTTP handlers need.
type Server struct {
	store  Store
	tokens *TokenSigner
	// crlKey signs the CRL distributed to tunnel servers (§7).
	crlPub  ed25519.PublicKey
	crlPriv ed25519.PrivateKey
	// Untraceable payments (§20): the e-cash mint and the payment rail.
	mint      *Mint
	rail      PaymentRail
	devSettle bool // enable the dev settle endpoint (never in production)
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

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		IdentityID string `json:"identity_id"`
		MlDsaPub   string `json:"ml_dsa_pub"`
		EdPub      string `json:"ed_pub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.Email == "" || len(body.Password) < 8 {
		errJSON(w, http.StatusBadRequest, "email required, password >= 8 chars")
		return
	}
	hash, err := hashPassword(body.Password)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "hash error")
		return
	}
	mlDsa, _ := hex.DecodeString(body.MlDsaPub)
	edPub, _ := hex.DecodeString(body.EdPub)
	identityID := body.IdentityID
	if identityID == "" && len(mlDsa) > 0 && len(edPub) > 0 {
		identityID = deriveIdentityID(mlDsa, edPub)
	}
	u := &User{
		Email:        body.Email,
		PasswordHash: hash,
		IdentityID:   identityID,
		MlDsaPub:     mlDsa,
		EdPub:        edPub,
	}
	if err := s.store.CreateUser(r.Context(), u); err != nil {
		errJSON(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"status":      "registered",
		"identity_id": identityID,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := s.store.GetUserByEmail(r.Context(), body.Email)
	if err != nil {
		// Do the work anyway to blunt user-enumeration timing.
		_, _ = verifyPassword(body.Password, dummyHash)
		errJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	ok, err := verifyPassword(body.Password, u.PasswordHash)
	if err != nil || !ok {
		errJSON(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	tok, err := s.tokens.Issue(u.ID, u.Email)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "token error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": tok})
}

// dummyHash is a valid Argon2id hash of a random value, used to equalize login
// timing for unknown users.
var dummyHash, _ = hashPassword("pqanon-timing-equalizer")

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			errJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		tok := strings.TrimPrefix(auth, "Bearer ")
		if tok == "" {
			errJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		claims, err := s.tokens.Verify(tok)
		if err != nil {
			errJSON(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := context.WithValue(r.Context(), ctxUserKey{}, claims.Subject)
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

func (s *Server) handleCreateNode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Address     string `json:"address"`
		PublicKey   string `json:"public_key"`
		StakeSats   int64  `json:"stake_sats"`
		DelayMeanMs int    `json:"delay_mean_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.Name == "" || body.Address == "" {
		errJSON(w, http.StatusBadRequest, "name and address required")
		return
	}
	pub, err := hex.DecodeString(body.PublicKey)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "public_key must be hex")
		return
	}
	n := &Node{
		Name: body.Name, Address: body.Address, PublicKey: pub,
		PublicKeyHex: body.PublicKey, StakeSats: body.StakeSats,
		DelayMeanMs: body.DelayMeanMs,
	}
	if err := s.store.CreateNode(r.Context(), n); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "id": n.ID})
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			errJSON(w, http.StatusNotFound, "not found")
			return
		}
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- connections ---

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	conns, err := s.store.ListActiveConnections(r.Context())
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, conns)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.EndConnection(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			errJSON(w, http.StatusNotFound, "not found")
			return
		}
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
}

// --- dashboard / mixnet / settings ---

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	conns, err := s.store.ListActiveConnections(ctx)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	var totalBytes int64
	for _, c := range conns {
		totalBytes += c.BytesIn + c.BytesOut
	}
	online, meanDelay := s.mixnetHealth(ctx)
	status := "degraded"
	if online > 0 {
		status = "ok"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active_connections": len(conns),
		"bandwidth_mb":       float64(totalBytes) / 1e6,
		"latency_ms":         meanDelay,
		"mixnet_status":      status,
		"nodes_online":       online,
	})
}

func (s *Server) handleMixnetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	active, _ := s.store.CountActiveConnections(ctx)
	online, meanDelay := s.mixnetHealth(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"active_paths":    active,
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

// defaultSettings is returned until a user saves their own.
func defaultSettings() map[string]any {
	return map[string]any{
		"default_route":   "fast",
		"kill_switch":     true,
		"auto_connect":    false,
		"mix_hops":        5,
		"cover_rate_idle": 2.0,
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	raw, err := s.store.GetSettings(r.Context(), userID(r))
	if errors.Is(err, ErrNotFound) {
		writeJSON(w, http.StatusOK, defaultSettings())
		return
	}
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if dr, ok := body["default_route"].(string); ok && dr != "fast" && dr != "anon" {
		errJSON(w, http.StatusBadRequest, "default_route must be 'fast' or 'anon'")
		return
	}
	raw, err := json.Marshal(body)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if err := s.store.SetSettings(r.Context(), userID(r), raw); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "saved"})
}

// --- CRL (§7) ---

// handleCRL serves the signed certificate revocation list. The payload is the
// JSON list of revoked identity_ids; the signature is Ed25519 over that payload.
// (A production CRL also carries an ML-DSA-65 signature; the signing key wiring
// for the PQ half is the same pattern.)
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
	payload, _ := json.Marshal(map[string]any{
		"issued_at": time.Now().UTC().Format(time.RFC3339),
		"revoked":   ids,
	})
	sig := ed25519.Sign(s.crlPriv, payload)
	writeJSON(w, http.StatusOK, map[string]any{
		"crl":           json.RawMessage(payload),
		"ed25519_sig":   hex.EncodeToString(sig),
		"ed25519_pub":   hex.EncodeToString(s.crlPub),
		"signature_alg": "Ed25519 (ML-DSA-65 co-signature: see §7)",
	})
}

func deriveIdentityID(mlDsaPub, edPub []byte) string {
	h := sha256.New()
	h.Write(mlDsaPub)
	h.Write(edPub)
	return hex.EncodeToString(h.Sum(nil)[:16])
}
