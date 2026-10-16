package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// This file completes the REST surface the audit flagged as missing: admin
// stats, personal API keys, the audit log, a public status probe, and the
// single-node read. Every handler is backed by a real Store method (in-memory
// and Postgres) — none return canned data.

// --- admin ---

// requireRole resolves the caller's role and returns true iff it matches.
func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, role string) bool {
	u, err := s.store.GetUserByID(r.Context(), userID(r))
	if err != nil {
		errJSON(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	if u.Role != role {
		errJSON(w, http.StatusForbidden, role+" only")
		return false
	}
	return true
}

// handleAdminStats returns network-wide totals; admin role required. Even an
// admin sees no per-customer data: the control plane holds none to show.
func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "admin") {
		return
	}
	ctx := r.Context()
	nodes, _ := s.store.ListNodes(ctx)
	online := 0
	for _, n := range nodes {
		if n.Status == "online" {
			online++
		}
	}
	users, _ := s.store.CountUsers(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"users":        users,
		"nodes_online": online,
		"nodes_total":  len(nodes),
	})
}

// --- API keys ---

// handleCreateAPIKey mints a token, stores only its SHA-256 hash, and returns
// the secret exactly once.
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Name == "" {
		body.Name = "api key"
	}
	secret, err := newAPIKeySecret()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "key generation failed")
		return
	}
	sum := sha256.Sum256([]byte(secret))
	k := &APIKey{
		UserID:  userID(r),
		Name:    body.Name,
		Prefix:  secret[:12], // "pqa_" + 8 chars, safe to display
		KeyHash: hex.EncodeToString(sum[:]),
	}
	if err := s.store.CreateAPIKey(r.Context(), k); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "api_key.create", k.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         k.ID,
		"name":       k.Name,
		"prefix":     k.Prefix,
		"key":        secret, // shown once
		"created_at": k.CreatedAt,
	})
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAPIKeys(r.Context(), userID(r))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteAPIKey(r.Context(), id, userID(r)); err != nil {
		if errors.Is(err, ErrNotFound) {
			errJSON(w, http.StatusNotFound, "not found")
			return
		}
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(r, "api_key.delete", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// apiKeyPrefix marks an API key in an Authorization header (session tokens
// are base64url claims, which never start with it).
const apiKeyPrefix = "pqa_"

// newAPIKeySecret returns a URL-safe token "pqa_<43 base64url chars>" from 32
// bytes of CSPRNG output.
func newAPIKeySecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// --- audit log ---

// audit records a security-relevant action for the authenticated caller: the
// action and the day, never where the request came from. A failure to
// persist the entry is not surfaced, so auditing cannot break a user action.
func (s *Server) audit(r *http.Request, action, detail string) {
	_ = s.store.AppendAudit(r.Context(), &AuditEntry{
		UserID: userID(r),
		Action: action,
		Detail: detail,
	})
}

// handleListAudit returns the caller's own audit entries. Nobody, admins
// included, can list another account's.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	entries, err := s.store.ListAudit(r.Context(), userID(r), limit)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// --- public status (unauthenticated) ---

// handlePublicStatus is a cache-friendly health/status probe for status pages
// and uptime monitors: node availability only, no per-user data.
func (s *Server) handlePublicStatus(w http.ResponseWriter, r *http.Request) {
	online, meanDelay := s.mixnetHealth(r.Context())
	status := "operational"
	if online == 0 {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          status,
		"nodes_online":    online,
		"mean_latency_ms": meanDelay,
		"protocol":        "PQANON/1",
	})
}

// --- single-resource reads ---

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	n, err := s.store.GetNode(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, n)
}
