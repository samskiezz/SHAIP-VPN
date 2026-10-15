package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// userID pulls the authenticated subject the auth middleware stored on the
// request context. It is always present inside the authed route group.
func userID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUserKey{}).(string); ok {
		return v
	}
	return ""
}

// --- routing rules (§13) ---

func (s *Server) handleListRouting(w http.ResponseWriter, r *http.Request) {
	rules, err := s.store.ListRoutingRules(r.Context(), userID(r))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleCreateRouting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain   string `json:"domain"`
		Route    string `json:"route"`
		Priority int    `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.Domain == "" {
		errJSON(w, http.StatusBadRequest, "domain required")
		return
	}
	if body.Route != "fast" && body.Route != "anon" {
		errJSON(w, http.StatusBadRequest, "route must be 'fast' or 'anon'")
		return
	}
	rule := &RoutingRule{
		UserID:   userID(r),
		Domain:   body.Domain,
		Route:    body.Route,
		Priority: body.Priority,
	}
	if err := s.store.CreateRoutingRule(r.Context(), rule); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleDeleteRouting(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DeleteRoutingRule(r.Context(), id, userID(r)); err != nil {
		if errors.Is(err, ErrNotFound) {
			errJSON(w, http.StatusNotFound, "not found")
			return
		}
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- current user (§14) ---

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUserByID(r.Context(), userID(r))
	if err != nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	resp := map[string]any{
		"id":          u.ID,
		"email":       u.Email,
		"identity_id": u.IdentityID,
		"created_at":  u.CreatedAt,
	}
	if len(u.MlDsaPub) > 0 {
		resp["ml_dsa_pub"] = hex.EncodeToString(u.MlDsaPub)
	}
	if len(u.EdPub) > 0 {
		resp["ed_pub"] = hex.EncodeToString(u.EdPub)
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- network stats (§16) ---

// handleStats returns network-wide counts any authenticated user can read.
// It aggregates from the existing store methods, so it needs no new tables.
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	online := 0
	for _, n := range nodes {
		if n.Status == "online" {
			online++
		}
	}
	active, _ := s.store.CountActiveConnections(ctx)
	users, _ := s.store.CountUsers(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"users":              users,
		"nodes_total":        len(nodes),
		"nodes_online":       online,
		"connections_active": active,
	})
}
