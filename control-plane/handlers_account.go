package main

import (
	"net/http"
)

// userID pulls the authenticated subject the auth middleware stored on the
// request context. It is always present inside the authed route group.
func userID(r *http.Request) string {
	if v, ok := r.Context().Value(ctxUserKey{}).(string); ok {
		return v
	}
	return ""
}

// --- current user (§14) ---

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := s.store.GetUserByID(r.Context(), userID(r))
	if err != nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":             u.ID,
		"account_number": formatAccountNumber(u.AccountNumber),
		"role":           u.Role,
		"created_at":     u.CreatedAt,
	})
}

// --- network stats (§16) ---

// handleStats returns network-wide counts any authenticated user can read:
// totals only, nothing per account.
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
	users, _ := s.store.CountUsers(ctx)
	writeJSON(w, http.StatusOK, map[string]any{
		"users":        users,
		"nodes_total":  len(nodes),
		"nodes_online": online,
	})
}
