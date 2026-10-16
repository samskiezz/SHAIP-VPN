package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
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

// handleDeleteAccount erases the caller's account and everything stored about
// it (Store.DeleteAccount). The password is asked again, so a stolen session
// token alone can't do it.
func (s *Server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAuthBody)).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	u, err := s.store.GetUserByID(r.Context(), userID(r))
	if err != nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	if ok, err := verifyPassword(body.Password, u.PasswordHash); err != nil || !ok {
		errJSON(w, http.StatusUnauthorized, "wrong password")
		return
	}
	switch err := s.store.DeleteAccount(r.Context(), u.ID, time.Now()); {
	case errors.Is(err, ErrOwnsNodes):
		errJSON(w, http.StatusConflict, "this account still owns nodes: unbond and delete them first")
		return
	case errors.Is(err, ErrNotFound):
		errJSON(w, http.StatusNotFound, "not found")
		return
	case err != nil:
		errJSON(w, http.StatusInternalServerError, "could not delete the account")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
