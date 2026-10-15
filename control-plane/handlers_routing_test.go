package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*Server, http.Handler, *MemStore) {
	t.Helper()
	store := NewMemStore()
	tokens, err := NewTokenSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("crl key: %v", err)
	}
	srv := &Server{store: store, tokens: tokens, crlPub: pub, crlPriv: priv}
	return srv, routes(srv, "memory"), store
}

// authedUser creates a user in the store and returns its id plus a bearer token.
func authedUser(t *testing.T, srv *Server, store *MemStore) (string, string) {
	t.Helper()
	u := &User{Email: "r@t.co", PasswordHash: "x", IdentityID: "id-1"}
	if err := store.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	tok, err := srv.tokens.Issue(u.ID, u.Email)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return u.ID, tok
}

func do(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRoutingRulesCRUD(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)

	// Unauthenticated access is rejected by the auth middleware.
	if rec := do(t, h, "GET", "/api/routing", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	// Empty list initially.
	rec := do(t, h, "GET", "/api/routing", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d (%s)", rec.Code, rec.Body.String())
	}
	var list []RoutingRule
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 0 {
		t.Fatalf("expected 0 rules, got %d", len(list))
	}

	// Create a valid rule.
	rec = do(t, h, "POST", "/api/routing", tok,
		map[string]any{"domain": "example.com", "route": "anon", "priority": 5})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d (%s)", rec.Code, rec.Body.String())
	}
	var created RoutingRule
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID == "" || created.Route != "anon" || created.Domain != "example.com" {
		t.Fatalf("bad created rule: %+v", created)
	}

	// An invalid route is rejected.
	if rec := do(t, h, "POST", "/api/routing", tok,
		map[string]any{"domain": "x.com", "route": "bogus"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad route, got %d", rec.Code)
	}

	// The list now has exactly the one rule.
	rec = do(t, h, "GET", "/api/routing", tok, nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(list))
	}

	// Delete it.
	if rec := do(t, h, "DELETE", "/api/routing/"+created.ID, tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d", rec.Code)
	}

	// Deleting again returns 404.
	if rec := do(t, h, "DELETE", "/api/routing/"+created.ID, tok, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on second delete, got %d", rec.Code)
	}
}

func TestRoutingRuleUserIsolation(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tokA := authedUser(t, srv, store)

	// A second user with their own token.
	ub := &User{Email: "b@t.co", PasswordHash: "x", IdentityID: "id-2"}
	if err := store.CreateUser(context.Background(), ub); err != nil {
		t.Fatalf("create user b: %v", err)
	}
	tokB, _ := srv.tokens.Issue(ub.ID, ub.Email)

	// User A creates a rule.
	rec := do(t, h, "POST", "/api/routing", tokA,
		map[string]any{"domain": "a.example", "route": "fast"})
	var ruleA RoutingRule
	_ = json.Unmarshal(rec.Body.Bytes(), &ruleA)

	// User B does not see it.
	rec = do(t, h, "GET", "/api/routing", tokB, nil)
	var listB []RoutingRule
	_ = json.Unmarshal(rec.Body.Bytes(), &listB)
	if len(listB) != 0 {
		t.Fatalf("user B should see 0 rules, got %d", len(listB))
	}

	// User B cannot delete user A's rule.
	if rec := do(t, h, "DELETE", "/api/routing/"+ruleA.ID, tokB, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 deleting another user's rule, got %d", rec.Code)
	}
}

func TestMeAndStats(t *testing.T) {
	srv, h, store := newTestServer(t)
	uid, tok := authedUser(t, srv, store)

	rec := do(t, h, "GET", "/api/me", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("me: %d (%s)", rec.Code, rec.Body.String())
	}
	var me map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me["id"] != uid {
		t.Fatalf("me.id = %v, want %v", me["id"], uid)
	}
	if me["email"] != "r@t.co" {
		t.Fatalf("me.email = %v", me["email"])
	}

	// SeedDemo-style nodes aren't present here, but stats must still return.
	rec = do(t, h, "GET", "/api/stats", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("stats: %d", rec.Code)
	}
	var stats map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &stats)
	for _, k := range []string{"users", "nodes_total", "nodes_online", "connections_active"} {
		if _, ok := stats[k]; !ok {
			t.Fatalf("stats missing %q: %v", k, stats)
		}
	}
	if stats["users"].(float64) != 1 {
		t.Fatalf("expected 1 user, got %v", stats["users"])
	}
}
