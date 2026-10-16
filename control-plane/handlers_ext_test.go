package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// adminUser creates an admin account and returns its id + token.
func adminUser(t *testing.T, srv *Server, store *MemStore) (string, string) {
	t.Helper()
	u := newUser(t, store, "admin")
	tok, _ := srv.tokens.Issue(u.ID)
	return u.ID, tok
}

func TestAPIKeyLifecycle(t *testing.T) {
	srv, h, store := newTestServer(t)
	uid, tok := authedUser(t, srv, store)

	// Create: the full secret is returned exactly once.
	rec := do(t, h, "POST", "/api/apikeys", tok, map[string]any{"name": "ci"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create key: %d (%s)", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	secret, _ := created["key"].(string)
	id, _ := created["id"].(string)
	if !strings.HasPrefix(secret, "pqa_") || len(secret) < 20 {
		t.Fatalf("expected a pqa_ token, got %q", secret)
	}
	if id == "" {
		t.Fatalf("missing key id")
	}

	// List: the secret is NOT returned, only the prefix.
	rec = do(t, h, "GET", "/api/apikeys", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list keys: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("list must not leak the full key")
	}
	var keys []APIKey
	_ = json.Unmarshal(rec.Body.Bytes(), &keys)
	if len(keys) != 1 || keys[0].Name != "ci" {
		t.Fatalf("expected 1 key named ci, got %+v", keys)
	}

	// The stored hash must not be the plaintext key (query by the real uid;
	// UserID is json:"-" so it is not present in the API response).
	ctx := context.Background()
	stored, _ := store.ListAPIKeys(ctx, uid)
	if len(stored) != 1 || stored[0].KeyHash == secret || len(stored[0].KeyHash) != 64 {
		t.Fatalf("key must be stored as a SHA-256 hash, not plaintext")
	}

	// Delete, then 404 on re-delete.
	if rec := do(t, h, "DELETE", "/api/apikeys/"+id, tok, nil); rec.Code != http.StatusOK {
		t.Fatalf("delete key: %d", rec.Code)
	}
	if rec := do(t, h, "DELETE", "/api/apikeys/"+id, tok, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on re-delete, got %d", rec.Code)
	}
}

func TestAPIKeyUserIsolation(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tokA := authedUser(t, srv, store)
	ub := newUser(t, store, "")
	tokB, _ := srv.tokens.Issue(ub.ID)

	rec := do(t, h, "POST", "/api/apikeys", tokA, map[string]any{"name": "a-key"})
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	id := created["id"].(string)

	// B cannot see or delete A's key.
	rec = do(t, h, "GET", "/api/apikeys", tokB, nil)
	var keysB []APIKey
	_ = json.Unmarshal(rec.Body.Bytes(), &keysB)
	if len(keysB) != 0 {
		t.Fatalf("user B should see 0 keys, got %d", len(keysB))
	}
	if rec := do(t, h, "DELETE", "/api/apikeys/"+id, tokB, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 deleting another user's key, got %d", rec.Code)
	}
}

func TestAdminStatsRoleGate(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, userTok := authedUser(t, srv, store)
	_, adminTok := adminUser(t, srv, store)

	// A normal user is forbidden.
	if rec := do(t, h, "GET", "/api/admin/stats", userTok, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", rec.Code)
	}
	// An admin gets the stats.
	rec := do(t, h, "GET", "/api/admin/stats", adminTok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin stats: %d (%s)", rec.Code, rec.Body.String())
	}
	var s map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	for _, k := range []string{"users", "nodes_online", "nodes_total"} {
		if _, ok := s[k]; !ok {
			t.Fatalf("admin stats missing %q: %v", k, s)
		}
	}
}

func TestAuditLogRecordsActions(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)

	// Creating a key writes an audit entry.
	do(t, h, "POST", "/api/apikeys", tok, map[string]any{"name": "audited"})

	rec := do(t, h, "GET", "/api/audit", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit: %d", rec.Code)
	}
	var entries []AuditEntry
	_ = json.Unmarshal(rec.Body.Bytes(), &entries)
	if len(entries) == 0 || entries[0].Action != "api_key.create" {
		t.Fatalf("expected an api_key.create audit entry, got %+v", entries)
	}
}

func TestPublicStatusNoAuth(t *testing.T) {
	srv, h, store := newTestServer(t)
	store.SeedDemo()
	_ = srv

	// No token required.
	rec := do(t, h, "GET", "/api/public/status", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("public status: %d", rec.Code)
	}
	var s map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	if s["status"] != "operational" {
		t.Fatalf("expected operational with seeded nodes, got %v", s["status"])
	}
	if s["protocol"] != "PQANON/1" {
		t.Fatalf("missing protocol tag: %v", s)
	}
}

func TestNodeDetail(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)

	// Create a node, then read it back by id.
	n := &Node{Name: "syd-01", Address: "203.0.113.5:443", Status: "online", DelayMeanMs: 14}
	_ = store.CreateNode(context.Background(), n)
	rec := do(t, h, "GET", "/api/nodes/"+n.ID, tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("node detail: %d (%s)", rec.Code, rec.Body.String())
	}
	var got Node
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.Name != "syd-01" {
		t.Fatalf("node detail name = %q", got.Name)
	}
	// Missing node → 404.
	if rec := do(t, h, "GET", "/api/nodes/does-not-exist", tok, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing node, got %d", rec.Code)
	}
}
