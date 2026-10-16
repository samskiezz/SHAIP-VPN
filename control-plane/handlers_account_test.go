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
	enrollPub, enrollPriv, _ := ed25519.GenerateKey(rand.Reader)
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	dirPub, dirPriv, _ := ed25519.GenerateKey(rand.Reader)
	srv := &Server{
		store: store, tokens: tokens, crlPub: pub, crlSigner: priv,
		enrollSigner: enrollPriv, enrollPub: enrollPub, deviceCASigner: caPriv, deviceCAPub: caPub,
		stake:     defaultStakeParams(),
		directory: &DirectoryAuthority{Name: "cp-test", Signer: dirPriv, Pub: dirPub},
		rails:     map[string]PaymentRail{"dev": NewDevRail()}, defaultRail: "dev", devSettle: true,
	}
	return srv, routes(srv, "memory"), store
}

// newUser stores an account with a fresh random account number.
func newUser(t *testing.T, store Store, role string) *User {
	t.Helper()
	number, err := newAccountNumber()
	if err != nil {
		t.Fatal(err)
	}
	u := &User{AccountNumber: number, PasswordHash: "x", Role: role}
	if err := store.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// authedUser creates a user in the store and returns its id plus a bearer token.
func authedUser(t *testing.T, srv *Server, store *MemStore) (string, string) {
	t.Helper()
	u := newUser(t, store, "")
	tok, err := srv.tokens.Issue(u.ID)
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

func TestMeAndStats(t *testing.T) {
	srv, h, store := newTestServer(t)
	uid, tok := authedUser(t, srv, store)

	rec := do(t, h, "GET", "/api/me", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("me: %d (%s)", rec.Code, rec.Body.String())
	}
	var me map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	u, _ := store.GetUserByID(context.Background(), uid)
	if me["id"] != uid || me["account_number"] != formatAccountNumber(u.AccountNumber) {
		t.Fatalf("me = %v", me)
	}
	for _, k := range []string{"email", "identity_id", "ml_dsa_pub", "ed_pub"} {
		if _, ok := me[k]; ok {
			t.Fatalf("/api/me carries %q: %v", k, me)
		}
	}

	// SeedDemo-style nodes aren't present here, but stats must still return.
	rec = do(t, h, "GET", "/api/stats", tok, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("stats: %d", rec.Code)
	}
	var stats map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &stats)
	for _, k := range []string{"users", "nodes_total", "nodes_online"} {
		if _, ok := stats[k]; !ok {
			t.Fatalf("stats missing %q: %v", k, stats)
		}
	}
	if stats["users"].(float64) != 1 {
		t.Fatalf("expected 1 user, got %v", stats["users"])
	}
}
