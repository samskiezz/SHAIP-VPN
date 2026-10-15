package main

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// callNoPanic runs f, converting any panic into a test failure with context.
func callNoPanic(t *testing.T, label string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC in %s: %v", label, r)
		}
	}()
	f()
}

// The token verifier must reject every malformed string without panicking.
func TestTokenVerifyBrute(t *testing.T) {
	signer, err := NewTokenSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	// A real token, plus a large population of hostile/garbage strings.
	good, _ := signer.Issue("u1", "a@b.co")
	seeds := []string{
		"", ".", "..", "a.b", "a.b.c",
		good, good + "x", "x" + good,
		good[:len(good)-1], strings.Repeat("A", 100000),
		"\x00\x00.\x00", "....", "%%%.%%%",
		strings.ReplaceAll(good, ".", ""),
	}
	for _, s := range seeds {
		callNoPanic(t, "Verify(seed)", func() { _, _ = signer.Verify(s) })
	}

	rng := rand.New(rand.NewSource(0xBADC0DE))
	for i := 0; i < 50_000; i++ {
		n := rng.Intn(80)
		b := make([]byte, n)
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		s := string(b)
		callNoPanic(t, "Verify(random)", func() {
			if _, err := signer.Verify(s); err == nil && s != good {
				t.Fatalf("random string verified as a valid token: %q", s)
			}
		})
	}
}

// FuzzTokenVerify also runs its seed corpus under plain `go test`.
func FuzzTokenVerify(f *testing.F) {
	signer, err := NewTokenSigner(time.Hour)
	if err != nil {
		f.Fatalf("signer: %v", err)
	}
	for _, s := range []string{"", ".", "a.b", "a.b.c.d", strings.Repeat("x", 1000)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = signer.Verify(s) // must never panic for any input
	})
}

// The auth endpoints must handle hostile input with a clean 4xx, never a 5xx or
// a panic.
func TestAuthHostileInputs(t *testing.T) {
	_, h, _ := newTestServer(t)

	type reg struct {
		email, password string
	}
	cases := []reg{
		{"", ""},                                 // empty
		{"a@b.co", "short"},                       // password < 8
		{"", "longenoughpassword"},                // empty email
		{"'; DROP TABLE users;--@x.co", "password123"}, // SQL-ish (MemStore: stored, no SQL)
		{"user\x00null@x.co", "password123"},      // NUL byte
		{"😀@unicode.example", "pаsswоrd12"},       // unicode (incl. Cyrillic look-alikes)
		{"a@b.co", strings.Repeat("p", 4096)},     // long (but bounded) password
		{strings.Repeat("e", 4096) + "@b.co", "password123"}, // long email
	}
	for i, c := range cases {
		rec := do(t, h, "POST", "/api/auth/register", "",
			map[string]any{"email": c.email, "password": c.password})
		if rec.Code >= 500 {
			t.Fatalf("case %d (%q): server error %d — hostile input must not 5xx", i, c.email, rec.Code)
		}
		// Login attempts with the same hostile inputs must also never 5xx.
		rec = do(t, h, "POST", "/api/auth/login", "",
			map[string]any{"email": c.email, "password": c.password})
		if rec.Code >= 500 {
			t.Fatalf("case %d login (%q): server error %d", i, c.email, rec.Code)
		}
	}

	// Brute: random registration payloads — status must stay in a sane set.
	// (Argon2id is deliberately expensive, so keep the count modest.)
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 150; i++ {
		email := fmt.Sprintf("u%d-%d@x.co", i, rng.Int())
		pw := strings.Repeat("p", 8+rng.Intn(40))
		rec := do(t, h, "POST", "/api/auth/register", "",
			map[string]any{"email": email, "password": pw})
		if rec.Code != http.StatusCreated && rec.Code != http.StatusConflict &&
			rec.Code != http.StatusBadRequest {
			t.Fatalf("unexpected register status %d for %q", rec.Code, email)
		}
	}
}

// The in-memory store must be safe under concurrent access (run with -race).
func TestStoreConcurrency(t *testing.T) {
	srv, h, store := newTestServer(t)
	_ = store

	const workers = 12
	const perWorker = 6
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				email := fmt.Sprintf("w%d-%d@x.co", w, i)
				rec := do(t, h, "POST", "/api/auth/register", "",
					map[string]any{"email": email, "password": "password123"})
				if rec.Code != http.StatusCreated {
					t.Errorf("concurrent register failed: %d", rec.Code)
					return
				}
				// Each worker also issues a token and writes a routing rule.
				tok, _ := srv.tokens.Issue(fmt.Sprintf("w%d-%d", w, i), email)
				do(t, h, "POST", "/api/routing", tok,
					map[string]any{"domain": fmt.Sprintf("*.w%d-%d.example", w, i), "route": "anon"})
			}
		}(w)
	}
	wg.Wait()

	n, err := store.CountUsers(context.Background())
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != workers*perWorker {
		t.Fatalf("expected %d users after concurrent inserts, got %d", workers*perWorker, n)
	}
}
