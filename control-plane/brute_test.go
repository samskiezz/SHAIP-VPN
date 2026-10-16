package main

import (
	"context"
	"encoding/json"
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
	good, _ := signer.Issue("u1")
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

	passwords := []string{
		"", "short", "'; DROP TABLE users;--", "pass\x00word123", "pаsswоrd12",
		strings.Repeat("p", 1024), strings.Repeat("p", 4096),
	}
	accounts := []string{
		"", "1234", "1234 5678 9012 3456", "1234-5678-9012-3456", "12345678901234567",
		"abcd efgh ijkl mnop", "'; DROP TABLE users;--", "١٢٣٤٥٦٧٨٩٠١٢٣٤٥٦", // Arabic-Indic digits
		strings.Repeat("9", 4096),
	}
	for i, pw := range passwords {
		rec := do(t, h, "POST", "/api/auth/register", "", map[string]any{"password": pw})
		if rec.Code >= 500 {
			t.Fatalf("register case %d: server error %d — hostile input must not 5xx", i, rec.Code)
		}
		for j, acct := range accounts {
			rec = do(t, h, "POST", "/api/auth/login", "",
				map[string]any{"account_number": acct, "password": pw})
			if rec.Code >= 500 {
				t.Fatalf("login case %d/%d: server error %d", i, j, rec.Code)
			}
			if rec.Code == http.StatusOK {
				t.Fatalf("login case %d/%d: a guessed account number logged in", i, j)
			}
		}
	}

	// Brute: random registration payloads — status must stay in a sane set.
	// (Argon2id is deliberately expensive, so keep the count modest.)
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 150; i++ {
		pw := strings.Repeat("p", 4+rng.Intn(40))
		rec := do(t, h, "POST", "/api/auth/register", "", map[string]any{"password": pw})
		if rec.Code != http.StatusCreated && rec.Code != http.StatusBadRequest {
			t.Fatalf("unexpected register status %d (password length %d)", rec.Code, len(pw))
		}
	}
}

// The in-memory store must be safe under concurrent access (run with -race).
func TestStoreConcurrency(t *testing.T) {
	_, h, store := newTestServer(t)

	const workers = 12
	const perWorker = 6
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				rec := do(t, h, "POST", "/api/auth/register", "",
					map[string]any{"password": "password123"})
				if rec.Code != http.StatusCreated {
					t.Errorf("concurrent register failed: %d", rec.Code)
					return
				}
				// Each worker also logs in and writes an API key.
				var reg struct {
					AccountNumber string `json:"account_number"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &reg)
				rec = do(t, h, "POST", "/api/auth/login", "",
					map[string]any{"account_number": reg.AccountNumber, "password": "password123"})
				var login struct {
					Token string `json:"token"`
				}
				_ = json.Unmarshal(rec.Body.Bytes(), &login)
				if rec := do(t, h, "POST", "/api/apikeys", login.Token,
					map[string]any{"name": fmt.Sprintf("w%d-%d", w, i)}); rec.Code != http.StatusCreated {
					t.Errorf("concurrent api key: %d", rec.Code)
				}
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
