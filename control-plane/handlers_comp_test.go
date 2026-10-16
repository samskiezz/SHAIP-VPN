package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

// An operator mints a comp code; anyone can claim it (identity-free) for an
// access grant; a one-use code refuses a second claim; bad codes are rejected;
// and only an admin can mint one.
func TestCompCodeCreateAndClaim(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, adminTok := adminUser(t, srv, store)
	_, userTok := authedUser(t, srv, store)

	// Non-admin cannot mint a code.
	if rec := do(t, h, "POST", "/api/admin/comp-codes", userTok, map[string]any{"plan": "pro", "duration_days": 365, "max_uses": 1}); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin mint: want 403, got %d", rec.Code)
	}

	// Admin mints a one-year, single-use code.
	rec := do(t, h, "POST", "/api/admin/comp-codes", adminTok, map[string]any{"plan": "pro", "duration_days": 365, "max_uses": 1})
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint: %d (%s)", rec.Code, rec.Body.String())
	}
	var minted struct {
		Code string `json:"code"`
		Plan string `json:"plan"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	if minted.Code == "" || minted.Plan != "pro" {
		t.Fatalf("mint returned %+v", minted)
	}

	// Claiming it (no auth — identity-free) returns a grant for the plan.
	rec = do(t, h, "POST", "/api/pay/claim-code", "", map[string]any{"code": minted.Code})
	if rec.Code != http.StatusOK {
		t.Fatalf("claim: %d (%s)", rec.Code, rec.Body.String())
	}
	var claim struct {
		SessionID string `json:"session_id"`
		Grant     string `json:"grant"`
		Plan      string `json:"plan"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	if claim.Grant == "" || claim.SessionID == "" || claim.Plan != "pro" {
		t.Fatalf("claim returned %+v", claim)
	}
	// The grant verifies and carries only a session subject, no identity.
	tok, err := srv.tokens.Verify(claim.Grant)
	if err != nil || tok.Subject != "session:"+claim.SessionID {
		t.Fatalf("grant subject: %v %q", err, tok.Subject)
	}

	// Case-insensitive / whitespace-tolerant, but single-use: a second claim fails.
	if rec := do(t, h, "POST", "/api/pay/claim-code", "", map[string]any{"code": "  " + minted.Code + "  "}); rec.Code != http.StatusConflict {
		t.Fatalf("second claim: want 409, got %d (%s)", rec.Code, rec.Body.String())
	}

	// An unknown code is rejected.
	if rec := do(t, h, "POST", "/api/pay/claim-code", "", map[string]any{"code": "SHAIP-0000-0000-0000"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown code: want 401, got %d", rec.Code)
	}
	// An empty code is a bad request.
	if rec := do(t, h, "POST", "/api/pay/claim-code", "", map[string]any{"code": ""}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty code: want 400, got %d", rec.Code)
	}
}

// COMP_CODES seeding creates usable codes at startup.
func TestCompCodeSeeding(t *testing.T) {
	srv, h, _ := newTestServer(t)
	seedCompCodes(context.Background(), srv, "FREEYEAR:pro:365:3, BADENTRY, TRIAL:trial:7:0")
	// The well-formed, nonzero entry works; the malformed and zero-use ones are skipped.
	rec := do(t, h, "POST", "/api/pay/claim-code", "", map[string]any{"code": "freeyear"}) // lower-case: still matches
	if rec.Code != http.StatusOK {
		t.Fatalf("seeded claim: %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, "POST", "/api/pay/claim-code", "", map[string]any{"code": "TRIAL"}); rec.Code == http.StatusOK {
		t.Fatalf("a zero-use seed entry should not have been created")
	}
}
