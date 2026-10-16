package main

// Discount / comp codes (operator-issued free or promotional access).
//
// A code is the honest way to grant access without a crypto payment: a free
// trial, a launch promo, or a test pass. Claiming one is deliberately
// identity-free, exactly like redeeming a paid token — it returns the same kind
// of access grant and records nothing about who claimed it. Only a hash of the
// code is ever stored. Operators create codes with the admin endpoint or seed
// them from the COMP_CODES environment variable.

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// hashCode normalizes a code (trim, uppercase) and returns its SHA-256 hex, so
// codes are case-insensitive and the plaintext is never stored.
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(sum[:])
}

// POST /api/pay/claim-code {code} — redeem a discount/comp code for a VPN
// access grant. Identity-free, like /pay/redeem: no account, no auth, and the
// grant carries only a random session id and the plan's day-rounded expiry.
func (s *Server) handleClaimCode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if strings.TrimSpace(body.Code) == "" {
		errJSON(w, http.StatusBadRequest, "code required")
		return
	}
	c, err := s.store.ClaimCompCode(r.Context(), hashCode(body.Code))
	if err != nil {
		switch {
		case errors.Is(err, ErrCompExhausted):
			mCompClaims.WithLabelValues("exhausted").Inc()
			errJSON(w, http.StatusConflict, "this code has no uses left")
		case errors.Is(err, ErrNotFound):
			mCompClaims.WithLabelValues("invalid").Inc()
			errJSON(w, http.StatusUnauthorized, "unknown code")
		default:
			errJSON(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	mCompClaims.WithLabelValues("ok").Inc()

	sessionID := newSessionID()
	expires := dayCeil(time.Now().Add(time.Duration(c.DurationDays) * 24 * time.Hour))
	grant, err := s.tokens.IssueUntil("session:"+sessionID, expires)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "grant error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"grant":      grant,
		"plan":       c.Plan,
		"expires_at": expires,
	})
}

// POST /api/admin/comp-codes {plan, duration_days, max_uses} — admin only.
// Mints a fresh code, stores its hash, and returns the code once (it cannot be
// recovered later, like an account number or API key).
func (s *Server) handleCreateCompCode(w http.ResponseWriter, r *http.Request) {
	if !s.requireRole(w, r, "admin") {
		return
	}
	var body struct {
		Plan         string `json:"plan"`
		DurationDays int    `json:"duration_days"`
		MaxUses      int    `json:"max_uses"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	if body.DurationDays <= 0 || body.DurationDays > 3660 {
		errJSON(w, http.StatusBadRequest, "duration_days must be 1..3660")
		return
	}
	if body.MaxUses <= 0 || body.MaxUses > 1_000_000 {
		errJSON(w, http.StatusBadRequest, "max_uses must be 1..1000000")
		return
	}
	plan := strings.TrimSpace(body.Plan)
	if plan == "" {
		plan = "comp"
	}
	code := newCompCode()
	c := &CompCode{CodeHash: hashCode(code), Plan: plan, DurationDays: body.DurationDays, MaxUses: body.MaxUses}
	if err := s.store.CreateCompCode(r.Context(), c); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"code":          code,
		"plan":          plan,
		"duration_days": body.DurationDays,
		"max_uses":      body.MaxUses,
		"note":          "Shown once. Store it now; only a hash is kept and it cannot be recovered.",
	})
}

// newCompCode returns a readable, high-entropy code like "SHAIP-K7Q4-9ZB2-MX3R".
func newCompCode() string {
	b := make([]byte, 10)
	_, _ = crand.Read(b)
	s := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b) // 16 chars
	return fmt.Sprintf("SHAIP-%s-%s-%s", s[0:4], s[4:8], s[8:12])
}

// seedCompCodes creates codes from COMP_CODES, format
// "CODE:plan:days:maxuses,CODE2:plan:days:maxuses". Existing codes are left as
// they are (safe to re-run on restart). Nothing secret is logged.
func seedCompCodes(ctx context.Context, s *Server, spec string) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return
	}
	seeded := 0
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 4 {
			log.Printf("COMP_CODES: skipping malformed entry (want CODE:plan:days:maxuses)")
			continue
		}
		days, e1 := strconv.Atoi(strings.TrimSpace(parts[2]))
		uses, e2 := strconv.Atoi(strings.TrimSpace(parts[3]))
		if e1 != nil || e2 != nil || days <= 0 || uses <= 0 {
			log.Printf("COMP_CODES: skipping entry with a bad days/max-uses")
			continue
		}
		c := &CompCode{CodeHash: hashCode(parts[0]), Plan: strings.TrimSpace(parts[1]), DurationDays: days, MaxUses: uses}
		if err := s.store.CreateCompCode(ctx, c); err != nil {
			continue // already present, or unusable — don't log the code
		}
		seeded++
	}
	if seeded > 0 {
		log.Printf("seeded %d comp/discount code(s) from COMP_CODES", seeded)
	}
}
