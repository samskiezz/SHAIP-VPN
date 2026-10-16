package main

// Untraceable payment endpoints (§20). No endpoint here takes or returns any
// identity: an order is a denomination, an address, and a bag of blinded tokens.
// The flow is: GET /pay/denominations → POST /pay/order → (pay the address) →
// GET /pay/order/{id} until paid → POST /pay/collect → POST /pay/redeem.

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// How long a buyer has to pay before an order expires, and the cap on tokens
// per order (bounds the mint's signing work per request).
const (
	orderTTL      = 24 * time.Hour
	maxTokens     = 50
	b64TokenLimit = 4096 // max base64 chars per blinded token / signature
)

var b64std = base64.StdEncoding

// GET /api/pay/denominations — the plans on sale and their blind-signing public
// keys. Clients blind tokens under these and pin them.
func (s *Server) handleDenominations(w http.ResponseWriter, r *http.Request) {
	if s.mint == nil {
		errJSON(w, http.StatusServiceUnavailable, "payments not configured")
		return
	}
	type denomOut struct {
		ID           string `json:"id"`
		Label        string `json:"label"`
		DurationDays int    `json:"duration_days"`
		PriceAtomic  uint64 `json:"price_atomic"`
		PriceXMR     string `json:"price_xmr"`
		PriceSats    uint64 `json:"price_sats"`
		PriceBTC     string `json:"price_btc"`
		PublicKeyPEM string `json:"public_key_pem"`
	}
	out := []denomOut{}
	for _, d := range s.mint.Denominations() {
		out = append(out, denomOut{
			ID: d.ID, Label: d.Label, DurationDays: d.DurationDays,
			PriceAtomic: d.PriceAtomic, PriceXMR: formatXMR(d.PriceAtomic),
			PriceSats: d.PriceSats, PriceBTC: formatBTC(d.PriceSats),
			PublicKeyPEM: d.PublicKeyPEM(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rails":         s.railNames(),
		"default_rail":  s.defaultRail,
		"denominations": out,
	})
}

// railFor resolves a rail by name, defaulting to the configured default.
func (s *Server) railFor(name string) (PaymentRail, bool) {
	if name == "" {
		name = s.defaultRail
	}
	r, ok := s.rails[name]
	return r, ok
}

// railNames lists available rails in a stable order.
func (s *Server) railNames() []string {
	out := []string{}
	for _, n := range []string{"monero", "btcpay", "dev"} {
		if _, ok := s.rails[n]; ok {
			out = append(out, n)
		}
	}
	return out
}

// POST /api/pay/order {denom, blinded_tokens:[b64]} — open an order and quote an
// address to pay.
func (s *Server) handleCreateOrder(w http.ResponseWriter, r *http.Request) {
	if s.mint == nil {
		errJSON(w, http.StatusServiceUnavailable, "payments not configured")
		return
	}
	var body struct {
		Denom         string   `json:"denom"`
		Rail          string   `json:"rail"`
		BlindedTokens []string `json:"blinded_tokens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	d, ok := s.mint.Get(body.Denom)
	if !ok {
		errJSON(w, http.StatusBadRequest, "unknown denomination")
		return
	}
	rail, ok := s.railFor(body.Rail)
	if !ok {
		errJSON(w, http.StatusBadRequest, "unknown payment rail")
		return
	}
	if len(body.BlindedTokens) == 0 || len(body.BlindedTokens) > maxTokens {
		errJSON(w, http.StatusBadRequest, fmt.Sprintf("1..%d tokens per order", maxTokens))
		return
	}
	blinded := make([][]byte, 0, len(body.BlindedTokens))
	for _, t := range body.BlindedTokens {
		if len(t) > b64TokenLimit {
			errJSON(w, http.StatusBadRequest, "token too large")
			return
		}
		raw, err := b64std.DecodeString(t)
		if err != nil {
			errJSON(w, http.StatusBadRequest, "blinded tokens must be base64")
			return
		}
		blinded = append(blinded, raw)
	}

	order := &PayOrder{
		Denom: d.ID, Rail: rail.Name(), AmountAtomic: d.PriceAtomic,
		Status: "awaiting_payment", BlindedTokens: blinded,
		ExpiresAt: time.Now().Add(orderTTL).UTC(),
	}
	// Reserve the id first so the rail can label the charge with it.
	if err := s.store.CreatePayOrder(r.Context(), order); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	quote, err := rail.NewCharge(r.Context(), order.ID, d.Price())
	if err != nil {
		errJSON(w, http.StatusBadGateway, "payment backend error: "+err.Error())
		return
	}
	order.Address = quote.Address
	order.Meta = quote.Meta
	order.AmountLabel = quote.AmountLabel
	order.URI = quote.URI
	if err := s.store.UpdatePayOrder(r.Context(), order); err != nil {
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, s.orderView(order))
}

// GET /api/pay/order/{id} — status, checking the chain if still awaiting.
func (s *Server) handleOrderStatus(w http.ResponseWriter, r *http.Request) {
	order, err := s.store.GetPayOrder(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	if order.Status == "awaiting_payment" {
		if time.Now().After(order.ExpiresAt) {
			order.Status = "expired"
			_ = s.store.UpdatePayOrder(r.Context(), order)
		} else if s.checkOrderPaid(r.Context(), order) {
			now := time.Now().UTC()
			order.Status = "paid"
			order.PaidAt = &now
			_ = s.store.UpdatePayOrder(r.Context(), order)
		}
	}
	writeJSON(w, http.StatusOK, s.orderView(order))
}

// checkOrderPaid asks the order's rail whether it has been paid.
func (s *Server) checkOrderPaid(ctx context.Context, order *PayOrder) bool {
	rail, ok := s.rails[order.Rail]
	if !ok {
		return false
	}
	confirmed, err := rail.CheckPaid(ctx, RailQuote{Address: order.Address, Meta: order.Meta})
	return err == nil && confirmed
}

// POST /api/pay/collect {order_id} — once paid, blind-sign the tokens and return
// the signatures. Idempotent: repeated calls return the same signatures.
func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		OrderID string `json:"order_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	order, err := s.store.GetPayOrder(r.Context(), body.OrderID)
	if err != nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	d, ok := s.mint.Get(order.Denom)
	if !ok {
		errJSON(w, http.StatusInternalServerError, "denomination gone")
		return
	}

	// Re-check payment if the client collects before polling status.
	if order.Status == "awaiting_payment" && s.checkOrderPaid(r.Context(), order) {
		now := time.Now().UTC()
		order.Status = "paid"
		order.PaidAt = &now
		_ = s.store.UpdatePayOrder(r.Context(), order)
	}
	if order.Status != "paid" && order.Status != "collected" {
		errJSON(w, http.StatusPaymentRequired, "order not paid")
		return
	}

	// Sign once; store the signatures so retries are idempotent.
	if len(order.BlindSigs) == 0 {
		sigs := make([][]byte, 0, len(order.BlindedTokens))
		for _, bt := range order.BlindedTokens {
			sig, err := d.BlindSign(bt)
			if err != nil {
				errJSON(w, http.StatusInternalServerError, "blind sign failed")
				return
			}
			sigs = append(sigs, sig)
		}
		order.BlindSigs = sigs
		order.Status = "collected"
		if err := s.store.UpdatePayOrder(r.Context(), order); err != nil {
			errJSON(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	out := make([]string, len(order.BlindSigs))
	for i, s := range order.BlindSigs {
		out[i] = b64std.EncodeToString(s)
	}
	writeJSON(w, http.StatusOK, map[string]any{"signatures": out})
}

// POST /api/pay/redeem {denom, token:b64(nonce), signature:b64} — spend a token
// for a VPN access grant. The grant carries a random session id and the plan's
// expiry; it has no link to any order or payment.
func (s *Server) handleRedeem(w http.ResponseWriter, r *http.Request) {
	if s.mint == nil {
		errJSON(w, http.StatusServiceUnavailable, "payments not configured")
		return
	}
	var body struct {
		Denom     string `json:"denom"`
		Token     string `json:"token"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	d, ok := s.mint.Get(body.Denom)
	if !ok {
		errJSON(w, http.StatusBadRequest, "unknown denomination")
		return
	}
	nonce, err1 := b64std.DecodeString(body.Token)
	sig, err2 := b64std.DecodeString(body.Signature)
	if err1 != nil || err2 != nil || len(nonce) == 0 {
		errJSON(w, http.StatusBadRequest, "token and signature must be base64")
		return
	}
	if err := d.Verify(nonce, sig); err != nil {
		errJSON(w, http.StatusUnauthorized, "invalid token")
		return
	}
	// Double-spend guard, keyed by a hash of the nonce (we never store the nonce
	// itself, so redemption records reveal nothing).
	h := sha256.Sum256(append([]byte(d.ID+"|"), nonce...))
	nonceHash := hex.EncodeToString(h[:])
	if err := s.store.SpendToken(r.Context(), d.ID, nonceHash); err != nil {
		if errors.Is(err, ErrSpent) {
			errJSON(w, http.StatusConflict, "token already redeemed")
			return
		}
		errJSON(w, http.StatusInternalServerError, err.Error())
		return
	}

	sessionID := newSessionID()
	ttl := time.Duration(d.DurationDays) * 24 * time.Hour
	grant, err := s.tokens.IssueWithTTL("session:"+sessionID, "", ttl)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "grant error")
		return
	}
	s.audit(r, "token.redeem", d.ID) // no identity; records the plan only
	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"grant":      grant,
		"plan":       d.ID,
		"expires_at": time.Now().Add(ttl).UTC(),
	})
}

// POST /api/pay/dev/settle {order_id} — dev/CI only: mark an order paid without
// a chain. Gated by PAY_DEV_SETTLE; refused otherwise.
func (s *Server) handleDevSettle(w http.ResponseWriter, r *http.Request) {
	dev, _ := s.rails["dev"].(*DevRail)
	if !s.devSettle || dev == nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	var body struct {
		OrderID string `json:"order_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		errJSON(w, http.StatusBadRequest, "bad request")
		return
	}
	order, err := s.store.GetPayOrder(r.Context(), body.OrderID)
	if err != nil {
		errJSON(w, http.StatusNotFound, "not found")
		return
	}
	dev.Settle(order.Address, order.AmountAtomic)
	writeJSON(w, http.StatusOK, map[string]string{"status": "settled"})
}

func (s *Server) orderView(o *PayOrder) map[string]any {
	v := map[string]any{
		"id":           o.ID,
		"denom":        o.Denom,
		"rail":         o.Rail,
		"address":      o.Address,
		"amount_label": o.AmountLabel,
		"status":       o.Status,
		"expires_at":   o.ExpiresAt,
	}
	if o.URI != "" {
		v["uri"] = o.URI
	}
	return v
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}
