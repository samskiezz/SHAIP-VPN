package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// newPayServer builds a control plane wired for untraceable payments with the
// dev rail (no chain) and dev settlement enabled.
func newPayServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	tokens, err := NewTokenSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	mint, err := NewMint("", []DenomSpec{
		{ID: "month", Label: "1 month", DurationDays: 30, PriceAtomic: 125_000_000_000},
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	srv := &Server{
		store: NewMemStore(), tokens: tokens, mint: mint,
		rails: map[string]PaymentRail{"dev": NewDevRail()}, defaultRail: "dev", devSettle: true,
	}
	return srv, routes(srv, "memory")
}

func pubKeyFromPEM(t *testing.T, pemStr string) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("no PEM block in denomination key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	return k.(*rsa.PublicKey)
}

// TestUnlinkablePaymentFlow walks the whole e-cash purchase: fetch the plan key,
// blind a nonce, open an order, pay (dev settle), collect the blind signature,
// unblind, and redeem it for an access grant — then prove the token can't be
// spent twice. This is the same protocol the Rust client speaks; the live E2E
// proves cross-language interop.
func TestUnlinkablePaymentFlow(t *testing.T) {
	srv, h := newPayServer(t)

	// 1. Denominations + the month plan's public key.
	rec := do(t, h, "GET", "/api/pay/denominations", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("denominations: %d (%s)", rec.Code, rec.Body.String())
	}
	var denoms struct {
		Rails         []string `json:"rails"`
		DefaultRail   string   `json:"default_rail"`
		Denominations []struct {
			ID           string `json:"id"`
			PublicKeyPEM string `json:"public_key_pem"`
			PriceXMR     string `json:"price_xmr"`
			PriceBTC     string `json:"price_btc"`
		} `json:"denominations"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &denoms)
	if denoms.DefaultRail != "dev" || len(denoms.Denominations) != 1 {
		t.Fatalf("unexpected denominations: %+v", denoms)
	}
	pk := pubKeyFromPEM(t, denoms.Denominations[0].PublicKeyPEM)

	// 2. Blind a random nonce under the plan key (the buyer).
	client, err := blindrsa.NewClient(blindRSAVariant, pk)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	prepared, err := client.Prepare(rand.Reader, nonce)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	blinded, state, err := client.Blind(rand.Reader, prepared)
	if err != nil {
		t.Fatalf("blind: %v", err)
	}
	b64 := base64.StdEncoding

	// 3. Open an order.
	rec = do(t, h, "POST", "/api/pay/order", "", map[string]any{
		"denom":          "month",
		"blinded_tokens": []string{b64.EncodeToString(blinded)},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("order: %d (%s)", rec.Code, rec.Body.String())
	}
	var order struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Address string `json:"address"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &order)
	if order.ID == "" || order.Status != "awaiting_payment" || order.Address == "" {
		t.Fatalf("bad order: %+v", order)
	}

	// 4. Collect before payment is refused.
	if rec := do(t, h, "POST", "/api/pay/collect", "", map[string]any{"order_id": order.ID}); rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402 before payment, got %d", rec.Code)
	}

	// 5. Pay (dev settle), then status flips to paid.
	if rec := do(t, h, "POST", "/api/pay/dev/settle", "", map[string]any{"order_id": order.ID}); rec.Code != http.StatusOK {
		t.Fatalf("dev settle: %d (%s)", rec.Code, rec.Body.String())
	}
	rec = do(t, h, "GET", "/api/pay/order/"+order.ID, "", nil)
	var st struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Status != "paid" {
		t.Fatalf("status after settle = %q, want paid", st.Status)
	}

	// 6. Collect the blind signature and unblind it.
	rec = do(t, h, "POST", "/api/pay/collect", "", map[string]any{"order_id": order.ID})
	if rec.Code != http.StatusOK {
		t.Fatalf("collect: %d (%s)", rec.Code, rec.Body.String())
	}
	var coll struct {
		Signatures []string `json:"signatures"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &coll)
	if len(coll.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(coll.Signatures))
	}
	blindSig, _ := b64.DecodeString(coll.Signatures[0])
	sig, err := client.Finalize(state, blindSig)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if err := client.Verify(prepared, sig); err != nil {
		t.Fatalf("unblinded token must verify: %v", err)
	}

	// 7. Redeem the token for an access grant. Deterministic variant → the
	// signed message is the nonce itself (Prepare is identity).
	rec = do(t, h, "POST", "/api/pay/redeem", "", map[string]any{
		"denom":     "month",
		"token":     b64.EncodeToString(prepared),
		"signature": b64.EncodeToString(sig),
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem: %d (%s)", rec.Code, rec.Body.String())
	}
	var grant struct {
		SessionID string    `json:"session_id"`
		Grant     string    `json:"grant"`
		Plan      string    `json:"plan"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &grant)
	if grant.SessionID == "" || grant.Grant == "" || grant.Plan != "month" {
		t.Fatalf("bad grant: %+v", grant)
	}
	// The grant is a real, verifiable access credential.
	if _, err := srv.tokens.Verify(grant.Grant); err != nil {
		t.Fatalf("access grant must verify: %v", err)
	}
	// Nothing about the redemption is written down: no audit entry at all
	// (httptest requests come from 192.0.2.1, and it must appear nowhere).
	if n := len(srv.store.(*MemStore).audit); n != 0 {
		t.Fatalf("a redemption must leave no audit entry, found %d", n)
	}
	// The grant's expiry is a day boundary, not the redemption moment + 30d.
	if exp := grant.ExpiresAt; !exp.Equal(day(exp)) {
		t.Fatalf("grant expiry %v reveals the moment of redemption", exp)
	}

	// 8. Double-spend is refused.
	if rec := do(t, h, "POST", "/api/pay/redeem", "", map[string]any{
		"denom": "month", "token": b64.EncodeToString(prepared), "signature": b64.EncodeToString(sig),
	}); rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on double-spend, got %d", rec.Code)
	}

	// 9. A forged token (valid base64, wrong signature) is rejected.
	if rec := do(t, h, "POST", "/api/pay/redeem", "", map[string]any{
		"denom": "month", "token": b64.EncodeToString([]byte("not a real nonce........")),
		"signature": b64.EncodeToString(sig),
	}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a forged token, got %d", rec.Code)
	}

	// 10. The payment metrics now carry real samples (this flow created an order
	// and redeemed ok / was refused / was forged).
	m := do(t, metricsRoutes(), "GET", "/metrics", "", nil).Body.String()
	for _, want := range []string{
		`pqanon_cp_orders_total{denom="month",rail="dev"}`,
		`pqanon_cp_redemptions_total{denom="month",result="ok"}`,
		`pqanon_cp_redemptions_total{denom="month",result="invalid"}`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
}

// TestDevSettleGated proves the dev settle endpoint is unreachable unless
// explicitly enabled.
func TestDevSettleGated(t *testing.T) {
	tokens, _ := NewTokenSigner(time.Hour)
	mint, _ := NewMint("", []DenomSpec{{ID: "day", DurationDays: 1, PriceAtomic: 1}})
	srv := &Server{
		store: NewMemStore(), tokens: tokens, mint: mint,
		rails: map[string]PaymentRail{"dev": NewDevRail()}, defaultRail: "dev", devSettle: false,
	}
	h := routes(srv, "memory")
	if rec := do(t, h, "POST", "/api/pay/dev/settle", "", map[string]any{"order_id": "x"}); rec.Code != http.StatusNotFound {
		t.Fatalf("dev settle must be gated off, got %d", rec.Code)
	}
}
