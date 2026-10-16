package main

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// TestBlindSignRoundTrip proves the mint's blind signer and verifier agree: a
// client can blind a nonce, have the mint sign it without seeing it, unblind,
// and get a signature the mint then verifies. This is the same protocol the
// Rust client speaks; the live buy→redeem E2E proves cross-language interop.
func TestBlindSignRoundTrip(t *testing.T) {
	m, err := NewMint("", []DenomSpec{{ID: "month", Label: "1 month", DurationDays: 30, PriceAtomic: 1}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	d, _ := m.Get("month")

	// Client side (CIRCL): blind a random 32-byte nonce.
	client, err := blindrsa.NewClient(blindRSAVariant, &d.sk.PublicKey)
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

	// Mint signs the blinded nonce (never sees `nonce`).
	blindSig, err := d.BlindSign(blinded)
	if err != nil {
		t.Fatalf("blind sign: %v", err)
	}

	// Client unblinds to a normal signature.
	sig, err := client.Finalize(state, blindSig)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}

	// The mint verifies the finalized token over the prepared message.
	if err := d.Verify(prepared, sig); err != nil {
		t.Fatalf("verify valid token: %v", err)
	}

	// A tampered nonce must not verify.
	bad := make([]byte, len(prepared))
	copy(bad, prepared)
	bad[0] ^= 0xff
	if err := d.Verify(bad, sig); err == nil {
		t.Fatal("tampered token must not verify")
	}

	// A different denomination's key must not verify this token.
	m2, _ := NewMint("", []DenomSpec{{ID: "week", DurationDays: 7, PriceAtomic: 1}})
	d2, _ := m2.Get("week")
	if err := d2.Verify(prepared, sig); err == nil {
		t.Fatal("token must not verify under a different denomination key")
	}
}

func TestDefaultDenominations(t *testing.T) {
	m, err := NewMint("", defaultDenominations())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got := m.Denominations()
	if len(got) != 4 {
		t.Fatalf("expected 4 denominations, got %d", len(got))
	}
	// Order is stable and public keys are valid PEM.
	if got[0].ID != "day" || got[3].ID != "quarter" {
		t.Fatalf("unexpected order: %s..%s", got[0].ID, got[3].ID)
	}
	for _, d := range got {
		if len(d.PublicKeyPEM()) == 0 {
			t.Fatalf("denomination %q has no public key PEM", d.ID)
		}
	}
}
