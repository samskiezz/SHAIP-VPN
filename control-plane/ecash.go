package main

// Chaumian e-cash mint (§20 — untraceable access tokens).
//
// This is what makes payment unlinkable to usage. A buyer generates random
// token nonces, blinds them, and — once their Monero payment confirms — the
// mint blind-signs the blinded nonces with the RSA key for the plan they bought
// (a "denomination"). The buyer unblinds to get ordinary RSA signatures over
// their nonces. Later they redeem a token (nonce + signature); the mint verifies
// the signature against the denomination's public key and checks the nonce was
// never spent, then grants access. Because the mint only ever saw the *blinded*
// nonce at signing time, it cannot link the redeemed token to the payment that
// funded it — not even under subpoena.
//
// Crypto is RFC 9474 RSA Blind Signatures (RSABSSA-SHA384-PSS-Deterministic) via
// Cloudflare's CIRCL. We never hand-roll it; the deterministic variant is used
// because our messages are 32-byte CSPRNG nonces (high entropy), so no message
// randomizer is needed and the token stays a compact (nonce, signature) pair.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/blindsign/blindrsa"
)

// The one wire variant, matched byte-for-byte by the Rust client.
var blindRSAVariant = blindrsa.SHA384PSSDeterministic

// RSA modulus size for denomination keys. 2048 is the RFC 9474 example size and
// ample for short-lived access tokens; bump to 3072 for a longer key lifetime.
const blindRSABits = 2048

// DenomSpec declares a plan the mint will sell. Prices are set per coin in its
// own native unit, so no exchange-rate feed is needed.
type DenomSpec struct {
	ID           string
	Label        string
	DurationDays int
	PriceAtomic  uint64 // price in Monero atomic units (1 XMR = 1e12)
	PriceSats    uint64 // price in Bitcoin satoshis (1 BTC = 1e8)
}

// Price bundles a denomination's per-coin prices for the payment rail.
func (d *Denomination) Price() Price {
	return Price{MoneroAtomic: d.PriceAtomic, BitcoinSats: d.PriceSats}
}

// Denomination is a plan plus its blind-signing key.
type Denomination struct {
	DenomSpec
	sk       *rsa.PrivateKey
	signer   blindrsa.Signer
	verifier blindrsa.Verifier
}

// PublicKeyPEM returns the SPKI PEM of the denomination's public key, which
// clients fetch to blind tokens and to pin the key they expect.
func (d *Denomination) PublicKeyPEM() string {
	der, _ := x509.MarshalPKIXPublicKey(&d.sk.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// BlindSign signs a client's blinded token. The mint never sees the nonce.
func (d *Denomination) BlindSign(blinded []byte) ([]byte, error) {
	return d.signer.BlindSign(blinded)
}

// Verify checks a finalized token signature over its nonce.
func (d *Denomination) Verify(nonce, signature []byte) error {
	return d.verifier.Verify(nonce, signature)
}

// Mint holds every denomination, keyed by id, in a stable display order.
type Mint struct {
	denoms map[string]*Denomination
	order  []string
}

// NewMint builds the mint from specs. If keyDir is non-empty, each denomination
// key is loaded from <keyDir>/<id>.key.pem, generating and persisting one on
// first run so keys survive restarts (tokens signed before a restart stay
// valid). With an empty keyDir, keys are generated in memory (dev/tests).
func NewMint(keyDir string, specs []DenomSpec) (*Mint, error) {
	m := &Mint{denoms: make(map[string]*Denomination)}
	for _, spec := range specs {
		sk, err := loadOrCreateDenomKey(keyDir, spec.ID)
		if err != nil {
			return nil, fmt.Errorf("denomination %q: %w", spec.ID, err)
		}
		verifier, err := blindrsa.NewVerifier(blindRSAVariant, &sk.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("denomination %q verifier: %w", spec.ID, err)
		}
		m.denoms[spec.ID] = &Denomination{
			DenomSpec: spec,
			sk:        sk,
			signer:    blindrsa.NewSigner(sk),
			verifier:  verifier,
		}
		m.order = append(m.order, spec.ID)
	}
	return m, nil
}

// Get returns a denomination by id, or false.
func (m *Mint) Get(id string) (*Denomination, bool) {
	d, ok := m.denoms[id]
	return d, ok
}

// Denominations returns the denominations in declared order.
func (m *Mint) Denominations() []*Denomination {
	out := make([]*Denomination, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, m.denoms[id])
	}
	return out
}

func loadOrCreateDenomKey(keyDir, id string) (*rsa.PrivateKey, error) {
	if keyDir == "" {
		return rsa.GenerateKey(rand.Reader, blindRSABits)
	}
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(keyDir, id+".key.pem")
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, errors.New("invalid PEM in key file")
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	sk, err := rsa.GenerateKey(rand.Reader, blindRSABits)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(sk)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return sk, nil
}

// defaultDenominations are the plans the mint sells out of the box. Prices are
// in Monero atomic units (1 XMR = 1_000_000_000_000). These are placeholders an
// operator tunes; durations are what a redeemed token grants.
func defaultDenominations() []DenomSpec {
	const xmr = 1_000_000_000_000
	const btc = 100_000_000
	return []DenomSpec{
		{ID: "day", Label: "1 day", DurationDays: 1, PriceAtomic: xmr / 100, PriceSats: btc / 5000},    // 0.01 XMR / 20k sats
		{ID: "week", Label: "1 week", DurationDays: 7, PriceAtomic: xmr / 20, PriceSats: btc / 1100},   // 0.05 XMR / ~90k sats
		{ID: "month", Label: "1 month", DurationDays: 30, PriceAtomic: xmr / 8, PriceSats: btc / 450},  // 0.125 XMR / ~222k sats
		{ID: "quarter", Label: "3 months", DurationDays: 90, PriceAtomic: xmr / 4, PriceSats: btc / 220}, // 0.25 XMR / ~454k sats
	}
}
