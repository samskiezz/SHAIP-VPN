package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"pqanon/control-plane/keystore"
)

// Token is a compact EdDSA-signed bearer token: base64url(claims).base64url(sig)
// where sig = Ed25519(server_key, base64url(claims)). This is the control
// plane's own auth token (PQANON-CP/1); it is distinct from the tunnel's
// handshake authentication.
type Token struct {
	Subject   string `json:"sub"`
	Email     string `json:"email"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// TokenSigner signs and verifies tokens with an Ed25519 key. The private half is
// a crypto.Signer, so it may live in memory, in a key file, or in an HSM.
type TokenSigner struct {
	signer crypto.Signer
	pub    ed25519.PublicKey
	ttl    time.Duration
}

// NewTokenSigner generates a fresh signing key. The key is ephemeral: every
// process restart rotates it, which invalidates all outstanding tokens. Use
// this only for tests and ephemeral dev; production must pin a key via
// NewTokenSignerWithSeed so sessions survive restarts and horizontal scaling.
func NewTokenSigner(ttl time.Duration) (*TokenSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &TokenSigner{signer: priv, pub: pub, ttl: ttl}, nil
}

// NewTokenSignerFromSigner uses an already-resolved key (see keystore.Open).
func NewTokenSignerFromSigner(ttl time.Duration, s crypto.Signer) (*TokenSigner, error) {
	pub, err := keystore.Ed25519Public(s)
	if err != nil {
		return nil, err
	}
	return &TokenSigner{signer: s, pub: pub, ttl: ttl}, nil
}

// NewTokenSignerWithSeed derives a stable signing key from a 32-byte Ed25519
// seed, so the same seed always yields the same key. Tokens issued before a
// restart keep verifying, and multiple replicas sharing the seed accept each
// other's tokens.
func NewTokenSignerWithSeed(ttl time.Duration, seed []byte) (*TokenSigner, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("token signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &TokenSigner{signer: priv, pub: pub, ttl: ttl}, nil
}

var b64 = base64.RawURLEncoding

func (t *TokenSigner) Issue(sub, email string) (string, error) {
	return t.IssueWithTTL(sub, email, t.ttl)
}

// IssueWithTTL issues a token valid for a custom lifetime — used for paid VPN
// access grants, whose duration is the purchased plan's, not the default TTL.
func (t *TokenSigner) IssueWithTTL(sub, email string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Token{
		Subject:   sub,
		Email:     email,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := b64.EncodeToString(payload)
	sig, err := keystore.Sign(t.signer, []byte(encoded))
	if err != nil {
		return "", err
	}
	return encoded + "." + b64.EncodeToString(sig), nil
}

var errBadToken = errors.New("invalid token")

func (t *TokenSigner) Verify(tok string) (*Token, error) {
	dot := -1
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return nil, errBadToken
	}
	encoded, sigPart := tok[:dot], tok[dot+1:]
	sig, err := b64.DecodeString(sigPart)
	if err != nil || !ed25519.Verify(t.pub, []byte(encoded), sig) {
		return nil, errBadToken
	}
	payload, err := b64.DecodeString(encoded)
	if err != nil {
		return nil, errBadToken
	}
	var claims Token
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errBadToken
	}
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}
