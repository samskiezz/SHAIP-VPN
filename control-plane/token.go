package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
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

// TokenSigner signs and verifies tokens with an Ed25519 keypair.
type TokenSigner struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	ttl  time.Duration
}

// NewTokenSigner generates a fresh signing key (rotated on each boot unless a
// key is provided out of band).
func NewTokenSigner(ttl time.Duration) (*TokenSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &TokenSigner{priv: priv, pub: pub, ttl: ttl}, nil
}

var b64 = base64.RawURLEncoding

func (t *TokenSigner) Issue(sub, email string) (string, error) {
	now := time.Now()
	claims := Token{
		Subject:   sub,
		Email:     email,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(t.ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := b64.EncodeToString(payload)
	sig := ed25519.Sign(t.priv, []byte(encoded))
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
