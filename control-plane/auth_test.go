package main

import (
	"testing"
	"time"
)

func TestArgon2idRoundTrip(t *testing.T) {
	hash, err := hashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := verifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("verify good password: ok=%v err=%v", ok, err)
	}
	bad, err := verifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("verify bad password err: %v", err)
	}
	if bad {
		t.Fatal("wrong password accepted")
	}
}

func TestTokenSignVerify(t *testing.T) {
	signer, err := NewTokenSigner(time.Hour)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := signer.Issue("user-1")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	// Tampering must fail.
	if _, err := signer.Verify(tok + "x"); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestExpiredToken(t *testing.T) {
	signer, _ := NewTokenSigner(-1 * time.Second) // already expired
	tok, _ := signer.Issue("u")
	if _, err := signer.Verify(tok); err == nil {
		t.Fatal("expired token accepted")
	}
}
