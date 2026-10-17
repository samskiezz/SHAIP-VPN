//go:build cgo

package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/pkcs11"

	"shaip/control-plane/enrollment"
)

// TestPKCS11SoftHSM runs against a real PKCS#11 token. It needs a module path,
// an initialized token, and its user PIN in the environment; the master battery
// provisions a throwaway SoftHSM2 token and fails its HSM stage if this test is
// skipped rather than run.
func TestPKCS11SoftHSM(t *testing.T) {
	module := os.Getenv("SHAIP_TEST_PKCS11_MODULE")
	token := os.Getenv("SHAIP_TEST_PKCS11_TOKEN")
	if module == "" || token == "" || os.Getenv("SHAIP_TEST_PKCS11_PIN") == "" {
		t.Skip("set SHAIP_TEST_PKCS11_MODULE/_TOKEN/_PIN to run against a real token")
	}
	rnd := make([]byte, 4)
	_, _ = rand.Read(rnd)
	label := "shaip-test-" + hex.EncodeToString(rnd)
	base := "pkcs11:token=" + token + ";object=" + label +
		"?module-path=" + module + "&pin-env=SHAIP_TEST_PKCS11_PIN"

	// A wrong PIN is refused by the token. This must run before any successful
	// login: PKCS#11 login state is shared by every session in the application,
	// so after one good login a second C_Login reports "already logged in".
	t.Setenv("SHAIP_WRONG_PIN", "0000")
	wrong := strings.Replace(base, "pin-env=SHAIP_TEST_PKCS11_PIN", "pin-env=SHAIP_WRONG_PIN", 1)
	if _, err := Open(wrong + "&create=1"); err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("wrong PIN: want a login failure, got %v", err)
	}

	// Without create=1 a missing key is an error that says how to fix it.
	if _, err := Open(base); err == nil || !strings.Contains(err.Error(), "create=1") {
		t.Fatalf("missing key: want a create=1 hint, got %v", err)
	}

	// Generate on the token, then sign through it.
	s, err := Open(base + "&create=1")
	if err != nil {
		t.Fatalf("open+create: %v", err)
	}
	pub, err := Ed25519Public(s)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("signed inside the HSM")
	sig, err := Sign(s, msg)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("token signature does not verify as pure Ed25519")
	}

	// The keypair persists on the token: reopening finds the same key.
	s2, err := Open(base)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if pub2, _ := Ed25519Public(s2); !pub2.Equal(pub) {
		t.Fatal("reopening the token produced a different key")
	}

	// The private key is non-extractable: the token refuses to reveal CKA_VALUE.
	ps := s2.(*pkcs11Signer)
	if _, err := ps.ctx.GetAttributeValue(ps.session, ps.key, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}); err == nil {
		t.Fatal("private key value must not be readable from the token")
	}

	// An unknown token label is rejected.
	if _, err := Open("pkcs11:token=no-such-token;object=x?module-path=" + module + "&pin-env=SHAIP_TEST_PKCS11_PIN"); err == nil {
		t.Fatal("an unknown token label must be rejected")
	}

	// The HSM-held key works for a real artifact: issue an enrollment token
	// with it and verify that token against the token's public key.
	c := enrollment.EnrollClaims{
		Account:   "acct-hsm",
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	tok, err := enrollment.IssueEnrollToken(s, c)
	if err != nil {
		t.Fatalf("issue with HSM signer: %v", err)
	}
	got, err := enrollment.VerifyEnrollToken(pub, tok, time.Now())
	if err != nil || got.Account != "acct-hsm" {
		t.Fatalf("verify HSM-issued token: %v %+v", err, got)
	}
}
