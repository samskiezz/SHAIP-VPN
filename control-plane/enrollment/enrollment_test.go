package enrollment

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
)

func fixedKey(seedByte byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

func fixed16(b byte) [16]byte {
	var a [16]byte
	for i := range a {
		a[i] = b
	}
	return a
}

func TestEnrollTokenRoundTrip(t *testing.T) {
	authPriv, authPub := fixedKey(0x11)
	c := EnrollClaims{
		TokenID:   fixed16(0xab),
		Account:   "acct-demo",
		IssuedAt:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC),
		OneTime:   true,
	}
	tok, err := IssueEnrollToken(authPriv, c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 2, 1, 0, 30, 0, 0, time.UTC)
	got, err := VerifyEnrollToken(authPub, tok, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Account != "acct-demo" || got.TokenID != fixed16(0xab) || !got.OneTime {
		t.Fatalf("claims round-trip mismatch: %+v", got)
	}
	if !got.IssuedAt.Equal(c.IssuedAt) || !got.ExpiresAt.Equal(c.ExpiresAt) {
		t.Fatalf("time round-trip mismatch: %+v", got)
	}
}

func TestEnrollTokenWrongKeyRejected(t *testing.T) {
	authPriv, _ := fixedKey(0x11)
	_, otherPub := fixedKey(0x99)
	c := EnrollClaims{TokenID: fixed16(1), Account: "a", IssuedAt: time.Unix(1000, 0), ExpiresAt: time.Unix(9000, 0)}
	tok, _ := IssueEnrollToken(authPriv, c)
	if _, err := VerifyEnrollToken(otherPub, tok, time.Unix(2000, 0)); err != ErrSignature {
		t.Fatalf("expected ErrSignature, got %v", err)
	}
}

func TestEnrollTokenExpiryAndNotYetValid(t *testing.T) {
	authPriv, authPub := fixedKey(0x11)
	c := EnrollClaims{TokenID: fixed16(1), Account: "a",
		IssuedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC)}
	tok, _ := IssueEnrollToken(authPriv, c)
	if _, err := VerifyEnrollToken(authPub, tok, time.Date(2026, 2, 1, 2, 0, 0, 0, time.UTC)); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if _, err := VerifyEnrollToken(authPub, tok, time.Date(2026, 1, 31, 23, 0, 0, 0, time.UTC)); err != ErrNotYetVal {
		t.Fatalf("expected ErrNotYetVal, got %v", err)
	}
}

func TestLabelSwapRejected(t *testing.T) {
	// An enrollment token re-labelled as a certificate must not verify as a cert:
	// the body magic no longer matches. (It fails at signature since the CA key
	// differs, but even with a matching key the magic guard rejects it.)
	authPriv, authPub := fixedKey(0x11)
	c := EnrollClaims{TokenID: fixed16(1), Account: "a", IssuedAt: time.Unix(1000, 0), ExpiresAt: time.Unix(9000, 0)}
	tok, _ := IssueEnrollToken(authPriv, c)
	swapped := LabelCert + tok[len(LabelEnroll):]
	if _, err := VerifyDeviceCert(authPub, swapped, time.Unix(2000, 0)); err == nil {
		t.Fatal("label-swapped token must not verify as a certificate")
	}
}

func TestDeviceCertRoundTrip(t *testing.T) {
	caPriv, caPub := fixedKey(0x22)
	_, devPub := fixedKey(0x33)
	c := CertClaims{
		DeviceID:  fixed16(0xcd),
		Account:   "acct-demo",
		DevicePub: devPub,
		IssuedAt:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC),
	}
	cert, err := IssueDeviceCert(caPriv, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyDeviceCert(caPub, cert, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Account != "acct-demo" || got.DeviceID != fixed16(0xcd) {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if !ed25519.PublicKey(got.DevicePub).Equal(devPub) {
		t.Fatalf("device pubkey mismatch")
	}
}

func TestTamperedBodyRejected(t *testing.T) {
	caPriv, caPub := fixedKey(0x22)
	_, devPub := fixedKey(0x33)
	c := CertClaims{DeviceID: fixed16(1), Account: "acct-demo", DevicePub: devPub,
		IssuedAt: time.Unix(1000, 0), ExpiresAt: time.Unix(9_000_000_000, 0)}
	cert, _ := IssueDeviceCert(caPriv, c)
	// Flip one base64url character in the body segment.
	b := []byte(cert)
	// find the two dots
	first := -1
	for i, ch := range b {
		if ch == '.' {
			first = i
			break
		}
	}
	b[first+3] ^= 0x01 // perturb a body byte (different base64 char)
	if _, err := VerifyDeviceCert(caPub, string(b), time.Unix(2000, 0)); err == nil {
		t.Fatal("tampered body must fail")
	}
}

// TestCrossLanguageVector emits a token and a certificate with fixed keys so the
// Rust verifier (client/src/enrollment.rs) can embed and re-verify the exact
// artifacts. If the wire format ever changes, this and the Rust vector change
// together.
func TestCrossLanguageVector(t *testing.T) {
	authPriv, authPub := fixedKey(0x11) // enrollment authority
	caPriv, caPub := fixedKey(0x22)     // device CA
	_, devPub := fixedKey(0x33)         // the enrolling device's identity key

	tok, err := IssueEnrollToken(authPriv, EnrollClaims{
		TokenID:   fixed16(0xab),
		Account:   "acct-demo",
		IssuedAt:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 2, 1, 1, 0, 0, 0, time.UTC),
		OneTime:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := IssueDeviceCert(caPriv, CertClaims{
		DeviceID:  fixed16(0xcd),
		Account:   "acct-demo",
		DevicePub: devPub,
		IssuedAt:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("CROSSLANG enroll_authority_pub = %s", hex.EncodeToString(authPub))
	t.Logf("CROSSLANG device_ca_pub        = %s", hex.EncodeToString(caPub))
	t.Logf("CROSSLANG device_pub           = %s", hex.EncodeToString(devPub))
	t.Logf("CROSSLANG enroll_token         = %s", tok)
	t.Logf("CROSSLANG device_cert          = %s", cert)
	t.Logf("CROSSLANG enroll_url           = %s", EnrollURL(tok))

	// Self-check: both verify here.
	if _, err := VerifyEnrollToken(authPub, tok, time.Date(2026, 2, 1, 0, 30, 0, 0, time.UTC)); err != nil {
		t.Fatalf("token self-verify: %v", err)
	}
	if _, err := VerifyDeviceCert(caPub, cert, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("cert self-verify: %v", err)
	}
}
