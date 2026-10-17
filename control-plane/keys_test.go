package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"shaip/control-plane/keystore"
)

func pubOf(t *testing.T, name, specVar, legacy string) ed25519.PublicKey {
	t.Helper()
	s, _, err := resolveSigner(name, specVar, legacy)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	pub, err := keystore.Ed25519Public(s)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestKeyDirKeysSurviveRestart(t *testing.T) {
	// The CRL key used to be regenerated on every boot, so a tunnel server that
	// pinned it broke on each control-plane restart. With KEY_DIR it persists.
	dir := t.TempDir()
	t.Setenv("KEY_DIR", dir)
	t.Setenv("CRL_SIGNER", "")
	first := pubOf(t, "crl", "CRL_SIGNER", "")
	second := pubOf(t, "crl", "CRL_SIGNER", "")
	if !first.Equal(second) {
		t.Fatal("KEY_DIR key changed across a simulated restart")
	}
	fi, err := os.Stat(filepath.Join(dir, "crl.key"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("expected KEY_DIR/crl.key with mode 0600: %v", err)
	}
}

func TestSignerPrecedence(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	seedPub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	// The legacy seed variable beats KEY_DIR.
	t.Setenv("KEY_DIR", dir)
	t.Setenv("TOKEN_SIGNER", "")
	t.Setenv("TOKEN_SIGNING_KEY", base64.StdEncoding.EncodeToString(seed))
	if !pubOf(t, "token", "TOKEN_SIGNER", "TOKEN_SIGNING_KEY").Equal(seedPub) {
		t.Fatal("TOKEN_SIGNING_KEY must be honoured")
	}

	// An explicit spec beats both.
	explicit := filepath.Join(dir, "explicit.key")
	t.Setenv("TOKEN_SIGNER", "file:"+explicit)
	got := pubOf(t, "token", "TOKEN_SIGNER", "TOKEN_SIGNING_KEY")
	if got.Equal(seedPub) {
		t.Fatal("TOKEN_SIGNER must take precedence over TOKEN_SIGNING_KEY")
	}
	if _, err := os.Stat(explicit); err != nil {
		t.Fatalf("explicit key file not created: %v", err)
	}

	// A bad spec is a hard error, never a silent ephemeral fallback.
	t.Setenv("TOKEN_SIGNER", "nonsense:spec")
	if _, _, err := resolveSigner("token", "TOKEN_SIGNER", "TOKEN_SIGNING_KEY"); err == nil {
		t.Fatal("a malformed spec must fail startup")
	}
}

func TestCRLSignatureVerifiesWithPublishedKey(t *testing.T) {
	srv, h, _ := newTestServer(t)
	rec := do(t, h, "GET", "/api/crl", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("crl: %d", rec.Code)
	}
	var out struct {
		CRL json.RawMessage `json:"crl"`
		Sig string          `json:"ed25519_sig"`
		Pub string          `json:"ed25519_pub"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(out.Sig)
	pub, _ := hex.DecodeString(out.Pub)
	if !ed25519.PublicKey(pub).Equal(srv.crlPub) {
		t.Fatal("published CRL key differs from the server's")
	}
	if !ed25519.Verify(pub, out.CRL, sig) {
		t.Fatal("CRL signature does not verify over the served payload")
	}
}
