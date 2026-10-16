package keystore

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSignerCreatesThenReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "device-ca.key")
	s1, err := Open("file:" + path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("created key mode %04o, want 0600", fi.Mode().Perm())
	}
	s2, err := Open("file:" + path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p1, _ := Ed25519Public(s1)
	p2, _ := Ed25519Public(s2)
	if !p1.Equal(p2) {
		t.Fatal("reloading the key file produced a different key")
	}
	sig, err := Sign(s2, []byte("msg"))
	if err != nil || !ed25519.Verify(p1, []byte("msg"), sig) {
		t.Fatalf("sign/verify: %v", err)
	}
}

func TestFileSignerRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.key")
	if _, err := Open("file:" + path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open("file:" + path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected a permissions refusal, got %v", err)
	}
}

func TestFileSignerAcceptsRawAndBase64Seeds(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	for name, content := range map[string][]byte{
		"raw.key": seed,
		"b64.key": []byte(base64.StdEncoding.EncodeToString(seed) + "\n"),
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open("file:" + p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, _ := Ed25519Public(s); !got.Equal(want) {
			t.Fatalf("%s: wrong key", name)
		}
	}
	bad := filepath.Join(dir, "bad.key")
	_ = os.WriteFile(bad, []byte("not a key"), 0o600)
	if _, err := Open("file:" + bad); err == nil {
		t.Fatal("garbage key file must be rejected")
	}
}

func TestEnvSigner(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	t.Setenv("PQANON_TEST_SEED", base64.StdEncoding.EncodeToString(seed))
	s, err := Open("env:PQANON_TEST_SEED")
	if err != nil {
		t.Fatal(err)
	}
	want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if got, _ := Ed25519Public(s); !got.Equal(want) {
		t.Fatal("env signer derived the wrong key")
	}
	t.Setenv("PQANON_TEST_SEED", "too-short")
	if _, err := Open("env:PQANON_TEST_SEED"); err == nil {
		t.Fatal("bad env seed must be rejected")
	}
	if _, err := Open("env:PQANON_TEST_UNSET_VAR"); err == nil {
		t.Fatal("unset env var must be rejected")
	}
}

func TestEphemeralAndUnknownSpecs(t *testing.T) {
	a, err := Open("ephemeral")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Open("ephemeral")
	pa, _ := Ed25519Public(a)
	pb, _ := Ed25519Public(b)
	if pa.Equal(pb) {
		t.Fatal("two ephemeral keys must differ")
	}
	for _, spec := range []string{"", "file:", "kms:arn:aws:whatever", "pkcs11:token=x"} {
		if _, err := Open(spec); err == nil {
			t.Fatalf("spec %q must be rejected", spec)
		}
	}
}

func TestParsePKCS11Spec(t *testing.T) {
	t.Setenv("PQANON_TEST_PIN", "1234")
	cfg, err := parsePKCS11("pkcs11:token=pq%20anon;object=device-ca?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-env=PQANON_TEST_PIN&create=1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "pq anon" || cfg.Object != "device-ca" || cfg.PIN != "1234" || !cfg.Create ||
		cfg.Module != "/usr/lib/softhsm/libsofthsm2.so" {
		t.Fatalf("parsed %+v", cfg)
	}
	for _, spec := range []string{
		"pkcs11:object=k?module-path=/m.so&pin-value=1",    // no token
		"pkcs11:token=t?module-path=/m.so&pin-value=1",     // no object
		"pkcs11:token=t;object=k?pin-value=1",              // no module
		"pkcs11:token=t;object=k?module-path=/m.so",        // no PIN
		"pkcs11:token=t;object=k;slot=3?module-path=/m.so", // unsupported attribute
	} {
		if _, err := parsePKCS11(spec); err == nil {
			t.Fatalf("spec %q must be rejected", spec)
		}
	}
}

func TestDescribeRedactsPIN(t *testing.T) {
	d := Describe("pkcs11:token=t;object=k?module-path=/m.so&pin-value=hunter2")
	if strings.Contains(d, "hunter2") {
		t.Fatalf("pin leaked into %q", d)
	}
	if Describe("file:/x") != "file:/x" {
		t.Fatal("non-pkcs11 specs are logged unchanged")
	}
}

// badSigner returns signatures that do not verify, like a token misconfigured
// for a prehash mode.
type badSigner struct{ pub ed25519.PublicKey }

func (b badSigner) Public() crypto.PublicKey { return b.pub }
func (b badSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return make([]byte, ed25519.SignatureSize), nil
}

func TestSignRejectsSignaturesThatDoNotVerify(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Sign(badSigner{pub}, []byte("m")); err == nil {
		t.Fatal("Sign must refuse a backend whose signatures do not verify")
	}
}
