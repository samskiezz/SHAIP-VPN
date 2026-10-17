// Package keystore resolves the control plane's signing keys to standard
// crypto.Signer values, so the code that signs (auth tokens, the CRL, enrollment
// tokens, device certificates, the directory consensus) never touches key
// material directly and never needs to know where a key lives.
//
// A key is named by a spec string:
//
//	file:/var/lib/shaip/keys/device-ca.key
//	    Ed25519 seed on disk (base64 or 32 raw bytes). Created 0600 on first
//	    use; refused if group- or world-accessible.
//	env:TOKEN_SIGNING_KEY
//	    base64 32-byte Ed25519 seed in an environment variable.
//	pkcs11:token=shaip;object=device-ca?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-env=SHAIP_HSM_PIN
//	    Key held inside a PKCS#11 token (an HSM); the private key never leaves
//	    the device. RFC 7512 style. Add &create=1 to generate a non-extractable
//	    keypair on the token if no key with that label exists. Requires a cgo
//	    build (see pkcs11.go).
//	ephemeral
//	    A fresh in-memory key (dev and tests only; lost on restart).
//
// Every key is Ed25519 (RFC 8032, pure). Sign wraps crypto.Signer.Sign with the
// right options and verifies each signature against the signer's public key
// before returning it, so a misconfigured backend (wrong curve, a prehash mode)
// fails loudly instead of emitting signatures nobody can verify.
package keystore

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Open resolves a key spec to an Ed25519 crypto.Signer.
func Open(spec string) (crypto.Signer, error) {
	switch {
	case spec == "ephemeral":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case strings.HasPrefix(spec, "file:"):
		return openFile(strings.TrimPrefix(spec, "file:"))
	case strings.HasPrefix(spec, "env:"):
		return openEnv(strings.TrimPrefix(spec, "env:"))
	case strings.HasPrefix(spec, "pkcs11:"):
		cfg, err := parsePKCS11(spec)
		if err != nil {
			return nil, err
		}
		return openPKCS11(cfg)
	default:
		return nil, fmt.Errorf("unknown key spec %q (want file:, env:, pkcs11:, or ephemeral)", Describe(spec))
	}
}

// Describe returns a spec safe to log: a PKCS#11 pin-value is redacted.
func Describe(spec string) string {
	if !strings.HasPrefix(spec, "pkcs11:") {
		return spec
	}
	u, err := url.Parse(spec)
	if err != nil {
		return "pkcs11:<unparseable>"
	}
	q := u.Query()
	if q.Has("pin-value") {
		q.Set("pin-value", "REDACTED")
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// Ed25519Public returns the signer's Ed25519 public key.
func Ed25519Public(s crypto.Signer) (ed25519.PublicKey, error) {
	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signer is not Ed25519 (public key %T)", s.Public())
	}
	return pub, nil
}

// Sign produces a pure Ed25519 signature over msg and verifies it before
// returning it.
func Sign(s crypto.Signer, msg []byte) ([]byte, error) {
	pub, err := Ed25519Public(s)
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return nil, errors.New("keystore: backend produced an Ed25519 signature that does not verify")
	}
	return sig, nil
}

// ---- file ---------------------------------------------------------------------

func openFile(path string) (crypto.Signer, error) {
	if path == "" {
		return nil, errors.New("file: key spec needs a path")
	}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return createFile(path)
	}
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has permissions %04o; a private key must be 0600 (chmod 600 it)", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := decodeSeed(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// createFile generates a seed and writes it with O_EXCL so two processes racing
// on first boot cannot both create (and one silently lose) the key.
func createFile(path string) (crypto.Signer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return openFile(path) // lost the race: use the winner's key
		}
		return nil, err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// decodeSeed accepts base64 text (as written by createFile or
// `openssl rand -base64 32`) or exactly 32 raw bytes. The two cannot collide:
// 32 bytes of base64 text decode to 24 bytes, never 32.
func decodeSeed(raw []byte) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil && len(b) == ed25519.SeedSize {
		return b, nil
	}
	if len(raw) == ed25519.SeedSize {
		return raw, nil
	}
	return nil, fmt.Errorf("key must be a %d-byte Ed25519 seed (raw or base64)", ed25519.SeedSize)
}

// ---- env ----------------------------------------------------------------------

func openEnv(name string) (crypto.Signer, error) {
	v := os.Getenv(name)
	if v == "" {
		return nil, fmt.Errorf("environment variable %s is empty", name)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s must be base64 of a %d-byte seed", name, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ---- pkcs11 spec ----------------------------------------------------------------

// pkcs11Config is a parsed pkcs11: spec.
type pkcs11Config struct {
	Module string // module-path
	Token  string // token label
	Object string // key label (CKA_LABEL)
	PIN    string
	Create bool
}

func parsePKCS11(spec string) (pkcs11Config, error) {
	var cfg pkcs11Config
	u, err := url.Parse(spec)
	if err != nil || u.Scheme != "pkcs11" {
		return cfg, errors.New("malformed pkcs11: spec")
	}
	for _, attr := range strings.Split(u.Opaque, ";") {
		if attr == "" {
			continue
		}
		k, v, ok := strings.Cut(attr, "=")
		if !ok {
			return cfg, fmt.Errorf("pkcs11: bad attribute %q", attr)
		}
		v, err := url.PathUnescape(v)
		if err != nil {
			return cfg, fmt.Errorf("pkcs11: bad escaping in %q", k)
		}
		switch k {
		case "token":
			cfg.Token = v
		case "object":
			cfg.Object = v
		default:
			return cfg, fmt.Errorf("pkcs11: unsupported attribute %q", k)
		}
	}
	q := u.Query()
	cfg.Module = q.Get("module-path")
	cfg.Create = q.Get("create") == "1"
	switch {
	case q.Get("pin-env") != "":
		cfg.PIN = os.Getenv(q.Get("pin-env"))
		if cfg.PIN == "" {
			return cfg, fmt.Errorf("pkcs11: PIN variable %s is empty", q.Get("pin-env"))
		}
	case q.Has("pin-value"):
		cfg.PIN = q.Get("pin-value")
	}
	if cfg.Module == "" || cfg.Token == "" || cfg.Object == "" {
		return cfg, errors.New("pkcs11: spec needs token=, object=, and module-path=")
	}
	if cfg.PIN == "" {
		return cfg, errors.New("pkcs11: spec needs pin-env= (or pin-value=)")
	}
	return cfg, nil
}
