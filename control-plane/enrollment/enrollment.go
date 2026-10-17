// Package enrollment implements the SHAIP one-click device-enrollment crypto:
// a compact, signed enrollment token and a signed device certificate.
//
// An operator issues an enrollment token (authorizing one device to join an
// account) and hands it to the device out of band — a QR code or a
// `shaip://enroll?t=...` deep link. The device verifies that token against a
// pinned enrollment-authority key, generates its own identity keypair, and
// presents the public half; the control plane then issues a device certificate
// binding that public key to the account, signed by a device-CA key the servers
// pin. Later, a server verifies the presented certificate before admitting the
// device.
//
// Both artifacts use the same shape: a fully deterministic, length-prefixed
// binary body carrying a domain-separation magic, signed directly with Ed25519
// (RFC 8032, pure — the body is the message), and wrapped as
//
//	<label>.<base64url(body)>.<base64url(sig)>
//
// base64url is unpadded (URL/QR safe). The format is specified byte-for-byte so
// the Rust verifier (client/src/enrollment.rs) decodes the identical bytes and a
// signature produced here verifies there unchanged. The `TestCrossLanguageVector`
// test pins a token and a certificate the Rust side re-verifies.
package enrollment

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Wire labels (the first dot-separated field). They route parsing; the
// security-relevant domain separation is the magic inside the signed body.
const (
	LabelEnroll = "PQE1" // SHAIP enrollment token, v1
	LabelCert   = "PQC1" // SHAIP device certificate, v1
)

// Domain-separation magics, carried inside the signed body so a signature over
// one artifact type can never be reinterpreted as the other even if the outer
// label is swapped.
const (
	magicEnroll = "SHAIP-ENROLL-V1"
	magicCert   = "SHAIP-DEVCERT-V1"
)

// Version is the body format version.
const Version = 1

// MaxClockSkew is how far a verifier tolerates its own clock being behind the
// issuer's when checking the not-yet-valid boundary. Expiry is strict.
const MaxClockSkew = 2 * time.Minute

var b64 = base64.RawURLEncoding

// EnrollClaims is what an enrollment token asserts.
type EnrollClaims struct {
	TokenID   [16]byte // unique per issuance (replay/one-time tracking key)
	Account   string   // the account the device is being added to
	IssuedAt  time.Time
	ExpiresAt time.Time
	OneTime   bool // advisory: the control plane should accept it at most once
}

// WithheldAccount is the account field of every device certificate the control
// plane issues. A tunnel server admits a device because its key is certified
// and not revoked; it never needs to know whose device it is, and if the field
// named the account, any server (staked nodes are run by third parties) could
// link one customer's devices to each other. The field stays in the v1 format
// so certificates issued before this keep verifying.
const WithheldAccount = "-"

// CertClaims is what a device certificate binds.
type CertClaims struct {
	DeviceID  [16]byte
	Account   string            // WithheldAccount in certificates the control plane issues
	DevicePub ed25519.PublicKey // the device's own identity public key (32 bytes)
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// ---- deterministic body encoding --------------------------------------------

type writer struct{ b []byte }

func (w *writer) u8(v byte)    { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *writer) raw(p []byte) { w.b = append(w.b, p...) }
func (w *writer) lp(p []byte)  { w.u16(uint16(len(p))); w.raw(p) } // length-prefixed
func (w *writer) str(s string) { w.lp([]byte(s)) }

type reader struct {
	b   []byte
	off int
}

var errTruncated = errors.New("truncated body")

func (r *reader) need(n int) ([]byte, error) {
	if r.off+n > len(r.b) {
		return nil, errTruncated
	}
	p := r.b[r.off : r.off+n]
	r.off += n
	return p, nil
}
func (r *reader) u8() (byte, error) {
	p, err := r.need(1)
	if err != nil {
		return 0, err
	}
	return p[0], nil
}
func (r *reader) u16() (uint16, error) {
	p, err := r.need(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(p), nil
}
func (r *reader) u64() (uint64, error) {
	p, err := r.need(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(p), nil
}
func (r *reader) lp() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	return r.need(int(n))
}

func encodeEnrollBody(c EnrollClaims) []byte {
	w := &writer{}
	w.str(magicEnroll)
	w.u8(Version)
	w.raw(c.TokenID[:])
	w.str(c.Account)
	w.u64(uint64(c.IssuedAt.UTC().Unix()))
	w.u64(uint64(c.ExpiresAt.UTC().Unix()))
	var flags byte
	if c.OneTime {
		flags |= 0x01
	}
	w.u8(flags)
	return w.b
}

func encodeCertBody(c CertClaims) []byte {
	w := &writer{}
	w.str(magicCert)
	w.u8(Version)
	w.raw(c.DeviceID[:])
	w.str(c.Account)
	w.raw(c.DevicePub)
	w.u64(uint64(c.IssuedAt.UTC().Unix()))
	w.u64(uint64(c.ExpiresAt.UTC().Unix()))
	return w.b
}

// ---- issue ------------------------------------------------------------------

func wrap(label string, body, sig []byte) string {
	return label + "." + b64.EncodeToString(body) + "." + b64.EncodeToString(sig)
}

// IssueEnrollToken signs an enrollment token with the enrollment-authority key.
//
// The authority is any crypto.Signer holding an Ed25519 key — an in-memory key
// or one inside an HSM (see the keystore package).
func IssueEnrollToken(authority crypto.Signer, c EnrollClaims) (string, error) {
	if len(c.Account) == 0 || len(c.Account) > 255 {
		return "", fmt.Errorf("account length %d out of range", len(c.Account))
	}
	body := encodeEnrollBody(c)
	sig, err := sign(authority, body)
	if err != nil {
		return "", err
	}
	return wrap(LabelEnroll, body, sig), nil
}

// IssueDeviceCert signs a device certificate with the device-CA key.
func IssueDeviceCert(ca crypto.Signer, c CertClaims) (string, error) {
	if len(c.DevicePub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("device public key must be %d bytes", ed25519.PublicKeySize)
	}
	if len(c.Account) == 0 || len(c.Account) > 255 {
		return "", fmt.Errorf("account length %d out of range", len(c.Account))
	}
	body := encodeCertBody(c)
	sig, err := sign(ca, body)
	if err != nil {
		return "", err
	}
	return wrap(LabelCert, body, sig), nil
}

// sign makes a pure Ed25519 signature with any crypto.Signer and verifies it
// before use, so a misconfigured backend cannot mint artifacts nobody accepts.
func sign(s crypto.Signer, body []byte) ([]byte, error) {
	pub, ok := s.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signer is not Ed25519 (%T)", s.Public())
	}
	sig, err := s.Sign(rand.Reader, body, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, body, sig) {
		return nil, errors.New("signer produced a signature that does not verify")
	}
	return sig, nil
}

// ---- verify -----------------------------------------------------------------

// ErrFormat and friends let callers distinguish why verification failed.
var (
	ErrFormat    = errors.New("malformed token")
	ErrMagic     = errors.New("wrong artifact type")
	ErrVersion   = errors.New("unsupported version")
	ErrSignature = errors.New("signature does not verify")
	ErrNotYetVal = errors.New("not yet valid")
	ErrExpired   = errors.New("expired")
)

func unwrap(label, s string) (body, sig []byte, err error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] != label {
		return nil, nil, ErrFormat
	}
	body, err = b64.DecodeString(parts[1])
	if err != nil {
		return nil, nil, ErrFormat
	}
	sig, err = b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, nil, ErrFormat
	}
	return body, sig, nil
}

func checkWindow(now, issued, expires time.Time) error {
	if now.Add(MaxClockSkew).Before(issued) {
		return ErrNotYetVal
	}
	if now.After(expires) {
		return ErrExpired
	}
	return nil
}

// VerifyEnrollToken verifies a token against a pinned authority public key and
// returns its claims. It checks the signature first, then the validity window.
func VerifyEnrollToken(authority ed25519.PublicKey, token string, now time.Time) (EnrollClaims, error) {
	var out EnrollClaims
	body, sig, err := unwrap(LabelEnroll, token)
	if err != nil {
		return out, err
	}
	if !ed25519.Verify(authority, body, sig) {
		return out, ErrSignature
	}
	r := &reader{b: body}
	magic, err := r.lp()
	if err != nil {
		return out, ErrFormat
	}
	if string(magic) != magicEnroll {
		return out, ErrMagic
	}
	ver, err := r.u8()
	if err != nil {
		return out, ErrFormat
	}
	if ver != Version {
		return out, ErrVersion
	}
	tid, err := r.need(16)
	if err != nil {
		return out, ErrFormat
	}
	copy(out.TokenID[:], tid)
	acct, err := r.lp()
	if err != nil {
		return out, ErrFormat
	}
	out.Account = string(acct)
	issued, err := r.u64()
	if err != nil {
		return out, ErrFormat
	}
	expires, err := r.u64()
	if err != nil {
		return out, ErrFormat
	}
	flags, err := r.u8()
	if err != nil {
		return out, ErrFormat
	}
	if r.off != len(r.b) {
		return out, ErrFormat // trailing garbage
	}
	out.IssuedAt = time.Unix(int64(issued), 0).UTC()
	out.ExpiresAt = time.Unix(int64(expires), 0).UTC()
	out.OneTime = flags&0x01 != 0
	if err := checkWindow(now, out.IssuedAt, out.ExpiresAt); err != nil {
		return out, err
	}
	return out, nil
}

// VerifyDeviceCert verifies a certificate against a pinned device-CA public key
// and returns its claims.
func VerifyDeviceCert(ca ed25519.PublicKey, cert string, now time.Time) (CertClaims, error) {
	var out CertClaims
	body, sig, err := unwrap(LabelCert, cert)
	if err != nil {
		return out, err
	}
	if !ed25519.Verify(ca, body, sig) {
		return out, ErrSignature
	}
	r := &reader{b: body}
	magic, err := r.lp()
	if err != nil {
		return out, ErrFormat
	}
	if string(magic) != magicCert {
		return out, ErrMagic
	}
	ver, err := r.u8()
	if err != nil {
		return out, ErrFormat
	}
	if ver != Version {
		return out, ErrVersion
	}
	did, err := r.need(16)
	if err != nil {
		return out, ErrFormat
	}
	copy(out.DeviceID[:], did)
	acct, err := r.lp()
	if err != nil {
		return out, ErrFormat
	}
	out.Account = string(acct)
	pub, err := r.need(ed25519.PublicKeySize)
	if err != nil {
		return out, ErrFormat
	}
	out.DevicePub = append(ed25519.PublicKey(nil), pub...)
	issued, err := r.u64()
	if err != nil {
		return out, ErrFormat
	}
	expires, err := r.u64()
	if err != nil {
		return out, ErrFormat
	}
	if r.off != len(r.b) {
		return out, ErrFormat
	}
	out.IssuedAt = time.Unix(int64(issued), 0).UTC()
	out.ExpiresAt = time.Unix(int64(expires), 0).UTC()
	if err := checkWindow(now, out.IssuedAt, out.ExpiresAt); err != nil {
		return out, err
	}
	return out, nil
}

// EnrollURL wraps a token in the deep-link form handed to a device.
func EnrollURL(token string) string {
	return "shaip://enroll?t=" + token + "&v=1"
}
