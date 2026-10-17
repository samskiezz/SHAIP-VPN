//go:build cgo

package keystore

// PKCS#11 (HSM) backend. The private key lives inside the token and is marked
// sensitive and non-extractable; this process only ever asks the token to sign.
// Ed25519 uses the PKCS#11 3.0 Edwards mechanisms, which SoftHSM2 (>= 2.6) and
// current network HSMs implement.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// PKCS#11 3.0 constants for Edwards curves. miekg/pkcs11 v1.1.1 predates 3.0,
// so they are defined here with their OASIS values.
const (
	ckkECEdwards           = 0x00000040 // CKK_EC_EDWARDS
	ckmECEdwardsKeyPairGen = 0x00001055 // CKM_EC_EDWARDS_KEY_PAIR_GEN
	ckmEdDSA               = 0x00001057 // CKM_EDDSA
)

// DER encoding of the id-Ed25519 OID (1.3.101.112), the CKA_EC_PARAMS that
// selects Ed25519 for an Edwards key.
var ed25519ECParams = []byte{0x06, 0x03, 0x2b, 0x65, 0x70}

// selfTestMessage is signed once at open time to prove the token's signatures
// verify as pure Ed25519 before any real artifact is signed.
var selfTestMessage = []byte("SHAIP-KEYSTORE-SELFTEST-V1")

// A process loads each PKCS#11 module once: C_Initialize is process-global, so
// signers sharing a module share one context, which is never finalized.
var (
	modulesMu sync.Mutex
	modules   = map[string]*pkcs11.Ctx{}
)

func moduleCtx(path string) (*pkcs11.Ctx, error) {
	modulesMu.Lock()
	defer modulesMu.Unlock()
	if ctx, ok := modules[path]; ok {
		return ctx, nil
	}
	ctx := pkcs11.New(path)
	if ctx == nil {
		return nil, fmt.Errorf("pkcs11: cannot load module %s", path)
	}
	if err := ctx.Initialize(); err != nil && !isCKR(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		ctx.Destroy()
		return nil, fmt.Errorf("pkcs11: C_Initialize: %w", err)
	}
	modules[path] = ctx
	return ctx, nil
}

func isCKR(err error, code uint) bool {
	var e pkcs11.Error
	return errors.As(err, &e) && uint(e) == code
}

// pkcs11Signer is a crypto.Signer backed by a key on a PKCS#11 token.
type pkcs11Signer struct {
	mu      sync.Mutex // a session runs one operation at a time
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	key     pkcs11.ObjectHandle
	pub     ed25519.PublicKey
}

func openPKCS11(cfg pkcs11Config) (crypto.Signer, error) {
	ctx, err := moduleCtx(cfg.Module)
	if err != nil {
		return nil, err
	}
	slot, err := findSlot(ctx, cfg.Token)
	if err != nil {
		return nil, err
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: open session: %w", err)
	}
	// Login state is per token for the whole application, so a second signer on
	// the same token finds it already logged in.
	if err := ctx.Login(session, pkcs11.CKU_USER, cfg.PIN); err != nil && !isCKR(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		ctx.CloseSession(session)
		return nil, fmt.Errorf("pkcs11: login to token %q: %w", cfg.Token, err)
	}

	priv, privFound, err := findKey(ctx, session, pkcs11.CKO_PRIVATE_KEY, cfg.Object)
	if err != nil {
		ctx.CloseSession(session)
		return nil, err
	}
	pubObj, pubFound, err := findKey(ctx, session, pkcs11.CKO_PUBLIC_KEY, cfg.Object)
	if err != nil {
		ctx.CloseSession(session)
		return nil, err
	}
	switch {
	case !privFound && !pubFound && cfg.Create:
		pubObj, priv, err = generateEd25519(ctx, session, cfg.Object)
		if err != nil {
			ctx.CloseSession(session)
			return nil, err
		}
	case !privFound || !pubFound:
		ctx.CloseSession(session)
		return nil, fmt.Errorf("pkcs11: token %q has no complete Ed25519 keypair labelled %q (add &create=1 to generate one)", cfg.Token, cfg.Object)
	}

	pub, err := readEdwardsPoint(ctx, session, pubObj)
	if err != nil {
		ctx.CloseSession(session)
		return nil, err
	}
	s := &pkcs11Signer{ctx: ctx, session: session, key: priv, pub: pub}
	if _, err := Sign(s, selfTestMessage); err != nil {
		ctx.CloseSession(session)
		return nil, fmt.Errorf("pkcs11: self-test signature for %q failed: %w", cfg.Object, err)
	}
	return s, nil
}

func findSlot(ctx *pkcs11.Ctx, label string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: list slots: %w", err)
	}
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		// Token labels are fixed-width, space-padded fields.
		if strings.TrimRight(info.Label, " \x00") == label {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: no token labelled %q", label)
}

func findKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, label string) (pkcs11.ObjectHandle, bool, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, ckkECEdwards),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, false, fmt.Errorf("pkcs11: find objects: %w", err)
	}
	objs, _, err := ctx.FindObjects(session, 2)
	if ferr := ctx.FindObjectsFinal(session); err == nil {
		err = ferr
	}
	if err != nil {
		return 0, false, fmt.Errorf("pkcs11: find objects: %w", err)
	}
	switch len(objs) {
	case 0:
		return 0, false, nil
	case 1:
		return objs[0], true, nil
	default:
		return 0, false, fmt.Errorf("pkcs11: more than one key labelled %q; labels must be unique", label)
	}
}

// generateEd25519 creates a token-resident Ed25519 keypair. The private half is
// sensitive and non-extractable: it can sign, and nothing can read it out.
func generateEd25519(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, pkcs11.ObjectHandle, error) {
	id := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return 0, 0, err
	}
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ed25519ECParams),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmECEdwardsKeyPairGen, nil)}
	pub, priv, err := ctx.GenerateKeyPair(session, mech, pubTmpl, privTmpl)
	if err != nil {
		return 0, 0, fmt.Errorf("pkcs11: generate Ed25519 keypair %q: %w", label, err)
	}
	return pub, priv, nil
}

// readEdwardsPoint reads CKA_EC_POINT, which tokens return as a DER OCTET STRING
// wrapping the 32-byte point (some return the bare point).
func readEdwardsPoint(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) (ed25519.PublicKey, error) {
	attrs, err := ctx.GetAttributeValue(session, obj, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	})
	if err != nil || len(attrs) != 1 {
		return nil, fmt.Errorf("pkcs11: read public point: %v", err)
	}
	v := attrs[0].Value
	switch {
	case len(v) == ed25519.PublicKeySize+2 && v[0] == 0x04 && v[1] == ed25519.PublicKeySize:
		return ed25519.PublicKey(append([]byte(nil), v[2:]...)), nil
	case len(v) == ed25519.PublicKeySize:
		return ed25519.PublicKey(append([]byte(nil), v...)), nil
	default:
		return nil, fmt.Errorf("pkcs11: unexpected Ed25519 public point encoding (%d bytes)", len(v))
	}
}

func (s *pkcs11Signer) Public() crypto.PublicKey { return s.pub }

// Sign implements crypto.Signer for pure Ed25519: opts must not name a hash, and
// msg is the whole message (the token hashes it internally, as RFC 8032 does).
func (s *pkcs11Signer) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("pkcs11: only pure Ed25519 is supported (opts must not name a hash)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckmEdDSA, nil)}
	if err := s.ctx.SignInit(s.session, mech, s.key); err != nil {
		return nil, fmt.Errorf("pkcs11: C_SignInit: %w", err)
	}
	sig, err := s.ctx.Sign(s.session, msg)
	if err != nil {
		return nil, fmt.Errorf("pkcs11: C_Sign: %w", err)
	}
	return sig, nil
}
