// Package staking implements the cryptographic core of node staking: signed
// node descriptors, equivocation evidence, and the slash arithmetic.
//
// Each epoch a node publishes one descriptor — its address and keys — signed
// with its Ed25519 node key. Publishing two *different* descriptors for the
// same epoch is equivocation: it lets a node show different keys or addresses
// to different clients, the partitioning attack a directory exists to prevent.
// Two such descriptors, both verifying under the node's registered key, are
// self-contained proof, so anyone may submit them and the node is slashed
// without trusting the reporter. An honest node re-publishing an identical
// descriptor is not equivocation.
//
// The descriptor is a deterministic, length-prefixed binary body signed with
// pure Ed25519, wrapped as `PQD1.<base64url(body)>.<base64url(sig)>`. The body
// begins with a length-prefixed domain magic, so it can never coincide with a
// SHAIP-HS/1 transcript (which starts with a 4-byte ML-KEM key length) or an
// enrollment proof — the same node key signs all three. The format matches the
// Rust signer (client/src/descriptor.rs) byte-for-byte; TestCrossLanguageVector
// pins it.
package staking

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Label is the descriptor wire label.
const Label = "PQD1"

const (
	magic   = "SHAIP-NODEDESC-V1"
	version = 1
)

var b64 = base64.RawURLEncoding

// Descriptor is what a node asserts about itself for one epoch.
type Descriptor struct {
	NodeID       string // the control plane's id for the node
	Epoch        uint64
	Address      string
	X25519       [32]byte // mix onion key (zero if the node has none)
	Ed25519      [32]byte // the node key that signs this descriptor
	CapacityMbps uint32
	Region       string
}

func (d Descriptor) body() []byte {
	var b []byte
	lp := func(p []byte) {
		b = binary.BigEndian.AppendUint16(b, uint16(len(p)))
		b = append(b, p...)
	}
	lp([]byte(magic))
	b = append(b, version)
	lp([]byte(d.NodeID))
	b = binary.BigEndian.AppendUint64(b, d.Epoch)
	lp([]byte(d.Address))
	b = append(b, d.X25519[:]...)
	b = append(b, d.Ed25519[:]...)
	b = binary.BigEndian.AppendUint32(b, d.CapacityMbps)
	lp([]byte(d.Region))
	return b
}

// Sign produces the wire descriptor. The signer must hold d.Ed25519.
func Sign(key crypto.Signer, d Descriptor) (string, error) {
	pub, ok := key.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, d.Ed25519[:]) {
		return "", errors.New("staking: signer does not hold the descriptor's Ed25519 key")
	}
	for _, s := range []string{d.NodeID, d.Address, d.Region} {
		if len(s) > 255 {
			return "", errors.New("staking: descriptor field too long")
		}
	}
	body := d.body()
	sig, err := key.Sign(rand.Reader, body, crypto.Hash(0))
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, body, sig) {
		return "", errors.New("staking: signer produced a signature that does not verify")
	}
	return Label + "." + b64.EncodeToString(body) + "." + b64.EncodeToString(sig), nil
}

// Errors returned by Parse and CheckEquivocation.
var (
	ErrFormat     = errors.New("malformed descriptor")
	ErrSignature  = errors.New("descriptor signature does not verify under the node key")
	ErrNoConflict = errors.New("descriptors do not conflict")
)

// Parse decodes a wire descriptor and verifies it under nodeKey, which must be
// the key the control plane has registered for the node (never the key the
// descriptor itself names).
func Parse(s string, nodeKey ed25519.PublicKey) (Descriptor, []byte, error) {
	var d Descriptor
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] != Label {
		return d, nil, ErrFormat
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return d, nil, ErrFormat
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize || len(nodeKey) != ed25519.PublicKeySize {
		return d, nil, ErrFormat
	}
	if !ed25519.Verify(nodeKey, body, sig) {
		return d, nil, ErrSignature
	}
	r := reader{b: body}
	if string(r.lp()) != magic || r.u8() != version {
		return d, nil, ErrFormat
	}
	d.NodeID = string(r.lp())
	d.Epoch = r.u64()
	d.Address = string(r.lp())
	copy(d.X25519[:], r.n(32))
	copy(d.Ed25519[:], r.n(32))
	d.CapacityMbps = r.u32()
	d.Region = string(r.lp())
	if r.err || r.off != len(body) {
		return d, nil, ErrFormat
	}
	if !bytes.Equal(d.Ed25519[:], nodeKey) {
		return d, nil, fmt.Errorf("%w: descriptor names a different node key", ErrFormat)
	}
	return d, body, nil
}

// PeekNodeID reads the node id a descriptor claims, WITHOUT verifying it. It
// exists only to look up which registered key to verify against; nothing else
// may trust its result.
func PeekNodeID(s string) (string, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 || parts[0] != Label {
		return "", ErrFormat
	}
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		return "", ErrFormat
	}
	r := reader{b: body}
	if string(r.lp()) != magic || r.u8() != version {
		return "", ErrFormat
	}
	id := string(r.lp())
	if r.err {
		return "", ErrFormat
	}
	return id, nil
}

// CheckEquivocation verifies a slashing claim: both descriptors verify under
// the node's registered key, name the same node and epoch, and differ. It
// returns that epoch.
func CheckEquivocation(nodeID string, nodeKey ed25519.PublicKey, a, b string) (uint64, error) {
	da, ba, err := Parse(a, nodeKey)
	if err != nil {
		return 0, fmt.Errorf("first descriptor: %w", err)
	}
	db, bb, err := Parse(b, nodeKey)
	if err != nil {
		return 0, fmt.Errorf("second descriptor: %w", err)
	}
	if da.NodeID != nodeID || db.NodeID != nodeID {
		return 0, fmt.Errorf("%w: descriptors are for another node", ErrNoConflict)
	}
	if da.Epoch != db.Epoch {
		return 0, fmt.Errorf("%w: different epochs (%d, %d)", ErrNoConflict, da.Epoch, db.Epoch)
	}
	if bytes.Equal(ba, bb) {
		return 0, fmt.Errorf("%w: identical descriptors are a re-publication, not equivocation", ErrNoConflict)
	}
	return da.Epoch, nil
}

// SlashCut is the amount a slash of percent removes from amount (floor).
func SlashCut(amount int64, percent int) int64 {
	if amount <= 0 || percent <= 0 {
		return 0
	}
	if percent >= 100 {
		return amount
	}
	return amount * int64(percent) / 100
}

type reader struct {
	b   []byte
	off int
	err bool
}

func (r *reader) n(k int) []byte {
	if r.err || r.off+k > len(r.b) {
		r.err = true
		return make([]byte, k)
	}
	p := r.b[r.off : r.off+k]
	r.off += k
	return p
}
func (r *reader) u8() byte    { return r.n(1)[0] }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.n(4)) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.n(8)) }
func (r *reader) lp() []byte  { return r.n(int(binary.BigEndian.Uint16(r.n(2)))) }
