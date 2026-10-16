// Package directory implements the PQANON directory consensus: a signed,
// plain-text list of the active nodes, published by a set of independent
// authorities. Clients accept the document only when at least `Threshold` of
// the known authorities have signed the exact canonical bytes.
//
// The format is deliberately plain ASCII with a fully specified canonical form
// so an independent implementation (the Rust client in `client/src/directory.rs`)
// produces byte-identical bytes and the same SHA-256 digest, and so a signature
// made here verifies there. Signatures are Ed25519 (RFC 8032) over the 32-byte
// SHA-256 digest of the canonical form.
package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// FormatVersion is the required first line of every consensus document.
const FormatVersion = "PQANON-CONSENSUS-V1"

// MaxClockSkew is how far before `Published` a verifier tolerates its own clock
// being behind.
const MaxClockSkew = 15 * time.Minute

// Authority is an entity permitted to sign the consensus.
type Authority struct {
	Name   string
	KeyTag uint16
	PubKey ed25519.PublicKey // nil until attached by the verifier
}

// Node is one node in the consensus. Every field participates in the canonical
// form, so every field is covered by the signatures.
type Node struct {
	Name         string
	Address      string
	Role         string // "mix", "entry", "exit", "gateway"
	X25519Hex    string
	Ed25519Hex   string
	CapacityMbps int
	Region       string
}

// Document is a consensus plus the signatures collected for it.
type Document struct {
	Published   time.Time
	ValidUntil  time.Time
	Threshold   int
	Authorities []Authority
	Nodes       []Node
	Signatures  map[string][]byte // authority name -> raw Ed25519 signature
}

// Canonical returns the exact bytes that are signed: a fully deterministic
// plain-text form with authorities and nodes sorted by name. It never includes
// the signature lines.
func (d *Document) Canonical() []byte {
	var b bytes.Buffer
	b.WriteString(FormatVersion)
	b.WriteByte('\n')
	fmt.Fprintf(&b, "published %s\n", d.Published.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "valid-until %s\n", d.ValidUntil.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "threshold %d/%d\n", d.Threshold, len(d.Authorities))
	fmt.Fprintf(&b, "authorities %d\n", len(d.Authorities))

	auths := append([]Authority(nil), d.Authorities...)
	sort.Slice(auths, func(i, j int) bool { return auths[i].Name < auths[j].Name })
	for _, a := range auths {
		fmt.Fprintf(&b, "authority-name %s key-tag 0x%04x\n", a.Name, a.KeyTag)
	}
	b.WriteByte('\n')

	nodes := append([]Node(nil), d.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	for _, n := range nodes {
		fmt.Fprintf(&b, "node %s addr %s role %s\n", n.Name, n.Address, n.Role)
		fmt.Fprintf(&b, "    x25519 %s\n", n.X25519Hex)
		fmt.Fprintf(&b, "    ed25519 %s\n", n.Ed25519Hex)
		fmt.Fprintf(&b, "    capacity-mbps %d\n", n.CapacityMbps)
		fmt.Fprintf(&b, "    region %s\n", n.Region)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Digest is the SHA-256 of the canonical form — the message the authorities
// sign.
func (d *Document) Digest() [32]byte {
	return sha256.Sum256(d.Canonical())
}

// Sign adds this authority's Ed25519 signature over the digest. The authority
// must be listed in the document.
func (d *Document) Sign(authorityName string, priv ed25519.PrivateKey) error {
	known := false
	for _, a := range d.Authorities {
		if a.Name == authorityName {
			known = true
			break
		}
	}
	if !known {
		return fmt.Errorf("unknown authority: %s", authorityName)
	}
	if d.Signatures == nil {
		d.Signatures = make(map[string][]byte)
	}
	digest := d.Digest()
	d.Signatures[authorityName] = ed25519.Sign(priv, digest[:])
	return nil
}

// Verify checks the document is within its validity window and carries at least
// `Threshold` valid signatures from distinct listed authorities. Every present
// signature must verify (a single bad signature is a hard failure, so a forged
// document cannot pad its way to the threshold with garbage).
func (d *Document) Verify(now time.Time) error {
	if now.Add(MaxClockSkew).Before(d.Published) {
		return fmt.Errorf("document not yet valid (published %s)", d.Published.UTC().Format(time.RFC3339))
	}
	if now.After(d.ValidUntil) {
		return fmt.Errorf("document expired at %s", d.ValidUntil.UTC().Format(time.RFC3339))
	}
	digest := d.Digest()
	valid := 0
	for _, a := range d.Authorities {
		sig, ok := d.Signatures[a.Name]
		if !ok {
			continue
		}
		if a.PubKey == nil {
			return fmt.Errorf("no public key attached for authority %s", a.Name)
		}
		if !ed25519.Verify(a.PubKey, digest[:], sig) {
			return fmt.Errorf("signature from %s is invalid", a.Name)
		}
		valid++
	}
	if valid < d.Threshold {
		return fmt.Errorf("only %d valid signatures, need %d", valid, d.Threshold)
	}
	return nil
}

// Encode returns the wire document: the canonical form followed by the
// signature lines, sorted by authority name.
func (d *Document) Encode() []byte {
	var b bytes.Buffer
	b.Write(d.Canonical())
	names := make([]string, 0, len(d.Signatures))
	for n := range d.Signatures {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "signature %s %s\n", n, hex.EncodeToString(d.Signatures[n]))
	}
	return b.Bytes()
}

// Decode parses a wire document. Authority public keys are not resolved here;
// the caller attaches them from a pinned registry before calling Verify.
func Decode(data []byte) (*Document, error) {
	d := &Document{Signatures: map[string][]byte{}}
	var current *Node
	inSig := false

	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "signature ") {
			inSig = true
			parts := strings.Fields(line)
			if len(parts) != 3 {
				return nil, fmt.Errorf("line %d: bad signature line", i+1)
			}
			sig, err := hex.DecodeString(parts[2])
			if err != nil {
				return nil, fmt.Errorf("line %d: bad signature hex: %w", i+1, err)
			}
			d.Signatures[parts[1]] = sig
			continue
		}
		if inSig {
			return nil, fmt.Errorf("line %d: content after signature block", i+1)
		}
		if i == 0 {
			if line != FormatVersion {
				return nil, fmt.Errorf("bad version line: %q", line)
			}
			continue
		}
		if strings.HasPrefix(raw, "    ") {
			if current == nil {
				return nil, fmt.Errorf("line %d: indented field outside a node", i+1)
			}
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return nil, fmt.Errorf("line %d: short node field", i+1)
			}
			if err := applyNodeField(current, parts); err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			continue
		}
		parts := strings.Fields(line)
		current = nil
		switch parts[0] {
		case "published", "valid-until":
			if len(parts) < 2 {
				return nil, fmt.Errorf("line %d: missing timestamp", i+1)
			}
			t, err := time.Parse(time.RFC3339, parts[1])
			if err != nil {
				return nil, fmt.Errorf("line %d: bad time: %w", i+1, err)
			}
			if parts[0] == "published" {
				d.Published = t
			} else {
				d.ValidUntil = t
			}
		case "threshold":
			if len(parts) < 2 {
				return nil, fmt.Errorf("line %d: missing threshold", i+1)
			}
			if _, err := fmt.Sscanf(parts[1], "%d", &d.Threshold); err != nil {
				return nil, fmt.Errorf("line %d: bad threshold: %w", i+1, err)
			}
		case "authorities":
			// Count is derived from the authority-name lines; ignore the value.
		case "authority-name":
			if len(parts) < 4 {
				return nil, fmt.Errorf("line %d: short authority line", i+1)
			}
			var tag uint16
			if _, err := fmt.Sscanf(parts[3], "0x%04x", &tag); err != nil {
				return nil, fmt.Errorf("line %d: bad key-tag: %w", i+1, err)
			}
			d.Authorities = append(d.Authorities, Authority{Name: parts[1], KeyTag: tag})
		case "node":
			if len(parts) < 6 {
				return nil, fmt.Errorf("line %d: short node line", i+1)
			}
			d.Nodes = append(d.Nodes, Node{Name: parts[1], Address: parts[3], Role: parts[5]})
			current = &d.Nodes[len(d.Nodes)-1]
		default:
			return nil, fmt.Errorf("line %d: unknown directive %q", i+1, parts[0])
		}
	}
	return d, nil
}

func applyNodeField(n *Node, parts []string) error {
	val := strings.Join(parts[1:], " ")
	switch parts[0] {
	case "x25519":
		n.X25519Hex = val
	case "ed25519":
		n.Ed25519Hex = val
	case "capacity-mbps":
		if _, err := fmt.Sscanf(val, "%d", &n.CapacityMbps); err != nil {
			return fmt.Errorf("bad capacity-mbps: %w", err)
		}
	case "region":
		n.Region = val
	default:
		return fmt.Errorf("unknown node field %q", parts[0])
	}
	return nil
}

// AuthorityRegistry maps an authority name to its pinned Ed25519 public key.
// A client ships this (or a signed bundle of it) and attaches the keys to a
// decoded document before verifying.
type AuthorityRegistry map[string]ed25519.PublicKey

// Attach fills in the PubKey of every authority listed in the document. It is
// an error for the document to list an authority the registry does not know.
func (r AuthorityRegistry) Attach(d *Document) error {
	for i := range d.Authorities {
		pk, ok := r[d.Authorities[i].Name]
		if !ok {
			return fmt.Errorf("no public key for authority %s", d.Authorities[i].Name)
		}
		d.Authorities[i].PubKey = pk
	}
	return nil
}
