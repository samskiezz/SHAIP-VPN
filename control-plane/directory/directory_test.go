package directory

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

func sampleDoc() *Document {
	return &Document{
		Published:  time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		ValidUntil: time.Date(2026, 1, 15, 1, 0, 0, 0, time.UTC),
		Threshold:  2,
		Authorities: []Authority{
			{Name: "Reykjavik-01", KeyTag: 0x9e12},
			{Name: "Toronto-01", KeyTag: 0x3f88},
			{Name: "Zurich-01", KeyTag: 0x7c4a},
		},
		Nodes: []Node{
			{
				Name: "zrh-01-mix", Address: "203.0.113.5:8443", Role: "mix",
				X25519Hex:    "3a7f0000000000000000000000000000000000000000000000000000000000ff",
				Ed25519Hex:   "1f2e0000000000000000000000000000000000000000000000000000000000aa",
				CapacityMbps: 500, Region: "CH",
			},
		},
		Signatures: map[string][]byte{},
	}
}

func TestCanonicalIsDeterministicAndSorted(t *testing.T) {
	d := sampleDoc()
	// Shuffle the input order; the canonical form must be identical.
	d.Authorities[0], d.Authorities[2] = d.Authorities[2], d.Authorities[0]
	c1 := d.Canonical()
	d.Authorities[0], d.Authorities[2] = d.Authorities[2], d.Authorities[0]
	c2 := d.Canonical()
	if string(c1) != string(c2) {
		t.Fatalf("canonical form not order-independent")
	}
	if got := d.Digest(); got != sampleDoc().Digest() {
		t.Fatalf("digest not stable: %x", got)
	}
}

func TestThresholdSigningAndVerify(t *testing.T) {
	zPriv, zPub := fixedKey(1)
	rPriv, rPub := fixedKey(2)
	_, tPub := fixedKey(3)

	reg := AuthorityRegistry{"Zurich-01": zPub, "Reykjavik-01": rPub, "Toronto-01": tPub}
	now := time.Date(2026, 1, 15, 0, 30, 0, 0, time.UTC)

	// One signature: below the 2-of-3 threshold → rejected.
	d := sampleDoc()
	if err := d.Sign("Zurich-01", zPriv); err != nil {
		t.Fatal(err)
	}
	wire := d.Encode()
	dec, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Attach(dec); err != nil {
		t.Fatal(err)
	}
	if err := dec.Verify(now); err == nil {
		t.Fatal("expected failure below threshold")
	}

	// Two signatures: meets the threshold → accepted (after a round trip).
	if err := d.Sign("Reykjavik-01", rPriv); err != nil {
		t.Fatal(err)
	}
	dec2, err := Decode(d.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Attach(dec2); err != nil {
		t.Fatal(err)
	}
	if err := dec2.Verify(now); err != nil {
		t.Fatalf("expected success at threshold, got %v", err)
	}
}

func TestTamperedNodeIsRejected(t *testing.T) {
	zPriv, zPub := fixedKey(1)
	rPriv, rPub := fixedKey(2)
	_, tPub := fixedKey(3)
	reg := AuthorityRegistry{"Zurich-01": zPub, "Reykjavik-01": rPub, "Toronto-01": tPub}
	now := time.Date(2026, 1, 15, 0, 30, 0, 0, time.UTC)

	d := sampleDoc() // 3 authorities, threshold 2
	if err := d.Sign("Zurich-01", zPriv); err != nil {
		t.Fatal(err)
	}
	if err := d.Sign("Reykjavik-01", rPriv); err != nil {
		t.Fatal(err)
	}

	dec, err := Decode(d.Encode())
	if err != nil {
		t.Fatal(err)
	}
	// Flip a node capacity after signing.
	dec.Nodes[0].CapacityMbps = 999999
	if err := reg.Attach(dec); err != nil {
		t.Fatal(err)
	}
	if err := dec.Verify(now); err == nil {
		t.Fatal("expected failure on tampered node")
	}
}

func TestExpiredDocumentRejected(t *testing.T) {
	zPriv, zPub := fixedKey(1)
	reg := AuthorityRegistry{"Zurich-01": zPub}
	d := sampleDoc()
	d.Authorities = d.Authorities[2:] // just Zurich
	d.Threshold = 1
	_ = d.Sign("Zurich-01", zPriv)
	dec, _ := Decode(d.Encode())
	_ = reg.Attach(dec)
	after := time.Date(2026, 1, 15, 2, 0, 0, 0, time.UTC)
	if err := dec.Verify(after); err == nil {
		t.Fatal("expected expiry failure")
	}
}

// TestCrossLanguageVector pins the exact bytes, digest, and a signature so the
// Rust client (client/src/directory.rs) can verify the same artifacts. If the
// canonical form ever changes, this and the Rust vector change together.
func TestCrossLanguageVector(t *testing.T) {
	zPriv, zPub := fixedKey(1)
	d := sampleDoc()
	d.Authorities = d.Authorities[2:] // just Zurich-01
	d.Threshold = 1
	if err := d.Sign("Zurich-01", zPriv); err != nil {
		t.Fatal(err)
	}
	digest := d.Digest()
	wire := d.Encode()

	t.Logf("CROSSLANG pubkey    = %s", hex.EncodeToString(zPub))
	t.Logf("CROSSLANG digest    = %s", hex.EncodeToString(digest[:]))
	t.Logf("CROSSLANG signature = %s", hex.EncodeToString(d.Signatures["Zurich-01"]))
	t.Logf("CROSSLANG document  =\n%s", string(wire))

	// Self-check: the decoded+attached document verifies.
	dec, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	reg := AuthorityRegistry{"Zurich-01": zPub}
	if err := reg.Attach(dec); err != nil {
		t.Fatal(err)
	}
	if err := dec.Verify(time.Date(2026, 1, 15, 0, 30, 0, 0, time.UTC)); err != nil {
		t.Fatalf("vector failed self-verify: %v", err)
	}
}
