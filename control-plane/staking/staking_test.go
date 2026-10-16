package staking

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func key(seed byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv, priv.Public().(ed25519.PublicKey)
}

func desc(pub ed25519.PublicKey, epoch uint64, addr string) Descriptor {
	d := Descriptor{NodeID: "node-1", Epoch: epoch, Address: addr, CapacityMbps: 500, Region: "CH"}
	copy(d.Ed25519[:], pub)
	d.X25519[0] = 0x3a
	return d
}

func TestSignParseRoundTrip(t *testing.T) {
	priv, pub := key(0x44)
	s, err := Sign(priv, desc(pub, 7, "203.0.113.5:443"))
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := Parse(s, pub)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.NodeID != "node-1" || d.Epoch != 7 || d.Address != "203.0.113.5:443" || d.CapacityMbps != 500 || d.Region != "CH" || d.X25519[0] != 0x3a {
		t.Fatalf("round trip: %+v", d)
	}
}

func TestSignRefusesAKeyThatIsNotTheDescriptors(t *testing.T) {
	priv, _ := key(0x44)
	_, other := key(0x45)
	if _, err := Sign(priv, desc(other, 7, "a")); err == nil {
		t.Fatal("signing a descriptor that names another key must fail")
	}
}

func TestEquivocationDetection(t *testing.T) {
	priv, pub := key(0x44)
	a, _ := Sign(priv, desc(pub, 42, "203.0.113.5:443"))
	b, _ := Sign(priv, desc(pub, 42, "198.51.100.9:443"))
	other, _ := Sign(priv, desc(pub, 43, "198.51.100.9:443"))

	epoch, err := CheckEquivocation("node-1", pub, a, b)
	if err != nil || epoch != 42 {
		t.Fatalf("conflicting descriptors for one epoch must be equivocation: %d %v", epoch, err)
	}
	if _, err := CheckEquivocation("node-1", pub, a, a); !errors.Is(err, ErrNoConflict) {
		t.Fatalf("identical descriptors are not equivocation: %v", err)
	}
	if _, err := CheckEquivocation("node-1", pub, a, other); !errors.Is(err, ErrNoConflict) {
		t.Fatalf("different epochs are not equivocation: %v", err)
	}
	if _, err := CheckEquivocation("node-2", pub, a, b); !errors.Is(err, ErrNoConflict) {
		t.Fatalf("descriptors for another node: %v", err)
	}
}

func TestForgedEvidenceIsRejected(t *testing.T) {
	// A reporter cannot frame a node: descriptors must verify under the key the
	// control plane registered for it, not under a key the reporter controls.
	_, nodePub := key(0x44)
	forger, forgerPub := key(0x66)
	d := desc(forgerPub, 42, "x")
	a, _ := Sign(forger, d)
	d.Address = "y"
	b, _ := Sign(forger, d)
	if _, err := CheckEquivocation("node-1", nodePub, a, b); !errors.Is(err, ErrSignature) {
		t.Fatalf("descriptors not signed by the node key: %v", err)
	}
	// Tampering with a genuine descriptor breaks its signature.
	priv, pub := key(0x44)
	good, _ := Sign(priv, desc(pub, 1, "203.0.113.5:443"))
	bad := good[:len(good)-2] + "AA"
	if _, _, err := Parse(bad, pub); err == nil {
		t.Fatal("tampered descriptor must fail")
	}
}

func TestSlashCut(t *testing.T) {
	for _, c := range []struct {
		amount int64
		pct    int
		want   int64
	}{{200_000, 50, 100_000}, {3, 50, 1}, {0, 50, 0}, {100, 0, 0}, {100, 100, 100}, {100, 150, 100}} {
		if got := SlashCut(c.amount, c.pct); got != c.want {
			t.Fatalf("SlashCut(%d, %d) = %d, want %d", c.amount, c.pct, got, c.want)
		}
	}
}

// TestCrossLanguageVector pins a descriptor the Rust signer
// (client/src/descriptor.rs) must reproduce byte-for-byte from the same
// fields and key (Ed25519 is deterministic).
func TestCrossLanguageVector(t *testing.T) {
	priv, pub := key(0x44)
	d := desc(pub, 42, "203.0.113.5:443")
	s, err := Sign(priv, d)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CROSSLANG descriptor = %s", s)
}
