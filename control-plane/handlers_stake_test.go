package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"pqanon/control-plane/directory"
	"pqanon/control-plane/staking"
)

type stakeStatus struct {
	Bonded       int64 `json:"bonded_sats"`
	Unbonding    int64 `json:"unbonding_sats"`
	Withdrawable int64 `json:"withdrawable_sats"`
	Slashed      int64 `json:"slashed_sats"`
	Jailed       bool  `json:"jailed"`
	Eligible     bool  `json:"eligible"`
	Pending      []any `json:"pending_bonds"`
}

func status(t *testing.T, h http.Handler, node string) stakeStatus {
	t.Helper()
	rec := do(t, h, "GET", "/api/stake/"+node, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("stake status: %d %s", rec.Code, rec.Body.String())
	}
	var s stakeStatus
	_ = json.Unmarshal(rec.Body.Bytes(), &s)
	return s
}

// registerNode creates a node operated by tok's user, with a fresh node key.
func registerNode(t *testing.T, h http.Handler, tok, name string) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := do(t, h, "POST", "/api/nodes", tok, map[string]any{
		"name": name, "address": "203.0.113.7:443", "public_key": hex.EncodeToString(pub),
		"ed_pub": hex.EncodeToString(pub), "role": "mix", "region": "ch", "capacity_mbps": 500,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register node: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.ID == "" {
		t.Fatal("node registration returned no id")
	}
	return out.ID, priv
}

// bondPaid opens a bond, settles it on the dev rail, and runs one bond-watcher
// pass — the path by which a paid bond counts without anyone polling it.
func bondPaid(t *testing.T, srv *Server, h http.Handler, tok, node string, sats int64) {
	t.Helper()
	rec := do(t, h, "POST", "/api/stake/"+node+"/bond", tok, map[string]any{"amount_sats": sats, "rail": "dev"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("bond: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		BondID string `json:"bond_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec := do(t, h, "POST", "/api/stake/dev/settle", "", map[string]any{"bond_id": out.BondID}); rec.Code != http.StatusOK {
		t.Fatalf("settle: %d", rec.Code)
	}
	bonds, _ := srv.store.ListAwaitingBonds(context.Background())
	if srv.creditPaidBonds(context.Background(), bonds) < 1 {
		t.Fatal("the watcher pass must credit the paid bond")
	}
}

func descriptor(t *testing.T, priv ed25519.PrivateKey, node string, epoch uint64, addr string) string {
	t.Helper()
	d := staking.Descriptor{NodeID: node, Epoch: epoch, Address: addr, CapacityMbps: 500, Region: "CH"}
	copy(d.Ed25519[:], priv.Public().(ed25519.PublicKey))
	s, err := staking.Sign(priv, d)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStakeCannotBeSelfDeclared(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)
	rec := do(t, h, "POST", "/api/nodes", tok, map[string]any{
		"name": "liar", "address": "203.0.113.9:443", "public_key": "ab", "stake_sats": 1_000_000,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("self-declared stake must be refused, got %d", rec.Code)
	}
	node, _ := registerNode(t, h, tok, "honest")
	if s := status(t, h, node); s.Bonded != 0 || s.Eligible {
		t.Fatalf("a new node has no stake: %+v", s)
	}
}

func TestBondCountsOnlyOncePaid(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)
	node, _ := registerNode(t, h, tok, "zrh-01")

	rec := do(t, h, "POST", "/api/stake/"+node+"/bond", tok, map[string]any{"amount_sats": 200_000, "rail": "dev"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("bond: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		BondID  string `json:"bond_id"`
		Address string `json:"address"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Address == "" {
		t.Fatal("a bond must quote an address to pay")
	}
	if s := status(t, h, node); s.Bonded != 0 || len(s.Pending) != 1 {
		t.Fatalf("unpaid bond must not count: %+v", s)
	}
	do(t, h, "POST", "/api/stake/dev/settle", "", map[string]any{"bond_id": out.BondID})
	if s := status(t, h, node); s.Bonded != 200_000 || len(s.Pending) != 0 || !s.Eligible {
		t.Fatalf("paid bond must count: %+v", s)
	}
	// Looking again does not credit it twice.
	if s := status(t, h, node); s.Bonded != 200_000 {
		t.Fatalf("bond credited twice: %+v", s)
	}
}

func TestBondPermissions(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tokA := authedUser(t, srv, store)
	ub := newUser(t, store, "")
	tokB, _ := srv.tokens.Issue(ub.ID)
	node, _ := registerNode(t, h, tokA, "a-node")

	if rec := do(t, h, "POST", "/api/stake/"+node+"/bond", tokB, map[string]any{"amount_sats": 1, "rail": "dev"}); rec.Code != http.StatusForbidden {
		t.Fatalf("a non-operator bonding: %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/stake/"+node+"/bond", tokA, map[string]any{"amount_sats": 1, "rail": "monero"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("a non-sats rail: %d", rec.Code)
	}
	// A node with no registered key cannot be staked: slashing could never be checked.
	rec := do(t, h, "POST", "/api/nodes", tokA, map[string]any{"name": "keyless", "address": "x:1", "public_key": "ab"})
	var out struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec := do(t, h, "POST", "/api/stake/"+out.ID+"/bond", tokA, map[string]any{"amount_sats": 1, "rail": "dev"}); rec.Code != http.StatusConflict {
		t.Fatalf("bonding a keyless node: %d", rec.Code)
	}
}

func TestEquivocationSlashesJailsAndDelists(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)
	node, priv := registerNode(t, h, tok, "zrh-01")
	bondPaid(t, srv, h, tok, node, 200_000)

	// Unbond part: it stays slashable through the unbonding period.
	if rec := do(t, h, "POST", "/api/stake/"+node+"/unbond", tok, map[string]any{"amount_sats": 50_000}); rec.Code != http.StatusOK {
		t.Fatalf("unbond: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, "POST", "/api/stake/"+node+"/unbond", tok, map[string]any{"amount_sats": 999_999}); rec.Code != http.StatusConflict {
		t.Fatalf("over-unbond: %d", rec.Code)
	}
	if s := status(t, h, node); s.Bonded != 150_000 || s.Unbonding != 50_000 {
		t.Fatalf("after unbond: %+v", s)
	}

	a := descriptor(t, priv, node, 42, "203.0.113.5:443")
	b := descriptor(t, priv, node, 42, "198.51.100.9:443")
	slash := func(x, y string) int {
		return do(t, h, "POST", "/api/stake/slash", "", map[string]any{"descriptor_a": x, "descriptor_b": y}).Code
	}

	// Not evidence: identical, different epochs, or signed by another key.
	if c := slash(a, a); c != http.StatusBadRequest {
		t.Fatalf("identical descriptors: %d", c)
	}
	if c := slash(a, descriptor(t, priv, node, 43, "198.51.100.9:443")); c != http.StatusBadRequest {
		t.Fatalf("different epochs: %d", c)
	}
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	fa, fb := descriptor(t, forger, node, 42, "x:1"), descriptor(t, forger, node, 42, "y:1")
	if c := slash(fa, fb); c != http.StatusBadRequest {
		t.Fatalf("forged evidence: %d", c)
	}
	if s := status(t, h, node); s.Slashed != 0 || s.Jailed {
		t.Fatalf("rejected evidence must change nothing: %+v", s)
	}

	// Real equivocation: 50% of bonded (150k) and of unreleased unbonding (50k).
	rec := do(t, h, "POST", "/api/stake/slash", "", map[string]any{"descriptor_a": a, "descriptor_b": b})
	if rec.Code != http.StatusOK {
		t.Fatalf("slash: %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		Slashed int64  `json:"slashed_sats"`
		Epoch   uint64 `json:"epoch"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Slashed != 100_000 || res.Epoch != 42 {
		t.Fatalf("slash result: %+v", res)
	}
	s := status(t, h, node)
	if s.Bonded != 75_000 || s.Unbonding != 25_000 || s.Slashed != 100_000 || !s.Jailed || s.Eligible {
		t.Fatalf("after slash: %+v", s)
	}
	// The same evidence cannot slash twice; a jailed node cannot re-bond.
	if c := slash(b, a); c != http.StatusConflict {
		t.Fatalf("repeat slash: %d", c)
	}
	if rec := do(t, h, "POST", "/api/stake/"+node+"/bond", tok, map[string]any{"amount_sats": 1, "rail": "dev"}); rec.Code != http.StatusConflict {
		t.Fatalf("bonding a jailed node: %d", rec.Code)
	}
}

func TestDirectoryListsOnlyBondedUnjailedNodes(t *testing.T) {
	srv, h, store := newTestServer(t)
	_, tok := authedUser(t, srv, store)
	bonded, priv := registerNode(t, h, tok, "bonded-01")
	under, _ := registerNode(t, h, tok, "under-01")
	bondPaid(t, srv, h, tok, bonded, srv.stake.MinSats)
	bondPaid(t, srv, h, tok, under, srv.stake.MinSats-1)

	names := func() []string {
		rec := do(t, h, "GET", "/api/directory", "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("directory: %d", rec.Code)
		}
		doc, err := directory.Decode(rec.Body.Bytes())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		reg := directory.AuthorityRegistry{srv.directory.Name: srv.directory.Pub}
		if err := reg.Attach(doc); err != nil {
			t.Fatal(err)
		}
		if err := doc.Verify(time.Now()); err != nil {
			t.Fatalf("the served directory must verify under the authority key: %v", err)
		}
		var out []string
		for _, n := range doc.Nodes {
			out = append(out, n.Name)
		}
		return out
	}
	if got := strings.Join(names(), ","); got != "bonded-01" {
		t.Fatalf("directory = %q, want only the sufficiently bonded node", got)
	}

	// Equivocate: the node is slashed, jailed, and dropped from the directory.
	a := descriptor(t, priv, bonded, 7, "a:1")
	b := descriptor(t, priv, bonded, 7, "b:1")
	do(t, h, "POST", "/api/stake/slash", "", map[string]any{"descriptor_a": a, "descriptor_b": b})
	if got := names(); len(got) != 0 {
		t.Fatalf("a jailed node must leave the directory, got %v", got)
	}
}
