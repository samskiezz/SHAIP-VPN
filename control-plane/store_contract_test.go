package main

// One behavioural contract for every Store implementation. It always runs
// against MemStore; against Postgres it runs when PQANON_TEST_DATABASE_URL
// points at a database (the master battery provisions a throwaway PostgreSQL
// cluster and fails its stage if the Postgres run was skipped). Until this
// suite existed, no test exercised PgStore at all.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestStoreContractMemory(t *testing.T) {
	storeContract(t, NewMemStore())
}

func TestStoreContractPostgres(t *testing.T) {
	url := os.Getenv("PQANON_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set PQANON_TEST_DATABASE_URL to run the contract against Postgres")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := NewPgStore(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer st.Close()
	storeContract(t, st)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// mkUser creates a user and returns its id.
func mkUser(t *testing.T, st Store) string {
	t.Helper()
	number, _ := newAccountNumber()
	u := &User{AccountNumber: number, PasswordHash: "x"}
	if err := st.CreateUser(context.Background(), u); err != nil || u.ID == "" {
		t.Fatalf("create user: %v %q", err, u.ID)
	}
	return u.ID
}

// isDay reports whether t is a UTC day boundary: what every customer record
// stores in place of a moment.
func isDay(t time.Time) bool { return t.Equal(day(t)) }

func mkToken(t *testing.T, st Store, userID string, ttl time.Duration) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	id := randHex(16)
	if err := st.CreateEnrollToken(context.Background(), &EnrollToken{
		TokenID: id, UserID: userID, IssuedAt: now, ExpiresAt: now.Add(ttl),
	}); err != nil {
		t.Fatalf("create token: %v", err)
	}
	return id
}

func mkDevice(userID string) *Device {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return &Device{
		ID: randHex(16), UserID: userID, Name: "dev-" + randHex(2), EdPub: pub,
		CertExpires: time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second),
	}
}

func storeContract(t *testing.T, st Store) {
	ctx := context.Background()

	t.Run("users", func(t *testing.T) {
		number, _ := newAccountNumber()
		created := &User{AccountNumber: number, PasswordHash: "h"}
		if err := st.CreateUser(ctx, created); err != nil || created.ID == "" {
			t.Fatal(err)
		}
		if err := st.CreateUser(ctx, &User{AccountNumber: number, PasswordHash: "h"}); !errors.Is(err, ErrAccountNumberTaken) {
			t.Fatalf("a duplicate account number must be refused with ErrAccountNumberTaken, got %v", err)
		}
		u, err := st.GetUserByAccount(ctx, number)
		if err != nil || u.Role != "user" || u.ID != created.ID || u.AccountNumber != number {
			t.Fatalf("by account number: %v %+v", err, u)
		}
		if !isDay(u.CreatedAt) {
			t.Fatalf("created_at is a moment, not a day: %v", u.CreatedAt)
		}
		if byID, err := st.GetUserByID(ctx, u.ID); err != nil || byID.AccountNumber != number {
			t.Fatalf("by id: %v", err)
		}
		other, _ := newAccountNumber()
		if _, err := st.GetUserByAccount(ctx, other); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing user: %v", err)
		}
		if _, err := st.GetUserByID(ctx, "session:"+randHex(8)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a non-UUID id: %v", err)
		}
	})

	t.Run("enrollment-claim-once", func(t *testing.T) {
		uid := mkUser(t, st)
		tok := mkToken(t, st, uid, time.Hour)
		d := mkDevice(uid)
		if err := st.ClaimEnrollment(ctx, tok, time.Now().UTC(), d); err != nil {
			t.Fatalf("claim: %v", err)
		}
		if d.TokenID != tok || d.EdPubHex != hex.EncodeToString(d.EdPub) || !isDay(d.CreatedAt) {
			t.Fatalf("claimed device not filled in (or created_at is a moment): %+v", d)
		}
		if err := st.ClaimEnrollment(ctx, tok, time.Now().UTC(), mkDevice(uid)); !errors.Is(err, ErrTokenClaimed) {
			t.Fatalf("second claim: %v", err)
		}
		if err := st.ClaimEnrollment(ctx, randHex(16), time.Now().UTC(), mkDevice(uid)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("unknown token: %v", err)
		}
	})

	t.Run("enrollment-guards-change-nothing", func(t *testing.T) {
		uid := mkUser(t, st)
		other := mkUser(t, st)

		// A token issued to another account is not claimable for this one.
		tok := mkToken(t, st, uid, time.Hour)
		if err := st.ClaimEnrollment(ctx, tok, time.Now().UTC(), mkDevice(other)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-account claim: %v", err)
		}
		// An expired token fails. Stores keep the expiry only to the end of its
		// day (the exact one is in the signed token), so go two days on.
		if err := st.ClaimEnrollment(ctx, tok, time.Now().UTC().Add(49*time.Hour), mkDevice(uid)); !errors.Is(err, ErrTokenExpired) {
			t.Fatalf("expired claim: %v", err)
		}
		// ...and a reused device key fails without burning the fresh token.
		first := mkDevice(uid)
		if err := st.ClaimEnrollment(ctx, tok, time.Now().UTC(), first); err != nil {
			t.Fatalf("claim: %v", err)
		}
		tok2 := mkToken(t, st, uid, time.Hour)
		dup := mkDevice(uid)
		dup.EdPub = first.EdPub
		if err := st.ClaimEnrollment(ctx, tok2, time.Now().UTC(), dup); !errors.Is(err, ErrDeviceKeyInUse) {
			t.Fatalf("reused key: %v", err)
		}
		if err := st.ClaimEnrollment(ctx, tok2, time.Now().UTC(), mkDevice(uid)); err != nil {
			t.Fatalf("token must survive the failed claim: %v", err)
		}
	})

	t.Run("enrollment-concurrent-claims", func(t *testing.T) {
		// Many devices race for one token: exactly one wins. A single race can
		// miss a missing lock (a negative control without FOR UPDATE double-
		// claimed in about one run in three), so race several rounds per run.
		const n, rounds = 16, 8
		for round := 0; round < rounds; round++ {
			uid := mkUser(t, st)
			tok := mkToken(t, st, uid, time.Hour)
			var wg sync.WaitGroup
			results := make([]error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					results[i] = st.ClaimEnrollment(ctx, tok, time.Now().UTC(), mkDevice(uid))
				}(i)
			}
			wg.Wait()
			wins, claimed := 0, 0
			for _, err := range results {
				switch {
				case err == nil:
					wins++
				case errors.Is(err, ErrTokenClaimed):
					claimed++
				default:
					t.Fatalf("round %d: unexpected error: %v", round, err)
				}
			}
			if wins != 1 || claimed != n-1 {
				t.Fatalf("round %d: wins=%d claimed=%d, want 1 and %d", round, wins, claimed, n-1)
			}
			if devs, _ := st.ListDevices(ctx, uid); len(devs) != 1 {
				t.Fatalf("round %d: exactly one device must exist, got %d", round, len(devs))
			}
		}
	})

	t.Run("devices-list-revoke", func(t *testing.T) {
		uid := mkUser(t, st)
		other := mkUser(t, st)
		d := mkDevice(uid)
		if err := st.ClaimEnrollment(ctx, mkToken(t, st, uid, time.Hour), time.Now().UTC(), d); err != nil {
			t.Fatal(err)
		}
		devs, err := st.ListDevices(ctx, uid)
		if err != nil || len(devs) != 1 {
			t.Fatalf("list: %v %d", err, len(devs))
		}
		got := devs[0]
		if got.ID != d.ID || got.Name != d.Name || got.EdPubHex != hex.EncodeToString(d.EdPub) ||
			!got.CertExpires.Equal(d.CertExpires) || got.RevokedAt != nil {
			t.Fatalf("listed device differs: %+v vs %+v", got, d)
		}
		if devs, _ := st.ListDevices(ctx, other); len(devs) != 0 {
			t.Fatal("devices leak across accounts")
		}
		if err := st.RevokeDevice(ctx, d.ID, other); !errors.Is(err, ErrNotFound) {
			t.Fatalf("revoke by non-owner: %v", err)
		}
		if err := st.RevokeDevice(ctx, d.ID, uid); err != nil {
			t.Fatal(err)
		}
		first := revokedAt(t, st, d.ID)
		if !isDay(first) {
			t.Fatalf("revoked_at is a moment, not a day: %v", first)
		}
		if err := st.RevokeDevice(ctx, d.ID, uid); err != nil {
			t.Fatal(err)
		}
		if again := revokedAt(t, st, d.ID); !again.Equal(first) {
			t.Fatal("revoking twice must keep the first day")
		}
	})

	t.Run("apikeys-audit", func(t *testing.T) {
		uid := mkUser(t, st)
		k := &APIKey{UserID: uid, Name: "ci", Prefix: "pqa_abcdefgh", KeyHash: randHex(32)}
		if err := st.CreateAPIKey(ctx, k); err != nil || k.ID == "" {
			t.Fatalf("api key: %v", err)
		}
		if keys, _ := st.ListAPIKeys(ctx, uid); len(keys) != 1 || keys[0].Name != "ci" || !isDay(keys[0].CreatedAt) {
			t.Fatalf("keys (created_at must be a day): %+v", keys)
		}
		if err := st.DeleteAPIKey(ctx, k.ID, uid); err != nil {
			t.Fatal(err)
		}

		if err := st.AppendAudit(ctx, &AuditEntry{UserID: uid, Action: "contract.test", Detail: "d"}); err != nil {
			t.Fatal(err)
		}
		entries, _ := st.ListAudit(ctx, uid, 10)
		if len(entries) != 1 || entries[0].Action != "contract.test" || !isDay(entries[0].At) {
			t.Fatalf("audit (at must be a day): %+v", entries)
		}
		if others, _ := st.ListAudit(ctx, mkUser(t, st), 10); len(others) != 0 {
			t.Fatalf("audit entries leak across accounts: %+v", others)
		}
		if all, _ := st.ListAudit(ctx, "", 10); len(all) != 0 {
			t.Fatalf("an empty account must list nothing, not everyone's entries: %+v", all)
		}
	})

	t.Run("delete-account", func(t *testing.T) {
		uid := mkUser(t, st)
		other := mkUser(t, st)
		d := mkDevice(uid)
		if err := st.ClaimEnrollment(ctx, mkToken(t, st, uid, time.Hour), time.Now().UTC(), d); err != nil {
			t.Fatal(err)
		}
		if err := st.CreateAPIKey(ctx, &APIKey{UserID: uid, Name: "k", Prefix: "pqa_x", KeyHash: randHex(32)}); err != nil {
			t.Fatal(err)
		}
		_ = st.AppendAudit(ctx, &AuditEntry{UserID: uid, Action: "x"})
		_ = st.AppendAudit(ctx, &AuditEntry{UserID: other, Action: "kept"})
		mkToken(t, st, uid, time.Hour) // an unclaimed token goes too

		if err := st.DeleteAccount(ctx, uid, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.GetUserByID(ctx, uid); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the account must be gone: %v", err)
		}
		if keys, _ := st.ListAPIKeys(ctx, uid); len(keys) != 0 {
			t.Fatal("API keys must be gone")
		}
		if devs, _ := st.ListDevices(ctx, uid); len(devs) != 0 {
			t.Fatal("devices must be gone")
		}
		if entries, _ := st.ListAudit(ctx, uid, 10); len(entries) != 0 {
			t.Fatal("the security log must be gone")
		}
		if entries, _ := st.ListAudit(ctx, other, 10); len(entries) != 1 {
			t.Fatal("another account's log must stay")
		}
		// The device's certificate is still refused: its id is in the CRL.
		if at := revokedAt(t, st, d.ID); !isDay(at) {
			t.Fatalf("revocation day: %v", at)
		}
		if err := st.DeleteAccount(ctx, uid, time.Now()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("deleting twice: %v", err)
		}
		// An account that runs nodes keeps them (and its stake) until it removes them.
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		if err := st.CreateNode(ctx, &Node{Name: "del-" + randHex(3), Address: "203.0.113.4:443", PublicKey: pub, EdPub: pub, OwnerID: other}); err != nil {
			t.Fatal(err)
		}
		if err := st.DeleteAccount(ctx, other, time.Now()); !errors.Is(err, ErrOwnsNodes) {
			t.Fatalf("an account with nodes: %v", err)
		}
		if _, err := st.GetUserByID(ctx, other); err != nil {
			t.Fatal("a refused deletion must change nothing")
		}
	})

	t.Run("staking", func(t *testing.T) {
		owner := mkUser(t, st)
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		n := &Node{Name: "stake-" + randHex(3), Address: "203.0.113.1:443", PublicKey: pub, EdPub: pub,
			Role: "mix", Region: "CH", OwnerID: owner}
		if err := st.CreateNode(ctx, n); err != nil || n.ID == "" {
			t.Fatalf("CreateNode must report the new id: %v %q", err, n.ID)
		}
		got, err := st.GetNode(ctx, n.ID)
		if err != nil || got.OwnerID != owner || got.EdPubHex != hex.EncodeToString(pub) || got.StakeSats != 0 || got.Role != "mix" {
			t.Fatalf("node round trip: %v %+v", err, got)
		}
		if err := st.CreateBond(ctx, &StakeBond{NodeID: "00000000-0000-0000-0000-000000000000", AmountSats: 1, Rail: "dev"}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("bond for a missing node: %v", err)
		}

		// A bond is credited exactly once, even when checks race.
		b := &StakeBond{NodeID: n.ID, AmountSats: 200_000, Rail: "dev", Quote: RailQuote{Address: "dev:x"}}
		if err := st.CreateBond(ctx, b); err != nil {
			t.Fatal(err)
		}
		if aw, _ := st.ListAwaitingBonds(ctx); !containsBond(aw, b.ID) {
			t.Fatal("an unpaid bond must be awaiting")
		}
		var wg sync.WaitGroup
		credits := make([]bool, 8)
		for i := range credits {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				credits[i], _ = st.CreditBond(ctx, b.ID, time.Now().UTC())
			}(i)
		}
		wg.Wait()
		wins := 0
		for _, c := range credits {
			if c {
				wins++
			}
		}
		if node, _ := st.GetNode(ctx, n.ID); wins != 1 || node.StakeSats != 200_000 {
			t.Fatalf("credit races: wins=%d stake=%d, want 1 and 200000", wins, node.StakeSats)
		}
		if aw, _ := st.ListAwaitingBonds(ctx); containsBond(aw, b.ID) {
			t.Fatal("a credited bond is no longer awaiting")
		}

		// Unbonding: over-unbond refused and changes nothing; one entry already
		// released (no longer slashable), one still locked.
		if err := st.Unbond(ctx, n.ID, 999_999, time.Now()); !errors.Is(err, ErrInsufficientStake) {
			t.Fatalf("over-unbond: %v", err)
		}
		if err := st.Unbond(ctx, n.ID, 40_000, time.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := st.Unbond(ctx, n.ID, 60_000, time.Now().Add(24*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if node, _ := st.GetNode(ctx, n.ID); node.StakeSats != 100_000 {
			t.Fatalf("bonded after unbonding = %d, want 100000", node.StakeSats)
		}

		// Slash 50%: bonded 100k → 50k cut, locked unbonding 60k → 30k cut; the
		// released 40k is untouched. The node is jailed; a repeat changes nothing.
		cut, err := st.Slash(ctx, n.ID, 9, 50, "evidence", time.Now().UTC())
		if err != nil || cut != 80_000 {
			t.Fatalf("slash: cut=%d err=%v, want 80000", cut, err)
		}
		node, _ := st.GetNode(ctx, n.ID)
		if node.StakeSats != 50_000 || node.JailedAt == nil {
			t.Fatalf("after slash: stake=%d jailed=%v", node.StakeSats, node.JailedAt)
		}
		us, _ := st.ListUnbondings(ctx, n.ID)
		var released, locked int64
		for _, u := range us {
			if u.ReleaseAt.Before(time.Now()) {
				released += u.AmountSats
			} else {
				locked += u.AmountSats
			}
		}
		if released != 40_000 || locked != 30_000 {
			t.Fatalf("unbondings after slash: released=%d locked=%d, want 40000 and 30000", released, locked)
		}
		if _, err := st.Slash(ctx, n.ID, 9, 50, "again", time.Now().UTC()); !errors.Is(err, ErrAlreadySlashed) {
			t.Fatalf("repeat slash: %v", err)
		}
		if node, _ := st.GetNode(ctx, n.ID); node.StakeSats != 50_000 {
			t.Fatal("a refused repeat slash must change nothing")
		}
		if sl, _ := st.ListSlashes(ctx, n.ID); len(sl) != 1 || sl[0].Epoch != 9 || sl[0].SlashedSats != 80_000 {
			t.Fatalf("slash record: %+v", sl)
		}
	})

	t.Run("payments", func(t *testing.T) {
		o := &PayOrder{
			Denom: "month", Rail: "dev", Address: "dev:" + randHex(4), AmountAtomic: 125,
			Status: "awaiting_payment", BlindedTokens: [][]byte{{1, 2, 3}},
			ExpiresAt: time.Now().UTC().Add(time.Hour),
		}
		if err := st.CreatePayOrder(ctx, o); err != nil || o.ID == "" {
			t.Fatalf("order: %v", err)
		}
		now := time.Now().UTC()
		o.Status, o.PaidAt, o.BlindSigs = "paid", &now, [][]byte{{9}}
		if err := st.UpdatePayOrder(ctx, o); err != nil {
			t.Fatal(err)
		}
		got, err := st.GetPayOrder(ctx, o.ID)
		if err != nil || got.Status != "paid" || len(got.BlindSigs) != 1 || len(got.BlindedTokens) != 1 {
			t.Fatalf("order round trip: %v %+v", err, got)
		}
		// An order's times are days: opened, paid, and an expiry rounded up
		// (never earlier than the one asked for).
		if !isDay(got.CreatedAt) || got.PaidAt == nil || !isDay(*got.PaidAt) || !isDay(got.ExpiresAt) ||
			got.ExpiresAt.Before(time.Now().Add(time.Hour)) {
			t.Fatalf("order times must be days: %+v", got)
		}
		// Re-saving an order does not move its expiry.
		if err := st.UpdatePayOrder(ctx, got); err != nil {
			t.Fatal(err)
		}
		if again, _ := st.GetPayOrder(ctx, o.ID); !again.ExpiresAt.Equal(got.ExpiresAt) || !again.CreatedAt.Equal(got.CreatedAt) {
			t.Fatalf("re-saving moved the order's times: %+v vs %+v", again, got)
		}
		nonce := randHex(16)
		if err := st.SpendToken(ctx, "month", nonce); err != nil {
			t.Fatal(err)
		}
		if err := st.SpendToken(ctx, "month", nonce); !errors.Is(err, ErrSpent) {
			t.Fatalf("double spend: %v", err)
		}
	})
}

func containsBond(bs []StakeBond, id string) bool {
	for _, b := range bs {
		if b.ID == id {
			return true
		}
	}
	return false
}

func revokedAt(t *testing.T, st Store, id string) time.Time {
	t.Helper()
	devs, err := st.ListRevokedDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.ID == id && d.RevokedAt != nil {
			return *d.RevokedAt
		}
	}
	t.Fatalf("device %s not in the revoked list", id)
	return time.Time{}
}
