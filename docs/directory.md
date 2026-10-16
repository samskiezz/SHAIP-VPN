# Directory consensus (§ infrastructure)

A **directory consensus** is a signed, plain-text list of the active nodes.
Multiple independent **authorities** sign it; a client accepts it only when at
least a threshold of the authorities it pins have signed the exact bytes. This
is the trust root for path selection: a node list no quorum agreed on is never
used.

## Format

ASCII, one directive per line, fully deterministic so two independent
implementations produce byte-identical bytes:

```
PQANON-CONSENSUS-V1
published 2026-01-15T00:00:00Z
valid-until 2026-01-15T01:00:00Z
threshold 2/3
authorities 3
authority-name Reykjavik-01 key-tag 0x9e12
authority-name Toronto-01 key-tag 0x3f88
authority-name Zurich-01 key-tag 0x7c4a

node zrh-01-mix addr 203.0.113.5:8443 role mix
    x25519 <64 hex>
    ed25519 <64 hex>
    capacity-mbps 500
    region CH

signature Zurich-01 <128 hex>
signature Reykjavik-01 <128 hex>
```

Authorities and nodes are sorted by name. The **digest** is the SHA-256 of the
*canonical form* — everything above the first `signature` line. Each authority
signs that 32-byte digest with **Ed25519** (RFC 8032). `Encode` appends the
signature lines; the digest never covers them, so signatures can be collected
incrementally without changing what was signed.

## Verification

A client:

1. Parses the document and recomputes the digest from the received bytes.
2. Attaches each listed authority's **pinned** public key from a registry it
   ships. An authority it doesn't recognize is a hard error.
3. Checks the validity window (`published ≤ now ≤ valid-until`).
4. Counts valid Ed25519 signatures. **Any** present-but-invalid signature fails
   the whole document (so a forgery can't pad to the threshold with garbage),
   and fewer than `threshold` valid signatures is a rejection.

## Implementations and cross-language proof

- **Authority (sign):** `control-plane/directory/directory.go` — stdlib
  `crypto/ed25519` + `crypto/sha256`, no external deps.
- **Client (verify):** `client/src/directory.rs` — `ed25519-dalek` + `sha2`,
  no network/time deps (timestamps are compared lexically, exact for canonical
  RFC 3339 UTC strings).

Because the canonical form is byte-exact across both, a signature made by the Go
authority verifies in the Rust client unchanged. This is pinned by a shared test
vector: `TestCrossLanguageVector` (Go) logs a document, digest, and signature; the
Rust tests `cross_language_digest_matches_go` and `cross_language_signature_verifies`
recompute the same digest from the same bytes and verify the same signature. If
the format ever changes, both sides change together.

## Serving and fetching

The control plane serves a live consensus at `GET /api/directory`. It is signed
by its directory-authority key (`DIRECTORY_SIGNER`, or `KEY_DIR/directory.key`,
HSM-capable) and lists only nodes with enough **paid, bonded stake** that are
not jailed for equivocation (see [staking.md](staking.md)).
`pqanon directory --url … --authority NAME=HEX` fetches it, verifies it with the
Rust verifier above, and lists the admitted nodes. The battery's `stake` stage
checks a node appearing once bonded and disappearing once slashed.

## Not yet wired

- Authority-to-authority voting/liveness: who proposes, and how a quorum with a
  minority offline still publishes. One control plane signs with threshold 1
  today; the format and the verifier already handle N-of-M.
- Feeding the verified node list into mix path selection (which already has
  `client/src/mix_reputation.rs` for per-node weighting).
