# PQ-ANON Architecture

This document describes the system **as it exists in this repository**. Planned
but not-yet-wired pieces are called out explicitly so the picture stays honest.

## Components

| Component | Location | Language | Purpose |
|---|---|---|---|
| `pqanon` (library) | `client/` (lib name `pqanon`) | Rust | Core PQANON/1 protocol: handshake, wire framing, obfuscation, transport, mix onion, routing |
| `pqanon` (client bin) | `client/src/main.rs` | Rust | CLI: `keygen`, `selftest`, `run` |
| `pqanond` | `server/src/bin/pqanond.rs` | Rust | Tunnel server daemon (handshake responder + data echo) |
| `pqanon-mixd` | `server/src/bin/pqanon-mixd.rs` | Rust | Mix node: peels one onion layer, replay-filters, forwards |
| Control plane | `control-plane/` | Go | Users, nodes, connections, routing rules, settings, signed CRL |
| Web UI | `web-ui/` | TypeScript / Next.js | Operator dashboard |

The Rust side is a two-package Cargo workspace (`client/`, `server/`); `server`
depends on `client` via `pqanon = { path = "../client", package = "pqanon-client" }`.
There is no single root crate, no `crates/*` split, and no FFI crate yet.

## Cryptography

All primitives come from RustCrypto / the standard library — none are
hand-rolled:

- Hybrid handshake: **ML-KEM-768** (`ml-kem`) + **X25519** (`x25519-dalek`).
- Dual signatures: **ML-DSA-65** (`ml-dsa`) + **Ed25519** (`ed25519-dalek`).
- AEAD: **ChaCha20-Poly1305** with the 22-byte wire header as AAD.
- KDF / MAC: **HKDF-SHA256**, **HMAC-SHA256**.
- Password hashing (control plane): **Argon2id** (PHC string).
- Control-plane tokens: **EdDSA** bearer tokens (not JWT).

## Data flows

### Handshake (PQANON-HS/1)

A two-sided authenticated handshake (`client/src/handshake.rs`):

1. `client_hello` → server: ephemeral ML-KEM-768 encapsulation key, X25519
   public key, client nonce.
2. Server verifies the client is authorized, encapsulates to the client's
   ML-KEM key, derives the X25519 shared secret, and replies with
   `server_hello` (its ephemerals + ML-DSA-65/Ed25519 signatures over the
   transcript).
3. Client verifies both signatures, decapsulates, and derives the mix secret
   `ss_mix = HKDF(ss_pq || ss_x, salt = client_nonce || server_nonce,
   info = "PQANON-HS/1")`.
4. `client_finish` → server; both sides derive `k_c2s`, `k_s2c`, `conn_id`.

`pqanon selftest` runs this in-process and asserts both sides derive identical
keys.

### Data path

- A DATA packet is framed as an `Envelope` (`client/src/wire.rs`) and sealed
  with the directional key under a deterministic nonce
  (`epoch(2) || seq(4) || zeros`), the 22-byte header as AAD.
- The sealed bytes are then **obfuscated** (`client/src/obf.rs`): header XOR
  morph + Fisher–Yates field permutation + length shaping. Invariant: the
  `PQAN` magic never appears on the wire (asserted in `selftest` and in the
  live UDP integration test `server/tests/tunnel.rs`).

### Mix path (PQANON-MIX/1)

- Fixed **2048-byte** cells, default **5 hops** (`client/src/mix.rs`).
- Each layer is `ephemeral_x25519_pub(32) || nonce(12) || AEAD(flag || [next_addr] || inner)`.
- A hop derives its per-cell key via `X25519(hop_sk, ephemeral_pub)` + HKDF,
  learning only the next hop.
- `pqanon-mixd` peels one layer, drops exact **replays** via a Bloom filter
  (`client/src/bloom.rs`), and forwards the re-framed cell.

## Control plane API

`control-plane/` exposes (chi router, `Store` interface backed by an in-memory
store by default or Postgres when `DATABASE_URL` is set):

- `POST /api/auth/register`, `POST /api/auth/login`
- `GET /api/crl` (Ed25519-signed revocation list, unauthenticated)
- Authenticated (`Bearer` token): `GET/POST /api/nodes`, `DELETE /api/nodes/{id}`,
  `GET /api/connections`, `DELETE /api/connections/{id}`, `GET /api/mixnet`,
  `GET /api/dashboard`, `GET /api/stats`, `GET /api/me`,
  `GET/POST /api/routing`, `DELETE /api/routing/{id}`,
  `GET/PUT /api/settings`.

## Trust boundaries

- **Client ↔ Server:** authenticated via long-term keys; confidential and
  forward-secret via the hybrid handshake.
- **Mix hop ↔ Mix hop:** authenticated per-cell via ephemeral X25519; each layer
  is AEAD-protected; no long-term trust between hops.
- **Client ↔ Control plane:** EdDSA bearer token over TLS.

## Not yet wired (honest status)

These are designed/partially present but **not** end-to-end today:

- Real TUN device I/O and server-side session routing by destination IP. The
  testable kernel of that routing (destination extraction from an IP header)
  exists and is unit-tested in `client/src/ipparse.rs`; the platform TUN device
  and the read/write loops are the remaining integration work (§19).
- Per-hop exponential mix delay queue and cover traffic scheduling.
- Rekey driver, PROBE/cookie anti-DoS exchange.
- Native platform clients (macOS/iOS/Android/desktop) and an FFI crate.
- Prometheus metrics emission (so Grafana dashboards are deferred until the
  series exist).
