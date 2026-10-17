# SHAIP VPN Architecture

This document describes the system **as it exists in this repository**. Planned
but not-yet-wired pieces are called out explicitly so the picture stays honest.

## Components

| Component | Location | Language | Purpose |
|---|---|---|---|
| `shaip` (library) | `client/` (lib name `shaip`) | Rust | Core SHAIP/1 protocol: handshake, wire framing, obfuscation, transport, mix onion, routing |
| `shaip` (client bin) | `client/src/main.rs` | Rust | CLI: `keygen`, `selftest`, `run` |
| `shaipd` | `server/src/bin/shaipd.rs` | Rust | Tunnel server daemon: handshake responder, session table, TUN device, egress NAT, DNS forwarder |
| `shaip-mixd` | `server/src/bin/shaip-mixd.rs` | Rust | Mix node: peels one onion layer, replay-filters, forwards |
| Control plane | `control-plane/` | Go | Anonymous accounts (random account numbers), devices, nodes, payments, staking, signed CRL |
| Web UI | `web-ui/` | TypeScript / Next.js | Operator dashboard |

The Rust side is a three-package Cargo workspace (`client/`, `server/`, `ffi/`);
`server` and `ffi` depend on `client` via
`shaip = { path = "../client", package = "shaip-client" }`. `ffi/` builds the
`shaip-ffi` static library and C header (`ffi/include/shaip.h`) that the iOS
Packet Tunnel links against. There is no single root crate and no `crates/*` split.

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

### Handshake (SHAIP-HS/1)

A two-sided authenticated handshake (`client/src/handshake.rs`):

1. `client_hello` → server: ephemeral ML-KEM-768 encapsulation key, X25519
   public key, client nonce.
2. Server verifies the client is authorized, encapsulates to the client's
   ML-KEM key, derives the X25519 shared secret, and replies with
   `server_hello` (its ephemerals + ML-DSA-65/Ed25519 signatures over the
   transcript).
3. Client verifies both signatures, decapsulates, and derives the mix secret
   `ss_mix = HKDF(ss_pq || ss_x, salt = client_nonce || server_nonce,
   info = "SHAIP-HS/1")`.
4. `client_finish` → server, AEAD-sealed under a key derived from `ss_mix`:
   the client's long-term public keys, its transcript signatures and MAC, and
   (for a device-bound server) its device certificate, which must bind the
   same Ed25519 key that signed the transcript. Both sides then derive `k_c2s`,
   `k_s2c` and `conn_id`.

`shaip selftest` runs this in-process and asserts both sides derive identical
keys.

### Data path

- A DATA packet is framed as an `Envelope` (`client/src/wire.rs`) and sealed
  with the directional key under a deterministic nonce
  (`epoch(2) || seq(4) || zeros`), the 22-byte header as AAD.
- The sealed bytes then pass through **SHAIP-OBF/2** (`client/src/obf.rs`):
  the 22-byte header is XORed with a ChaCha20 keystream selected by a 16-byte
  sample of the ciphertext under a per-session key (after RFC 9001 §5.4.4),
  and the datagram is padded to a shaped size plus 0–15 random bytes. Every
  packet's mask differs, so no header byte repeats across a flow.
- Handshake messages travel in the OBF/2 **boot layer**: split into fragments,
  each sealed with ChaCha20-Poly1305 (random nonce) under a key derived from the
  server's pinned public keys, in a datagram of exactly 1200 bytes. The server
  reassembles them (bounded in count, size and time), refuses an unpadded
  CLIENT_HELLO before any work, sends at most 3× what it received until the
  handshake completes, and answers nothing it can't open.
- Checked on the wire by the netns lab (`scripts/e2e/vpn_lab.sh` with
  `lab_wirecap.py` on the ISP's link): no IP fragments, no `PQAN` magic, and no
  byte position whose most common value exceeds 3% of a flow's packets.

### Mix path (SHAIP-MIX/1)

- Fixed **2048-byte** cells, default **5 hops** (`client/src/mix.rs`).
- Each layer is `ephemeral_x25519_pub(32) || nonce(12) || AEAD(flag || [next_addr] || inner)`.
- A hop derives its per-cell key via `X25519(hop_sk, ephemeral_pub)` + HKDF,
  learning only the next hop.
- `shaip-mixd` peels one layer, drops exact **replays** via a Bloom filter
  (`client/src/bloom.rs`), and forwards the re-framed cell.

## Control plane API

`control-plane/` exposes (chi router, `Store` interface backed by an in-memory
store by default or Postgres when `DATABASE_URL` is set):

- `POST /api/auth/register` (`{password}` → a random 16-digit `account_number`,
  the login; no email or name is taken), `POST /api/auth/login`
  (`{account_number, password}`)
- `GET /api/crl` (Ed25519-signed revocation list, unauthenticated)
- Payments, enrollment claims, staking status and the directory (public)
- Authenticated (`Bearer` session token, or `Bearer pqa_…` personal API key,
  matched by its SHA-256): `GET/POST /api/nodes`, `GET/DELETE /api/nodes/{id}`
  (delete: the node's operator or an admin only, and not while its stake is
  bonded, unbonding, or a bond awaits payment), `GET /api/mixnet`,
  `GET /api/dashboard`, `GET /api/stats`, `GET/DELETE /api/me` (deleting erases
  the account), API keys, the caller's own audit log, devices and enrollment,
  staking bonds.

The control plane keeps no per-account connection log, no domain rules and no
settings; it has no request logger and stores no IP address
(docs/privacy-policy.md, docs/log-schema.md).

## Trust boundaries

- **Client ↔ Server:** authenticated via long-term keys; confidential and
  forward-secret via the hybrid handshake.
- **Mix hop ↔ Mix hop:** authenticated per-cell via ephemeral X25519; each layer
  is AEAD-protected; no long-term trust between hops.
- **Client ↔ Control plane:** EdDSA bearer token over TLS.

## Advanced features (implemented)

- **BBR congestion control** (`client/src/transport.rs`): windowed max-bandwidth
  and min-RTT filters, a PROBE_BW pacing-gain cycle, and **explicit
  sub-millisecond pacing** — the inter-packet gap is `bytes / pacing_rate` at
  nanosecond resolution, not a fixed millisecond tick.
- **DNSSEC validation** (`client/src/dnssec.rs`, `client/src/dns_resolver.rs`):
  RRSIG verification over a canonical RRset (signature input per RFC 4034
  §3.1.8.1) for **RSASHA256** (alg 8 — the algorithm the root and most TLDs sign
  with), **ECDSA P-256/SHA-256** (alg 13 — modern leaf zones), and **Ed25519**
  (alg 15); the DS/DNSKEY **chain-of-trust walk** from a configured anchor
  (`validate_chain`); and the real **IANA root trust anchors** shipped as the
  default (`root_trust_anchors` — KSK-2017 tag 20326 and KSK-2024 tag 38696,
  each verified byte-for-byte against IANA's published trust-anchor file). The
  validating stub resolver sets the DNSSEC-OK bit, parses the wire response, and
  **drops `Bogus` answers** instead of returning them.
- **No answer to probes on the UDP port.** `shaipd` replies to nothing it
  can't open (OBF/2). It used to answer with a randomized TLS ServerHello
  record, but no real HTTPS server replies to stray UDP with a TLS record, so
  that reply was itself a fingerprint; it was removed. The live TLS decoy on
  TCP (`client/src/decoy.rs`) is unchanged.
- **Globally-scheduled mix cover** (`client/src/mix_cover.rs`
  `GlobalCoverScheduler`, wired into `shaip-mixd --cover-peer`): one node-wide
  Poisson emission process, independent of client count/activity, so the
  observable cover rate leaks nothing about the client population.

## Not yet wired (honest status)

Kept deliberately short and current. (Earlier versions of this file listed TUN
I/O, the FFI crate, the rekey driver and the anti-DoS cookie here; all four
have since shipped — see `scripts/e2e/vpn_lab.sh`, `ffi/`, `client/src/supervisor.rs`
and `client/src/retry.rs` respectively. If this section and the top-level
README disagree, the README is newer.)

Genuinely not end-to-end today:

- **No mixnet in the data path.** `shaip-mixd` peels and forwards onion cells
  and runs a global cover-traffic scheduler, but the tunnel goes straight to one
  server; `shaip run --route anon` refuses rather than pretend. The per-hop
  exponential mix delay queue is also not wired.
- **DNSSEC negative answers.** NSEC/NSEC3 non-existence and wildcard proofs are
  not implemented. The positive path — multi-algorithm RRSIG verification, the
  DS/DNSKEY chain walk, and the real IANA root anchors — is wired and tested
  (`client/src/dnssec.rs`). A live test against the real root also needs a DNS
  path that returns DNSKEY RRsets, which some sandboxed networks strip.
- **Native app builds.** The iOS app's Rust core (via `shaip-ffi`) is exercised
  on Linux against a live `shaipd`, but the SwiftUI/NetworkExtension/WidgetKit
  layer compiles only in Xcode on macOS; Android and desktop shells don't exist.

What IS wired end-to-end: the IPv4 VPN (real TUN device, egress NAT, DNS
forwarder, 4-netns lab), the FFI C ABI, rekey every 20 minutes via a fresh
handshake, and the stateless retry cookie for address validation under load.
