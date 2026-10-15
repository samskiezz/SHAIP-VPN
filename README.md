# PQ-ANON — Post-Quantum Anonymizing VPN Stack

A from-scratch VPN stack implementing **PQANON/1**: a hybrid post-quantum
handshake, a custom obfuscated UDP transport, a fixed-size onion mixnet, a REST
control plane, and a web dashboard. Every wire format and cryptographic
composition is defined in-house; only standard RustCrypto / Go stdlib primitives
are used as building blocks (ML-KEM-768, ML-DSA-65, X25519, Ed25519,
ChaCha20-Poly1305, HKDF/HMAC-SHA256, Argon2id).

> Built for defensive use: protecting our own company's traffic and
> infrastructure from traffic analysis, DPI, and a future quantum adversary.

## Status — what actually runs today

| Component | Language | State | Verified by |
|-----------|----------|-------|-------------|
| `pqanon` client lib (`wire`, `handshake`, `obf`, `transport`, `mix`, `routing`, `kdf`) | Rust | **Working** | 25 unit tests |
| Full hybrid handshake (client **and** server sides) | Rust | **Working** | handshake + tunnel tests |
| `pqanon` CLI (`keygen`, `selftest`, `run`) | Rust | **Working** | `pqanon selftest` |
| `pqanond` tunnel daemon (UDP handshake responder + echo) | Rust | **Working** | `tests/tunnel.rs` over real UDP |
| `pqanon-mixd` mix node (peels + forwards onion cells) | Rust | **Working** | mix round-trip tests |
| Control plane `PQANON-CP/1` (auth, nodes, connections, CRL) | Go | **Working** | `go test`, live curl |
| Web UI (dashboard, connections, routing, login) | Next.js/TS | **Working** | `next build`, `tsc` |
| Postgres schema + in-memory fallback | SQL/Go | **Working** | boots with or without a DB |

Everything above compiles and its tests pass. See **Known limitations** for the
integration work that remains (TUN plumbing, delay queue, cover-traffic driver).

## Layout

```
client/         Rust core library (lib "pqanon") + `pqanon` CLI binary
server/         Rust daemons: pqanond (tunnel) + pqanon-mixd (mix node)
control-plane/  Go REST API (PQANON-CP/1): auth, nodes, connections, CRL
db/             PostgreSQL schema (§15)
web-ui/         Next.js dashboard
examples/       Example server.toml / client.toml
scripts/        dpi-smoke.sh, run-local.sh
```

## Quick start

```bash
# 1. Build + test everything
make test            # cargo test  +  go vet/test
make build           # release binaries + control plane + web build

# 2. Prove the whole crypto/transport/obfuscation stack end to end
./target/release/pqanon selftest
#  → handshake OK (both sides derive identical keys)
#  → DATA packet sealed → morphed → demorphed → opened OK
#  → PQAN magic absent on the wire

# 3. Generate a long-term identity
./target/release/pqanon keygen

# 4. Run the control plane + daemons locally
./scripts/run-local.sh
curl localhost:8080/health

# 5. Or bring up the full stack in containers
docker compose up --build
#  web UI → http://localhost:3000   control plane → http://localhost:8080
```

### Web UI dev

```bash
cd web-ui && npm install && npm run dev   # http://localhost:3000
```

## Protocol summary

- **PQANON-HS/1 handshake** — 3-message mutually-authenticated handshake. The
  session secret `ss_mix` is derived from **both** ML-KEM-768 and X25519, so
  breaking either alone is insufficient. Both sides sign the transcript with
  long-term ML-DSA-65 **and** Ed25519 keys. The client's long-term verifying
  keys travel inside the obfuscated CLIENT_FINISH, so the server authenticates
  against a pinned `identity_id` set with no identifier ever in cleartext.
- **PQANON/1 envelope** — 22-byte header bound as AEAD associated data; any
  tamper with `epoch/conn_id/seq/type/length` breaks authentication. Nonces are
  deterministic (`epoch||seq`) and never repeat within an epoch; directional
  keys separate the two directions.
- **PQANON-OBF/1 obfuscation** — per-epoch morph key XORs + Fisher-Yates
  permutes the header, a random prefix and length-shaping padding hide size and
  structure; identical plaintext yields different wire bytes and the `PQAN`
  magic never appears on the wire.
- **PQANON-MIX/1 mixnet** — fixed-size 2048-byte onion cells; each hop peels one
  X25519 + ChaCha20-Poly1305 layer and learns only the next hop. Verified by a
  5-hop wrap → peel → deliver round-trip.
- **PQANON-UDP/1 transport** — anti-replay sliding window, EWMA RTT/RTO, and a
  custom BBR-inspired congestion controller (all unit-tested).

## Improvements / deviations from the v1.0 design doc

The spec's listings were a scaffold; making them *run* required fixes. None
remove functionality — they correct or complete it:

1. **`obf.rs` was invalid Rust** (`...region as u8 with`) with a non-reversible
   length scheme. Rewritten to a correct, reversible morph/demorph with an
   explicit 2-byte length field, header XOR **and** the Fisher-Yates header
   permutation the doc describes. Round-trip + "magic-not-on-wire" tested.
2. **Server-side handshake implemented.** The doc gave only the client half;
   `ServerHandshake` (and the client's `recv`/`finish`) now complete a real,
   mutually-authenticated handshake that both sides can run.
3. **Mix cells actually peel.** The doc's cell builder didn't round-trip;
   `mix.rs` now defines a concrete reversible onion that keeps the fixed 2048-byte
   cell at every hop.
4. **Control plane is functional, not stubbed** — real Argon2id (m=64 MiB, t=3,
   p=4), EdDSA bearer tokens, a signed CRL, and a storage interface with both an
   in-memory store (boots with no DB) and a Postgres store.
5. **Routing glob fixed** — `*.journalist.org` no longer matches
   `notjournalist.org`.
6. **Next.js bumped to a patched 14.2.x** (the pinned version had a published
   advisory) and wired to the control plane with login/token handling.

## Known limitations (the remaining integration work, per §19)

These are deliberately not yet wired; the library primitives they build on are
done and tested:

- TUN read/write loop on both ends; `pqanon run` binds transport but does not yet
  forward IP.
- Handshake messages are currently plain-framed (not morphed): the morph key
  derives from `ss_mix`, which doesn't exist until the handshake completes. A
  bootstrap morph key (from the pinned server key) is the intended fix.
- Large (~7 KB) handshake messages need UDP fragmentation for real paths.
- Not yet implemented: the stateless cookie/anti-probing path (§10), the mix
  delay queue + Bloom replay filter (§10.5), the cover-traffic rate controller
  (§9.4), rekey driver (§6.5), and connection migration (§8.6).

**This is pre-audit software.** Do not place real high-risk traffic on it until
the integration work above is complete and it has had an external review.

## License

MIT OR Apache-2.0. No code from WireGuard, Nym, OpenVPN, TLS, or QUIC.
