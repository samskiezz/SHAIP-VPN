# SHAIP VPN — Post-Quantum Anonymizing VPN Stack

> **[STATUS.md](STATUS.md) is the honest, no-spin build status** — what is real
> and proven, what is written but needs a Mac to compile, what was deliberately
> cut rather than faked, and the exact path to a working app and server. Read it
> first.

A from-scratch VPN stack implementing **SHAIP/1**: a hybrid post-quantum
handshake, a custom obfuscated UDP transport, a fixed-size onion mixnet, a REST
control plane, and a web dashboard. Every wire format and cryptographic
composition is defined in-house; only standard RustCrypto / Go stdlib primitives
are used as building blocks (ML-KEM-768, ML-DSA-65, X25519, Ed25519,
ChaCha20-Poly1305, HKDF/HMAC-SHA256, Argon2id).

> Built for defensive use. The aims: a VPN whose key exchange holds up against a
> future quantum computer, whose traffic is hard to fingerprint, and whose app
> tells its users the truth about what it protects. See
> [What it protects, and what it doesn't](#what-it-protects-and-what-it-doesnt).

## Status — what actually runs today

| Component | Language | State | Verified by |
|-----------|----------|-------|-------------|
| `pqanon` client lib (`wire`, `handshake`, `obf`, `transport`, `mix`, `routing`, `kdf`) | Rust | **Working** | 25 unit tests |
| Full hybrid handshake (client **and** server sides) | Rust | **Working** | handshake + tunnel tests |
| **The VPN, end to end**: `pqanon run` (full tunnel: routes, DNS, IPv6 block, optional kill switch, reconnect, rekey) ↔ `pqanond --tun --nat` (NAT, DNS forwarder, per-client addresses, keepalive, anti-spoofing) | Rust | **Working** | 4-namespace lab, 41 checks: traffic and DNS leave only from the server, 16 MiB intact, survives server restart and crash, kill switch holds after a client crash, the server's logs hold no address or client identity, a disconnected client's NAT state is deleted ([scripts/e2e/vpn_lab.sh](scripts/e2e/vpn_lab.sh)) |
| `pqanon` CLI (`keygen`, `selftest`, `run`, `status`, `disconnect`, `down`, `probe`, `enroll`, `crl`) | Rust | **Working** | `pqanon selftest` + battery E2E stages |
| `pqanon::supervisor` reconnecting link + `pqanon-ffi` C ABI for native shells | Rust + C | **Working** | restart/crash/hang/rekey test vs real `pqanond`; C and Swift programs against a live server ([docs/client-api.md](docs/client-api.md)) |
| `pqanond` session core: one session per identity, stable addresses, idempotent handshake retransmits, idle expiry, Close on shutdown | Rust | **Working** | unit tests with real handshakes + the lab |
| `pqanon-mixd` mix node (peels + forwards onion cells) | Rust | **Working, standalone** | mix round-trip tests. The tunnel does **not** route through mixes yet. |
| Control plane `SHAIP-CP/1` (anonymous accounts, devices, nodes, payments, CRL): no email, no request log, no stored addresses | Go | **Working** | `go test` incl. privacy tests (no address, id or path in any log line or stored record), live curl |
| Web UI (account-number sign-up, dashboard, devices, buy access, delete account) | Next.js/TS | **Working** | `next build`, `tsc`, a browser run with no third-party requests |
| iOS app: a Packet Tunnel extension running the Rust core; screens show only measured state and state the limits (`clients/ios`) | SwiftUI + Rust | **Written** (needs an Xcode 26 build) | the app's FFI Swift run against a live `pqanond` on Linux; Rust core clippy-clean for `aarch64-apple-ios`; `SHAIPCore` tests ([clients/ios/README.md](clients/ios/README.md)) |
| Postgres schema + in-memory fallback | SQL/Go | **Working** | one store contract run against both, incl. real PostgreSQL |
| Signing-key custody: key files + **PKCS#11 HSM**; persistent daemon identities | Go + Rust | **Working** | real SoftHSM2 token + restart checks ([docs/keys.md](docs/keys.md)) |
| One-click device enrollment (`/api/enroll`, `pqanon enroll`) + device-cert tunnel admission + CRL revocation | Go + Rust | **Working** | cross-language enroll E2E + handshake tests ([docs/enrollment.md](docs/enrollment.md)) |
| Node staking: paid bonds, unbonding, permissionless slashing on signed-descriptor equivocation, stake-gated signed directory | Go + Rust | **Working** | store contract (real PostgreSQL) + cross-language stake E2E ([docs/staking.md](docs/staking.md)) |
| DNSSEC resolver: RSA/ECDSA/Ed25519 RRSIG + chain-of-trust + real IANA root anchors | Rust | **Working** | 19 unit tests + live anchor check |
| Unlinkable-token payments: Monero + Bitcoin/Lightning + Chaumian e-cash (`buy`/`collect`/`redeem`) | Rust + Go | **Working** | cross-language buy→redeem E2E |
| Live TLS 1.3 decoy (`pqanon-decoy`, `pqanond --decoy`) | Rust | **Working** | openssl/curl + 2 integration tests |
| Monitoring: Prometheus `/metrics` + Grafana/Alertmanager (`docker compose up`) | Go + Rust | **Working** | metrics tests + live scrape |

Everything above compiles and its tests pass. See **Known limitations** for what
remains.

## What it protects, and what it doesn't

With `pqanon run` (or the iOS app) connected:

- **Your traffic is encrypted to the server.** Every IPv4 packet goes through the
  tunnel, sealed with ChaCha20-Poly1305 under keys from a hybrid ML-KEM-768 +
  X25519 handshake. The session key depends on both, so a future quantum
  computer that breaks X25519 would still have to break ML-KEM-768 to read
  traffic recorded today. Keys are replaced every 20 minutes.
- **The server is authenticated.** It must prove it holds the pinned ML-DSA-65
  and Ed25519 keys, or the client refuses it.
- **DNS goes through the tunnel**, to the server's resolver, not your network's.
- **IPv6 is blocked** while connected (the tunnel carries IPv4 only).
- **With the kill switch**, nothing leaves outside the tunnel, even if the
  client crashes, until it reconnects or you run `pqanon down`.

What it keeps about you: **nothing that identifies you.**

- **No identity.** An account is a random account number and a password; there
  is no email, name or phone number, and you can pay without an account.
- **No logs of you.** No server logs a client's IP address, identity, device or
  tunnel address, or a line per session, and there is no option that turns it
  on. Every server log line also passes through an address filter. The control
  plane has no request log and stores no address.
- **No usage records.** Nothing records when you connected, for how long, how
  much you sent, where it went or what you looked up. Account records keep the
  day, not the moment.
- **Nothing on your phone's lock screen or in its backups**: no server or
  address on the Live Activity, and device keys stay out of iCloud backups.
- **Delete your account** at any time; everything stored about it goes.

What the server necessarily sees while you're connected (your address, where
your traffic goes) is held in memory for the session only. The full list of
what is and isn't kept: [docs/privacy-policy.md](docs/privacy-policy.md).

What it does **not** do:

- **Hide your traffic from the VPN server.** The server sees where your traffic
  goes, as any VPN operator does. A VPN moves that visibility away from your
  local network and ISP; it doesn't remove it.
- **Defeat traffic analysis.** There is one hop and no mixnet in the data path,
  so someone watching both sides of the server can match flows by timing.
- **Hide that you use it from everyone.** To anyone without your server's
  public keys, every packet is random bytes: no fixed header, no protocol
  magic, no handshake to match. But sizes and timing are shaped, not hidden, so
  traffic analysis can still suggest an encrypted tunnel; a network that blocks
  UDP it can't identify blocks this too; and anyone who has the server's public
  keys (every client config for it carries them) can recognize its handshakes.
- **Make you anonymous to websites.** Logins, cookies and browser fingerprinting
  still identify you.
- **Filter content.** It does no ad, tracker or malware blocking.
- **Come audited.** It is pre-audit software (see the end of this file).

## Payments — the token is unlinkable to the payment

No cards, no fiat, no identity. Access is bought with **Monero** (or Bitcoin) and
redeemed through **Chaumian e-cash** (RFC 9474 RSA blind signatures). The mint
blind-signs your access tokens without ever seeing them, so a redeemed token
carries nothing that links it to the order that paid for it, and a redemption
records only a hash of the token and the day. That covers the token only. Timing and
network addresses can still suggest a link, for example if you buy and connect
from the same network. A Bitcoin payment is public on-chain.

```bash
pqanon plans   --server <cp-url>                 # day / week / month / quarter, priced in XMR
pqanon buy     --plan month --server <cp-url>    # prints a one-time Monero address
pqanon collect --order <id>  --server <cp-url>   # unblinds tokens once the payment confirms
pqanon redeem  --plan month  --server <cp-url>   # → a VPN access grant, unlinkable to payment
```

Full design, crypto choices, and threat model, including those limits:
**[docs/payments.md](docs/payments.md)**.

## Layout

```
client/         Rust core library (lib "pqanon") + `pqanon` CLI binary
server/         Rust daemons: pqanond (tunnel) + pqanon-mixd (mix node)
control-plane/  Go REST API (SHAIP-CP/1): anonymous accounts, devices, nodes, payments, CRL
db/             PostgreSQL schema (§15)
web-ui/         Next.js dashboard
clients/ios/    SwiftUI iOS app (SHAIP v2 design), SHAIPCore package, design reference
examples/       client.toml (CLI and iOS app) and pqanond.service (a production server unit)
scripts/        test-all.sh (the battery), e2e/vpn_lab.sh (the 4-namespace VPN lab), dpi-smoke.sh, run-local.sh
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

# 3. Generate persistent long-term identities (created 0600; see docs/keys.md)
./target/release/pqanon keygen --out ~/.pqanon/client.id
./target/release/pqanond --identity /var/lib/pqanon/pqanond.id --print-public
#  → identity_id / server_ml_dsa_pub / server_ed_pub: paste into the client's [server]

# 4. A real VPN. On the server (Linux, root): TUN, NAT out of eth0, DNS forwarder
./target/release/pqanond --identity /var/lib/pqanon/pqanond.id --listen 0.0.0.0:443 \
    --tun pqanon0 --nat eth0
#    On the client: put the server's address and --print-public pins in a client.toml
sudo ./target/release/pqanon run --config client.toml            # kill switch enabled by default
./target/release/pqanon status                                   # state, RTT, counters
./target/release/pqanon disconnect                               # routes and DNS restored

# 5. Run the control plane + daemons locally
./scripts/run-local.sh
curl localhost:8080/health

# 6. Or bring up the full stack in containers
docker compose up --build
#  web UI → http://localhost:3000   control plane → http://localhost:8080
```

### Web UI dev

```bash
cd web-ui && npm install && npm run dev   # http://localhost:3000
```

### Hosted web preview (no server needed)

`web-ui/preview/build.sh` packages the real web app into one static page: the
same React pages, with the real control plane compiled to WebAssembly
(`control-plane/wasm_main.go`) running in the visitor's browser tab with the
in-memory store and nothing seeded. Sign-up, devices, plans and account
deletion work on the real code; nothing leaves the tab, and its accounts are
gone on reload. The VPN connection and payments need the real servers.

```bash
cd web-ui && npm install && ./preview/build.sh   # → preview/dist/{index.html,pqanon-cp.wasm}
```

### iPhone app preview (in a browser)

`clients/ios/preview/build.sh` builds the SHAIP iPhone app's screens as one
self-contained page: Setup, Connect, Traffic, Protection, Server, Settings and
the lock-screen Live Activity, with the v2 design's glass and the live 3-D mesh
drawn by `clients/ios/design/shaip-engine.js` itself (the file the iPhone
renderer is tested against). Config import uses the app's own parsing rules.
A web page can't open a VPN tunnel, so connecting there runs a simulated
session inside the page, and the page says so; nothing is stored or sent.

```bash
clients/ios/preview/build.sh   # → clients/ios/preview/dist/index.html
```

## Protocol summary

- **SHAIP-HS/1 handshake** — 3-message mutually-authenticated handshake. The
  session secret `ss_mix` is derived from **both** ML-KEM-768 and X25519, so
  breaking either alone is insufficient. Both sides sign the transcript with
  long-term ML-DSA-65 **and** Ed25519 keys. The client's long-term verifying
  keys (and its device certificate, for a device-bound server) travel inside
  CLIENT_FINISH, AEAD-sealed under a key derived from `ss_mix`, so the server
  authenticates against a pinned `identity_id` set or an enrolled device
  certificate with no identifier ever in cleartext (regression-tested on the
  wire bytes).
- **SHAIP/1 envelope** — 22-byte header bound as AEAD associated data; any
  tamper with `epoch/conn_id/seq/type/length` breaks authentication. Nonces are
  deterministic (`epoch||seq`); a session refuses to seal past
  `REJECT_AFTER_SEQ` rather than wrap, and clients rekey with a fresh handshake
  long before (every 20 minutes or 2³⁰ packets). Directional keys separate the
  two directions.
- **SHAIP-OBF/2 wire layer** (`client/src/obf.rs`) — every datagram is random
  bytes to anyone without the keys. Session packets: the 22-byte header is
  masked with a ChaCha20 keystream chosen by a sample of the ciphertext under a
  per-session key (QUIC's header protection, RFC 9001 §5.4), then padded to a
  shaped size plus random jitter. Handshake messages: split into fragments, each
  sealed with ChaCha20-Poly1305 under a key derived from the server's pinned
  public keys, in its own 1200-byte datagram, so nothing depends on IP
  fragmentation. The server never answers a datagram it can't open. The netns
  lab checks the real wire: no IP fragments, no protocol magic, and no byte
  position holding a fixed value across a flow's packets.
- **Session control** — keepalive PING/PONG (the RTT clients show) and Close,
  sealed and padded like data, so they look like any other small packet.
- **SHAIP-MIX/1 mixnet** — fixed-size 2048-byte onion cells; each hop peels one
  X25519 + ChaCha20-Poly1305 layer and learns only the next hop. Verified by a
  5-hop wrap → peel → deliver round-trip. Standalone: the tunnel doesn't use it
  yet.
- **SHAIP-UDP/1 transport** — anti-replay sliding window, EWMA RTT/RTO, and a
  custom BBR-inspired congestion controller (all unit-tested).

## Improvements / deviations from the v1.0 design doc

The spec's listings were a scaffold; making them *run* required fixes. None
remove functionality — they correct or complete it:

1. **`obf.rs` was invalid Rust** (`...region as u8 with`) with a non-reversible
   length scheme. Rewritten to a correct, reversible morph/demorph with an
   explicit 2-byte length field, header XOR **and** the Fisher-Yates header
   permutation the doc describes. Round-trip + "magic-not-on-wire" tested.
   That design (OBF/1) has since been replaced by OBF/2: its header XOR used
   one key per session, so 16 of the 22 header bytes were identical in every
   packet of a flow, and the first byte said where they started.
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

## Known limitations

- **No mixnet in the data path.** `pqanon-mixd` peels and forwards onion cells,
  but the tunnel goes straight to one server, and `pqanon run --route anon`
  refuses rather than pretending. The cover-traffic rate controller (§9.4) and
  the mix delay queue (§10.5) aren't wired in either.
- **Recognizable to anyone with the server's keys.** Handshakes are sealed
  under a key derived from the server's public keys, which every client config
  for that server carries, so a censor who obtains one can recognize that
  server's handshakes. Without the keys the packets are random bytes, but their
  sizes and timing are shaped, not hidden, and "UDP that parses as nothing" is
  itself a signal that some networks block.
- **Handshake cost under attack.** Before a client has proved its address, the
  server sends it at most three times what it received (every CLIENT_HELLO is
  padded to two datagrams for this), and it never answers a datagram it can't
  open, so it can't be used as an amplifier. Once its half-open table is full,
  an unvalidated CLIENT_HELLO gets a **stateless retry cookie** instead of a
  signature (`client/src/retry.rs`, QUIC/DTLS-style address validation): a
  spoofed source, which never receives the cookie, can no longer cost the
  server its ML-KEM + ML-DSA work. A sender that echoes a valid cookie has
  proved its address and is admitted. A flood from *real* addresses that can
  complete this is still bounded only by the half-open cap (no global rate
  limiter yet), and the mix delay queue remains unwired.
- **IPv4 inside the tunnel only.** IPv6 is blocked while connected, not carried.
- **Roaming is a reconnect.** A client whose address changes renegotiates (at once
  on iOS, after the dead-peer timeout on Linux). It keeps its tunnel address, so
  connections usually survive, but there is no seamless connection migration (§8.6).
- **Single-threaded data path on the server** (about 450 Mbit/s through the lab on
  one core).

**This is pre-audit software.** Do not place real high-risk traffic on it until
the integration work above is complete and it has had an external review.

## License

MIT OR Apache-2.0. No code from WireGuard, Nym, OpenVPN, TLS, or QUIC.
