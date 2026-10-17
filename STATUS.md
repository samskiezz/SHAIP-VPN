# SHAIP-VPN — honest build status

Last audited: 2026-10-16. This file is the single source of truth for what is
real, what is written-but-unverified, and what does not exist. If any other
doc disagrees with this one, this one is right. No marketing.

## The two things that are NOT done, and why they need you

These are not code defects. They are steps that require hardware and accounts
this build environment (a Linux container) does not have:

1. **There is no installable iPhone app.** Apple only lets iOS apps be compiled
   on **macOS with Xcode**. The app's SwiftUI, Network Extension, and Live
   Activity code (19 files) has therefore **never been compiled** — it is
   written and reviewed, not built. The first real compile must happen on a Mac.
   This is the honest reason the only thing clickable so far is a browser
   preview, and why it can feel "fake": there is no `.ipa` yet. (This limit is
   iOS-only. The **Android** app in `clients/android` does build here, on
   Linux, to a real APK — Android needs no Apple toolchain. See the table
   below.)

2. **There is no server running on the internet.** The VPN server, the account
   service, and the web dashboard all build and run, and are proven end to end
   in a local network lab — but nothing is deployed to a public host, so a phone
   has nothing to connect to yet. Standing one up is a deliberate, ~30-minute
   step (below).

Everything else below is real.

## What is real and proven (reproduced on 2026-10-16)

| Component | Status | How it is verified |
|---|---|---|
| PQ crypto + handshake (ML-KEM-768 + X25519, ML-DSA-65 + Ed25519, ChaCha20-Poly1305) | **Real** | `cargo test` (148 lib tests), `selftest` |
| Wire obfuscation (OBF/2: per-packet header masking, boot-layer handshake) | **Real** | unit tests + the netns lab captures the wire: 0 fragments, 0 magic, no fixed bytes across a flow |
| Anti-DoS retry cookie (address validation under load) | **Real** | `client/src/retry.rs` unit tests + server core test |
| The IPv4 VPN tunnel end to end (TUN device, egress NAT, DNS forwarder, kill switch, reconnect) | **Real** | `scripts/e2e/vpn_lab.sh` — 47 checks, incl. a 16 MiB download byte-identical through the tunnel |
| Go control plane: anonymous accounts, devices, API keys, node directory, staking/slashing, unlinkable payments, enrollment, signed CRL | **Real** | `go test` + live curl (register → login → API key → auth → delete; times day-coarsened) |
| Privacy posture (no IP/connection logs, day-only timestamps, log redaction, account deletion) | **Real** | privacy tests in Rust + Go; the netns lab asserts no client data in server logs |
| Web account dashboard | **Real** | `tsc --noEmit` + `next build` |
| Discount / comp codes (operator-issued free or promo access, incl. a test pass) | **Real** | Go store-contract + handler tests; claimed in the browser sandbox |
| Servers screen from the signed node directory (web) | **Real** | lists real nodes; sandbox registers one and sees it appear |
| Web product end to end, clicked in a browser (register → dashboard → devices → redeem a code → delete account, plus the safety gates) | **Real** | `web-ui/e2e/run.sh` — 11/11 checks against the real control plane |
| iOS **core logic** (config parsing, telemetry, render engine) | **Real** | `swift test` (13 tests) — builds on Linux, Foundation-only |
| iOS ↔ Rust boundary (the app's FFI Swift against a live `pqanond`) | **Real** | `clients/ios/FFIInterop` runs in the battery on Linux |
| **Android app** (Kotlin + Jetpack Compose, same glass design; login, dashboard, Servers directory, devices, buy-access + code redeem; wired to the real control plane) | **Real — builds to an APK on Linux** | `cd clients/android && ./gradlew assembleDebug` → `app-debug.apk` (no macOS needed) |
| Android VpnService (owns the TUN + connection lifecycle) | **Real skeleton** | `clients/android/.../vpn/PqanonVpnService.kt`; PQ data plane bridges the Rust core over JNI next (does not black-hole traffic until then) |
| **Desktop app** (Rust + egui, same glass design; login, dashboard, Servers, Buy access + code redeem; wired to the real control plane) | **Real — cross-builds to Linux + Windows from Linux** | `cd clients/desktop && cargo build --release` (Linux ELF) and `--target x86_64-pc-windows-gnu` (Windows PE32+ GUI .exe); screens rendered headless under Xvfb |
| Desktop tunnel control | **Real control surface** | drives the local `pqanon` engine (shared Rust core); honest when the engine isn't installed |
| Full battery | **16 stages, 0 failed** | `scripts/test-all.sh` |

## What is written but UNVERIFIED (needs a Mac to compile)

The actual iPhone app UI and system integration. These are reviewed and
`swiftc -parse`-clean but have **no compilation anywhere**: `clients/ios/SHAIP/*`
(the 6 screens, the store, the design system), `clients/ios/SHAIPTunnel/*` (the
Network Extension packet pumps), `clients/ios/SHAIPWidgets/*` and
`clients/ios/Shared/TunnelActivity.swift` (the Live Activity). Correctness here
is asserted by review only until Xcode builds it.

## Design spec (HANDOFF.md, 10 screens) vs what exists

The app ships **5 honest screens + Setup**. Of the 10 spec screens, 4 are real,
2 were renamed to match reality, and **5 are UI mockups with no backend at all.**
Building those 5 "to spec" would require fabricating data — which is forbidden.
They are a product decision, not an engineering task:

| Spec screen | Status | Real backing? |
|---|---|---|
| Connect | **Built** (needs Mac) | Yes — real tunnel state and measured throughput |
| Traffic | **Built** (needs Mac) | Yes — measured byte/packet counters |
| Lock screen (Live Activity) | **Built** (needs Mac) | Yes — but shows no server/city (privacy) |
| Onboarding → **Setup** | **Built** (needs Mac) | Real config import. SSO/passkey/SOC2/ISO/FIPS: **no backend, cut** |
| Protocol → folded into **Settings** | **Built** (needs Mac) | Only PQANON/1 exists. WireGuard/IKEv2: **do not exist** |
| Security (kill switch half) | **Built** (needs Mac) | Kill switch real; threat radar / "1,284 threats": **no backend** |
| Network globe / Nodes | **Real on web** (globe art cut) | A real **Servers** page now lists the signed node directory (region, role, capacity, stake, status). The *globe animation* and per-node exit-IPs/loads/RTT sparklines remain unbuilt — no real source. |
| Zero-trust Access (trust score, CrowdStrike, MFA grants) | **Cut** | **No backend whatsoever** |
| Team & plan (seats, roster, "Acme Corp / Maya Chen") | **Cut** | Anonymous access plans are real; seats/team/SSO: **no backend** |

To make any cut screen real, the underlying feature has to be built first
(a threat-intel pipeline, a zero-trust policy engine, a team/seat model, a
second VPN protocol). Each is a real project. Say which ones matter and they go
on the roadmap; none will be faked.

## Protocol limitations (accurate today)

- **One hop, no mixnet in the data path.** The mix daemon exists and is tested
  standalone; the tunnel does not route through it. No traffic-analysis defence.
- **Recognizable to key-holders.** Without the server's keys every packet is
  random bytes; anyone holding a client config for that server can recognize its
  handshakes.
- **Single-threaded server data path** (~450 Mbit/s/core in the lab).
- **IPv4 only inside the tunnel; IPv6 blocked, not carried.**
- **Roaming = reconnect** (tunnel IP preserved, so TCP usually survives).
- **Not independently audited.** Pre-release software.

## The shortest path to a working product

1. **Stand up one server** (any Linux host, ~30 min): `docker compose up -d`
   brings up the control plane, the web dashboard, Postgres, and `pqanond`
   (see `docker-compose.yml`). Run `pqanond --identity … --print-public` to get
   the `[server]` block for clients. Terminate TLS in front with logging off.
2. **Free access for testing or promos.** Set `COMP_CODES="MYCODE:pro:365:50"` on the
   control plane (or `POST /api/admin/comp-codes` as an admin) and redeem the code on
   the web pay page's "Have a code?" box, or `POST /api/pay/claim-code`. It grants a real
   access token without a crypto payment — a legitimate coupon, not a backdoor. For CI,
   `PAY_DEV_SETTLE=1` settles a normal order without a chain.
3. **Build the app on a Mac** (Xcode 26): `cd clients/ios && brew install xcodegen
   && ./scripts/build-ffi.sh && xcodegen generate && open SHAIP.xcodeproj`. A
   Network Extension needs an Apple Developer account and signing. Install on a
   device via Xcode or TestFlight (packet tunnels don't run in the Simulator).
4. **Point the app at the server** — import the `[server]` block. It connects to
   the real tunnel; every number on screen then comes from that tunnel.

Until step 1 and step 2 are done by someone with a Linux host and a Mac, there
is no app on a phone and no live service — not because the code isn't there, but
because this environment cannot produce either.
