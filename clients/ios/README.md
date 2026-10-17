# SHAIP — iOS app

The SHAIP VPN for iPhone: SwiftUI on the iOS 26 SDK with the v2 design (Liquid Glass, the native
floating tab bar, live 3-D scenes), a **Packet Tunnel extension that runs the real SHAIP VPN client**,
and a Live Activity with Dynamic Island layouts.

**Nothing in the app is simulated.** Connection state is iOS's own (`NEVPNStatus`). Every number
about the session (speed, round-trip time, tunnel address, resolver, byte and packet counts,
reconnects, rekeys, the server's proven identity) comes from the tunnel extension, which reads it
from the Rust core carrying the traffic. If a value isn't known, the app shows a dash.

## How it works

```
SHAIP app ──NETunnelProviderManager──▶ SHAIPTunnel (NEPacketTunnelProvider)
   ▲  status JSON once a second               │  shaip_session_* (ffi/include/shaip.h)
   └──────────sendProviderMessage─────────────┤
                                              ▼
                                Rust core (shaip-ffi → shaip::supervisor)
                                SHAIP/1 over UDP ──▶ shaipd (--tun --nat)
```

- **The tunnel** is `shaip::supervisor::ManagedTunnel`, the same code `shaip run` uses on Linux:
  a hybrid ML-KEM-768 + X25519 handshake authenticated with ML-DSA-65 + Ed25519, then
  ChaCha20-Poly1305 traffic. It sends keepalives (the source of the RTT), detects a dead server,
  reconnects with backoff, and rekeys with a fresh handshake every 20 minutes.
- **Routing.** All IPv4 goes into the tunnel. DNS uses the resolver the server pushes, for every
  domain. The tunnel carries IPv4 only, so the extension also claims IPv6 and drops it rather than
  letting it go around the tunnel. MTU 1370, so sealed packets never fragment.
- **Network changes.** When the phone changes networks, the extension renegotiates at once
  (`shaip_session_reconnect`) instead of waiting for the dead-peer timer.
- **Kill switch** is iOS's `includeAllNetworks`. **Connect automatically** is an on-demand rule.
  Both are real VPN settings, saved to the system configuration.
- **Enrollment.** For servers that admit enrolled devices only, the app enrolls with a
  `shaip://enroll` link: `shaip_enroll` proves possession of this device's identity key and
  stores the certificate in the App Group container, where the extension finds it.

## What the app keeps to itself

The app collects nothing about the person using it and has no analytics, crash reporting or
third-party SDKs: it talks to the VPN server, and to the control plane only to enroll.

- **Enrollment sends no device name.** Only "iPhone" or "iPad" goes to the control plane, never
  the phone's name (often "Alex's iPhone"); the Rust core reduces any name to a platform label
  as well.
- **The lock screen shows no server.** The Live Activity and Dynamic Island say whether the VPN
  is on, for how long, and how fast. Not which server, its address or the tunnel address:
  anyone holding the phone can read a lock screen.
- **The app-switcher snapshot is covered.** iOS saves a picture of the screen as the app leaves
  the foreground; the app (and every sheet) shows a plain cover then, so the snapshot holds no
  server, fingerprint or address.
- **System logs are private.** The tunnel extension logs only that the tunnel came up or why it
  failed, with the details marked `.private`, so they are redacted from diagnostics reports.
- **Keys stay on this phone.** The device identity and certificate are excluded from iCloud and
  computer backups and readable only after the first unlock. A restored or new phone enrolls
  again rather than inheriting this one's keys.

## Screens

| Tab | What it shows |
|-----|---------------|
| Connect | The orb (connect/disconnect), the session card (state, timer, server, tunnel IP, measured DOWN/UP/RTT/DATA), kill switch, auto-connect, and where DNS goes. |
| Traffic | Throughput chart (48 s of measured samples), bytes and packets, and the tunnel's health counters: reconnects, rekeys, rejected packets, packets held while reconnecting, IPv6 blocked. |
| Protection | What is protecting this iPhone right now, from real state only, and next to it what this VPN does **not** do. |
| Server | The configured server, the identity the handshake proved, this device's enrollment, and replace/remove. |
| Settings | SHAIP/1 and what it uses, kill switch, auto-connect, the tunnel's real parameters, and versions. |

The first run shows **Setup**: import the client config the server's operator hands out. It's the
same `client.toml` the `shaip` CLI reads (`[server]` address and pins, plus an optional `[enroll]`
table). The app has nothing else to show until a real server is configured.

### What was removed from the v2 design, and why

The design handoff's sample content was illustrative, and some of it described things this
product doesn't do. Showing it to customers would have been false, so it's gone:

- Invented nodes (SYD-03, TYO-04…), exit IPs, loads, globe routes and node HUD labels.
- WireGuard and IKEv2 options, multi-hop, and "Private DNS · FILTERING". None of these exist.
- The threat radar, "1,284 threats", "C2 beacon blocked" alerts, and "Your admin has been notified".
- Zero-trust Access, MFA step-up, the device posture checks and the trust score.
- The team, seats and plan, the workspace, the SSO and passkey sign-in, and the
  "SOC 2 / ISO 27001 / FIPS 140-3" badges. The product holds none of those certifications.

The visual design stays: tokens, glass, typography, the orb, the cards and the mesh scene. The mesh
is now ambient art with no labels. The globe and radar engines remain in SHAIPCore (still verified
against the reference) but the app doesn't use them.

## Try the screens in a browser

`preview/build.sh` builds these screens as a single web page (`preview/dist/index.html`), with the same
copy, glass recipe and live mesh, drawn by `design/shaip-engine.js` itself. A web page can't open a VPN
tunnel, so connecting there plays a simulated session, and the page says so on screen. It is for
looking at and clicking through the app before a Mac build exists; the numbers in the real app come
from the tunnel.

## Build

On a **Mac with Xcode 26** and [rustup](https://rustup.rs):

```bash
cd clients/ios
brew install xcodegen          # once
./scripts/build-ffi.sh         # Rust core → Frameworks/ShaipFFI.xcframework (device + simulator)
xcodegen generate              # writes SHAIP.xcodeproj from project.yml
open SHAIP.xcodeproj
```

The tunnel target re-runs `build-ffi.sh` as a pre-build phase, and cargo rebuilds only what changed.
A Network Extension needs signing: set `DEVELOPMENT_TEAM` in `project.yml` (or under Signing &
Capabilities), with the **Network Extensions** (packet tunnel) and **App Groups**
(`group.com.shaip.vpn`) capabilities on your App ID. Packet tunnels don't run in the iOS
Simulator, so the tunnel needs a device. The app's screens do run in the Simulator.

You need a server: `shaipd --identity … --tun shaip0 --nat <egress-if>` on a Linux host. Then
give the iPhone the `[server]` block from `shaipd --identity … --print-public`.

## Verification

What has been checked, and how:

- **The VPN itself, end to end** (`scripts/e2e/vpn_lab.sh`, a battery stage). Four network
  namespaces: a client, an ISP router, `shaipd` with NAT, and an "internet" host. The client runs
  the same Rust core the extension runs. 36 checks, including:
  - the web host sees only the server's address, and lookups never reach the ISP's resolver;
  - 16 MiB arrives byte-identical;
  - the session comes back after a server restart and after a crash;
  - the kill switch blocks traffic after a client crash.
- **Swift ↔ Rust boundary** (`FFIInterop/`, in the battery's iOS stage). The app's own `FFI/*.swift`
  files are compiled with Swift against `shaip.h` and its module map, linked with the Rust static
  library, and run against a live `shaipd` in the extension's call order:
  - start, status, server address;
  - send (from `Data`) and receive (into a buffer);
  - snapshot and JSON round trip, including that the server identity matches `shaipd`'s
    `identity_id` byte for byte;
  - reconnect, stop (receive returns -1), and free.
- **The C ABI** (`ffi/tests/smoke.c`, battery): the session API, a forced reconnect and RTT, from C.
- **The Rust core for iOS.** `cargo clippy -p shaip-ffi --target aarch64-apple-ios -D warnings` is
  clean. The final link needs Apple's SDK, so `build-ffi.sh` runs on a Mac.
- **SHAIPCore** (`swift test`, 13 tests):
  - config parsing and validation, including the CLI's own file format;
  - the snapshot's JSON round trip;
  - rates computed from real byte deltas (and none from a counter reset);
  - formatting;
  - that the Protection report only claims what the current state supports, and contains no
    absolute claims such as "untraceable", "anonymous" or "can't be hacked";
  - the render engines, which reproduce `design/shaip-engine.js` op for op.
- **Project spec.** `xcodegen generate` produces the three targets, the entitlements, the
  XCFramework link and the build phase.
- **Not yet verified:** the SwiftUI, NetworkExtension, ActivityKit and WidgetKit code needs the
  iOS 26 SDK, so it has only been syntax-checked (`swiftc -parse`, all files) and reviewed. The
  first full compile happens in Xcode on a Mac; report anything it flags.

## Layout

| Path | Contents |
|------|----------|
| `SHAIPTunnel/` | `PacketTunnelProvider`: the Rust session, the packet pumps, network settings, IPv6 drop, path-change reconnects, status to the app. |
| `FFI/` | Swift over the C ABI, shared by the app and the extension (and compiled on Linux by `FFIInterop`). |
| `SHAIP/Store` | `TunnelStore` (system VPN configuration, status, measured rates, enrollment) and `LiveActivityController`. |
| `SHAIP/Screens` | Setup, Connect, Traffic, Protection, Server, Settings. |
| `SHAIP/Design`, `SHAIP/Render` | Glass recipe and controls; `SceneView`, which paints SHAIPCore draw ops. |
| `SHAIPCore/` | Foundation-only Swift package: `ServerConfig`, `TunnelSnapshot`, `RateMeter` and `ThroughputHistory`, `Protection`, and the render engines. |
| `Shared/` | App Group identifiers, tokens, and the Live Activity attributes and intents. |
| `SHAIPWidgets/` | The Live Activity: lock-screen card and the Dynamic Island layouts. |
| `FFIInterop/` | The Linux harness described above. |
| `design/` | The v2 handoff as delivered, then fixed. Its sample content is illustrative and not used by the app. |
| `preview/` | The browser preview of these screens (see above). |
| `scripts/` | `build-ffi.sh` (Rust → XCFramework) and `engine-vectors.mjs` (render test vectors). |

## Limits (also shown in the app)

These limits are shown on the Protection screen:

- The VPN server sees your traffic's destinations. This VPN hides your traffic from your local
  network and your ISP, not from whoever runs the server.
- It is one hop with no mixnet, so someone watching both sides of the server can match traffic by
  timing.
- To your network every packet is random bytes, but sizes and timing can still suggest an
  encrypted tunnel, and anyone who has this server's config can recognize its handshakes.
- It does no ad, tracker or malware filtering.
- It has not yet had an independent security audit.
