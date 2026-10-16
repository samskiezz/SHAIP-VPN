# SHAIP — iOS app (design v2)

Native SwiftUI implementation of the **SHAIP iOS v2** design handoff in [`design/`](design/):
SwiftUI on the iOS 26 SDK, Liquid Glass, the native floating tab bar, all **ten** screens, live 3-D
scenes, and a real Live Activity with Dynamic Island layouts.

## Build

Requires a **Mac with Xcode 26** (iOS 26 SDK).

```bash
cd clients/ios
brew install xcodegen          # once
xcodegen generate              # writes SHAIP.xcodeproj from project.yml
open SHAIP.xcodeproj           # ⌘R on an iOS 26 simulator or device
```

To run on a device, set `DEVELOPMENT_TEAM` in `project.yml`, or pick your team under Signing &
Capabilities. To see the Live Activity (screen 10), run the app and lock the simulator (⌘L).

The render engines, data and telemetry live in the **SHAIPCore** Swift package. It is
Foundation-only and builds and tests anywhere Swift runs, including Linux:

```bash
swift test --package-path clients/ios/SHAIPCore
```

## Layout

| Path | Contents |
|------|----------|
| `design/` | The v2 handoff: `SHAIP iOS v2.dc.html`, `shaip-engine.js`, `support.js`, `HANDOFF.md`. The handoff was committed as delivered, then fixed (see below). To preview it, serve the folder over HTTP (`python3 -m http.server --directory clients/ios/design`) and open the `.dc.html` file. |
| `SHAIPCore/` | Swift package: `Render/` (the `net`, `globe` and `radar` engines plus `SceneRenderer`, ported line for line from `shaip-engine.js`), `Catalog.swift` (nodes, protocols, access, alerts, team, HUD copy) and `Telemetry.swift` (the 1 Hz curves, 48-sample history, clock). |
| `SHAIP/App` | `@main`, the 5-tab `TabView`, the onboarding gate, `Router`. |
| `SHAIP/Store` | `TunnelStore` (the handoff's `@Observable` store) and `LiveActivityController`. |
| `SHAIP/Design` | Glass recipe (content cards on material; controls on native `.glassEffect`), switch, segmented control, pills, chips, the screen background and scrim. |
| `SHAIP/Render` | `SceneView`: a `Canvas` that paints SHAIPCore draw ops (glow sprites, additive blending, batched paths). It pauses offscreen and in the background, and follows Reduce Motion. |
| `SHAIP/Screens` | Onboarding, Connect, Network, Nodes, Traffic, Access, Security, Protocol, Team. |
| `Shared/` | Compiled into both targets: tokens, the Live Activity attributes, and the connect/disconnect `LiveActivityIntent`s. |
| `SHAIPWidgets/` | The Live Activity: lock-screen card, plus compact, minimal and expanded Dynamic Island layouts. |
| `scripts/engine-vectors.mjs` | Regenerates SHAIPCore's cross-language test vectors from `design/shaip-engine.js`. |

## Navigation

The handoff specifies five tabs and ten screens, but not how they connect. The app connects them like this:

| Tab | Root | Pushed |
|-----|------|--------|
| Connect | 02 Connect | 05 Traffic (tap the status card) |
| Network | 03 Network | 04 Nodes (tap the node chip); the layers button toggles the globe's HUD |
| Access | 06 Access | — (an MFA row runs Face ID / passcode step-up through `LAContext`) |
| Security | 07 Security | — |
| Settings | 08 Protocol | 09 Team & plan (tap the avatar) |

- **01 Onboarding** is a full-screen cover until you sign in.
- **10 Lock screen** is the real Live Activity.
- The bell on Connect opens Security and clears its unread dot.
- Every screen reads one `TunnelStore`. Connecting from the orb, a node row or the lock screen updates them all.

## Verification

What is checked, and how:

- **Render engines: op for op against the reference.** `scripts/engine-vectors.mjs` drives the real
  `draw()` from `shaip-engine.js` through a recording canvas. It runs seven timelines: mesh
  connect/disconnect, including the fade and a dt-clamp gap; mesh at density 60 with no floor or HUD;
  Reduce Motion; the globe with FRA active, then disconnected; a long globe run; Reduce Motion on the
  globe; and a full radar sweep. It stores op counts and an FNV-1a hash of every draw call (to 1e-4)
  for 33 frames, about 50,000 ops in total. `EngineVectorTests` replays the same timelines through
  `SceneRenderer` and must reproduce every hash.
  - It also checks the seeded RNG, mesh geometry at 60/170/210 nodes, the globe land mask and the radar blips.
  - Bit-exact geometry needs V8's own `Math.hypot` algorithm (scaled, Kahan-compensated). The port includes it.
  - Negative control: changing one constant (land alpha 0.78 → 0.77) fails every globe frame.
- **Telemetry and copy logic** (`CatalogTests`) check:
  - `toFixed` and `Math.round` semantics against values generated in JS;
  - that the segment filters return the right rows;
  - that HUD labels never repeat a node ID and follow the selection;
  - that the history keeps the past across a disconnect and that PK is the real peak;
  - the clock, the orb arc and the easing curve.
- **The design reference fixes** were checked by rendering in headless Chromium, with before/after
  screenshots and scripted checks:
  - a reconnect resets the timer;
  - picking FRA moves the globe's ACTIVE hub;
  - the segments filter;
  - the last Security alert can be scrolled clear of the tab bar.
- **SwiftUI app and widget**: every file passes `swiftc -parse`. The SwiftUI, Charts, ActivityKit
  and WidgetKit code needs the iOS 26 SDK, so it has **not been compiled here**. The first real
  build is in Xcode; report anything it flags.

## What changed from v1, and why

The v1 app was an 8-screen port of the earlier design.

- It is now the v2 design throughout: dark-first tokens (`#0B1020` → `#020306` background, signal
  `#5CF2FF`, steel, ok/warn/threat), the glass recipe, 10 screens, 5 tabs, and the new mesh, globe
  and radar engines.
- **Adaptive layout.** v1 drew a fixed 390×844 canvas and scaled it to the screen width. It
  stretched or clipped on other phones and ignored safe areas. v2 uses stacks and scroll views
  inside the safe area, as the handoff requires, and Dynamic Type scales all non-mono text.
- **Native navigation.** v1 used a paged `TabView` under a hand-drawn tab bar. v2 uses the native
  `TabView` with `NavigationStack`s, so the floating Liquid Glass tab bar, swipe-back and VoiceOver
  come from the system.
- **Build fixes.** `SWIFT_VERSION` was `"5.10"`, but language modes are `5.0`/`6.0`. v1's
  hand-written Info.plist had no `CFBundleExecutable`, which stops the bundle from installing. v2
  generates the Info.plist and merges in a small file for the Live Activity and ProMotion keys.
- **Render fixes.**
  - v1 accumulated phase without the reference's 50 ms clamp, so scenes jumped after the app returned from the background.
  - v1's jitter rounding differed from JS for negative halves.
  - v1 drew every paged screen's canvas at once. v2 renders only visible scenes.
- **Haptics** use `.sensoryFeedback`. **State** is an `@Observable` `TunnelStore`.

## Fixes to the v2 handoff

These are fixed in both `design/` and the app; the second commit on `design/` shows the diff.

- **Floor reflection:**
  - The mesh floor's reflection never painted. Its gradient was built in screen space, then filled under `translate`/`scale`.
  - In Chromium it painted 0 px; the fixed version reaches the intended 0.2 alpha.
- **Radar labels:** each HUD label jumped between different threat blips as the sweep moved.
- **Globe:**
  - The ACTIVE hub was hard-wired to Sydney and kept saying ACTIVE while disconnected.
  - Hub labels used wrong node IDs (TYO-01, AKL-01).
  - LAX replaces SFO and MEL is added, so every listed node is on the globe.
- **Session timer:** a reconnect resumed the old session's clock instead of starting at 00:00:00.
- **Traffic:**
  - Disconnecting erased the chart's history.
  - PK was a constant 212.4, above the curve's maximum of 202.
  - The indicator said LIVE while offline.
- **Nodes and Access:** the segments only moved the highlight; now they filter.
- **Duplicate labels:** selecting SIN, TYO or FRA labelled two mesh hubs with the same ID.
- **Security:** the last alert sat under the tab bar with no way to reach it.
- **Wrapping:** the Connect meta line, "Private DNS" and the lock screen's "Tap to disconnect" wrapped onto two lines.
- **Lock screen:**
  - The island showed "—ms".
  - DOWN showed 0 while RTT showed —.
  - The protocol was hard-coded to SHAIP MESH.
- **Copy consistency:**
  - Disconnected copy now reads "Not connected" everywhere.
  - The kill-switch tile now says DISARMED, like its card.
  - The relay showed "+41 ms" while offline.
  - The Network title used −4% tracking instead of the specified −3%.
  - Advanced keys weren't uppercase like every other eyebrow.
- **Motion and accessibility:**
  - Connection changes now ease over 550 ms (palette cross-fade, speed easing to 25%).
  - Reduce Motion freezes rotation, keeps pulses static and hides packets.
  - The orb is a labelled button.

## Not done here

- **The tunnel itself.** `TunnelStore` mocks the session with the design's telemetry curves. In
  production:
  - `connected` drives a `NETunnelProviderManager` with a packet-tunnel extension. The repo's
    `ffi/` crate exposes the PQANON client as a C ABI (`ffi/include/pqanon.h`) for exactly this.
  - IKEv2 goes through `NEVPNProtocolIKEv2`.
  - The kill switch sets `includeAllNetworks` and `enforceRoutes`.
  - Telemetry arrives through `sendProviderMessage`.
- **Sign-in.** SSO (`ASWebAuthenticationSession`) and passkeys
  (`ASAuthorizationPlatformPublicKeyCredentialProvider`) are seams. No IdP is configured, so both
  buttons sign in directly. Enrolment should go through the control plane's `/api/enroll`.
- **Metal.** The handoff suggests Metal for 120 fps. The scenes use `Canvas`, which is verified
  against the reference and batched, and are capped at 60 fps. Because the engines produce plain
  draw ops, a Metal painter can replace `ScenePainter` without touching the maths.
