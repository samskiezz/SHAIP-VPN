# Handoff: SHAIP VPN iOS v2 (Production)

## Overview
SHAIP is a zero-trust VPN client for teams on iOS 26+. This package covers 10 screens:
1. Onboarding
2. Connect
3. Network globe
4. Nodes
5. Traffic
6. Zero-trust access
7. Security (threat radar + kill switch)
8. Protocol
9. Team & plan
10. Lock screen Live Activity + Dynamic Island

The visual direction is clean, military-grade instrumentation: deep graphite surfaces, Liquid Glass material, and real-time 3D renders of the network.

Repo: `samskiezz/SHAIP-VPN`. It contains only a README today, so this is a greenfield build.

## About the design files
`SHAIP iOS v2.dc.html` is an **HTML design reference**, not production code. Rebuild it natively. To preview it, keep the three files in one folder and serve them over HTTP. The renderer loads as an ES module, so opening the file directly from disk may block it. Example: `npx serve .`, then open the file in Chrome or Safari.

## Fidelity
**High-fidelity.** Colours, type, spacing, radii, copy and motion are final. The layout is drawn at 390×844 pt. Build it on Auto Layout / SwiftUI stacks so it adapts to every device size, and respect safe areas.

## Recommended production stack
- **SwiftUI, iOS 26 SDK**, using native Liquid Glass:
  - `.glassEffect(.regular, in: .rect(cornerRadius:))`
  - `GlassEffectContainer` for grouped controls
  - native `TabView`, which gives the floating glass tab bar for free
- **Tunnel:** a `NEPacketTunnelProvider` network extension; WireGuardKit for the SHAIP Mesh and WireGuard protocols; `NEVPNProtocolIKEv2` for IKEv2.
- **3D scenes:** Metal (MTKView) or RealityKit. The HTML reference draws with Canvas2D and manual projection; port that same maths to a Metal vertex shader using instanced point sprites with additive blending. Target 120 fps on ProMotion, and pause rendering when a scene is offscreen or the app is backgrounded.
- **Live Activity:** ActivityKit + WidgetKit, with compact, minimal and expanded Dynamic Island layouts.
- **Fonts:** system only. `.system(design: .default)` maps to SF Pro and `.monospaced` to SF Mono; the lock-screen clock uses `.rounded`. Every number uses `.monospacedDigit()`.
- **Haptics:** `.sensoryFeedback(.impact(weight: .medium))` on connect/disconnect and the kill switch; `.selection` on rows and segmented controls.
- **State:** an `@Observable` `TunnelStore` (see State).

## Design tokens
**Colour (dark only; the app is dark-first)**
| Token | Value | Use |
|---|---|---|
| bg.top / bg.mid / bg.bottom | `#0B1020` / `#04050A` / `#020306` | screen radial gradient (120%×70% ellipse, centred top) |
| ink | `#F5F7FC` | primary text |
| ink.secondary | `rgba(220,228,255,0.50)` | secondary text |
| ink.tertiary | `rgba(220,228,255,0.42)` | mono eyebrows/labels |
| signal | `#5CF2FF` | active, primary accent, routes, mesh |
| steel | `#8A9BB8` | secondary accent, upload, mesh outer shell |
| ok | `#62F5A8` | protected, granted, switch on |
| warn | `#FFB547` | MFA, medium latency, Wi-Fi |
| threat | `#FF5C7A` | exposed, denied, threats |
| hairline | `rgba(255,255,255,0.08)` | row dividers (0.5 pt) |

**Glass surface recipe** (use native `.glassEffect` where you can; these are the values to match)
- fill: vertical gradient `rgba(255,255,255,0.085)` → `rgba(255,255,255,0.025)`
- backdrop: blur 40, saturation 180%
- border: 0.5 pt `rgba(255,255,255,0.15)`
- specular: inner top line 0.5 pt `rgba(255,255,255,0.32)`
- shadow: `0 1 1 rgba(0,0,0,.6)` + `0 24 48 -18 rgba(0,0,0,.9)`
- Secondary glass (tiles): fill `.07 → .02`, border `.13`, specular `.25`
- Tab bar glass: fill `rgba(44,48,64,.62) → rgba(16,18,26,.62)`, blur 40, saturation 200%, border `.16`, specular `.36`

**Accent glow:** active dots get `0 0 8–12 pt` of the same colour. The orb outer glow is `0 0 70 rgba(92,242,255,.28)`.

**Type** (SF Pro / SF Mono)
| Role | Spec |
|---|---|
| Hero (onboarding) | 40 / 600, tracking −4.5%, line-height 1.02, vertical gradient #FFF → #A9B4D6 |
| Large title | 34 / 700, tracking −3% |
| Display metric | 52 / 600, tracking −4.5%, tabular |
| City | 26 / 600, tracking −3.5% |
| Card title | 16–17 / 600 |
| Body / row | 14–15 / 500 |
| Caption | 12 / 400, ink.secondary |
| Mono eyebrow | SF Mono 9–11 / 500, tracking +14–18%, UPPERCASE |
| Mono data | SF Mono 10–15 / 500–600 |
| Lock clock | SF Pro Rounded 112 / 700, gradient #FFF → rgba(200,214,240,.72) |

**Spacing:** 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24. Screen side inset is 16 (titles 24).

**Radii:** device 58 · cards 30 · tab bar 32 · list cards 24–26 · tiles 20–22 · buttons 28 · search 22 · segmented 20/16 · badges 12–13 · chips 6–8.

**Controls**
- Switch: 58×32 track, 36×28 capsule thumb (Liquid Glass style), on = `ok`, off = `rgba(255,255,255,.14)`.
- Segmented control: 3 pt-padded track `rgba(255,255,255,.05)`; selected segment `rgba(255,255,255,.14)` with specular and shadow.

## Shared chrome
- **Status bar:** system.
- **Tab bar:** floating glass tab bar, inset 16 left/right, 22 from the bottom, height 64. Five tabs:
  - Connect: shield + check
  - Network: globe
  - Access: grid / QR
  - Security: radar
  - Settings: sliders
  - Active tab: pill `rgba(255,255,255,.1)`, colour `signal`. Use SF Symbols `checkmark.shield`, `globe`, `qrcode`, `scope`, `slider.horizontal.3`.
- **Bottom scrim:** 130 pt gradient behind the tab bar, from clear to `rgba(2,3,6,.92)`.
- **Ambient light:** one or two blurred accent blobs per screen (blur ~110 pt, opacity 0.10–0.16), placed behind the glass so it has something to refract.

## Screens

### 01 Onboarding
- **Background:** full-bleed mesh render (`net`), frame y 30, height 540, radius factor 0.40.
- **Corner HUD:** "SHAIP/OS 4.2" and "MESH · 0x3F9A" in mono 9.
- **Scrim:** bottom gradient from y 400.
- **Stack** (bottom 40, gap 20):
  1. Live eyebrow "42 EDGE NODES ONLINE" with a glowing signal dot
  2. Gradient hero "Zero-trust access for every device on your team."
  3. Body copy
  4. Primary button "Continue with SSO": white→`#DCE3F2` gradient, dark text, key icon, cyan drop glow
  5. Glass button "Sign in with passkey" (`person.badge.key` symbol)
  6. Compliance row: SOC 2 TYPE II · ISO 27001 · FIPS 140-3
- **Auth:** OIDC/SAML via `ASWebAuthenticationSession`; passkey via `ASAuthorizationPlatformPublicKeyCredentialProvider`.

### 02 Connect
- **Header:** workspace glass pill (32 pt gradient avatar, "Acme Corp", PROD chip) and a bell button with an unread dot.
- **Mesh render:** y 92, h 380.
- **Orb** (centred over the mesh):
  - 156 pt glass sphere: radial specular highlight, inner shadow, outer signal glow.
  - Concentric SVG rings: dotted tick ring at r 118, track at r 100, and a progress arc at r 100 that advances with session time.
  - Contents: power icon, "SECURED"/"OFFLINE" (mono 11, +18%), and "Tap to disconnect/connect".
  - Tap toggles the tunnel.
- **Status card** (y 478):
  - Status pill: PROTECTED (`ok`) or EXPOSED (`threat`).
  - Session timer, `hh:mm:ss`.
  - City (26/600); below it `NODE · DC · PROTOCOL`.
  - EXIT IP on the right.
  - 4-up metrics row (DOWN, UP, RTT, LOSS) separated by hairline dividers.
- **Quick actions** (y 676): 3 glass tiles, each a 62 pt toggle.
  - Kill switch: ARMED/OFF
  - Multi-hop: 3 HOPS/DIRECT
  - Private DNS: FILTERING/OFF
  - Border tints to 35% of the state colour when on.
- **Disconnected state:**
  - The mesh desaturates to `#8A93A8`/`#3E4558` at 25% speed.
  - The orb drops its glow and the arc empties.
  - Metrics show "—".

### 03 Network
- **Title** "Network", eyebrow "42 NODES · 18 REGIONS · 12 ROUTES", and a layers button.
- **Globe render:** y 118, h 420.
- **Floating chip:** `{node} · {rtt}`.
- **Active route card** (y 548):
  - Horizontal 4-node path: iPhone → `{CODE}` edge → SIN relay → Acme VPC.
  - Gradient connector line. Nodes fill with glow when that hop is active; the relay shows "bypassed" when multi-hop is off.
  - Tag: MULTI-HOP · 3 or DIRECT.
  - Footer row: CIPHER ChaCha20 · HANDSHAKE `n`s ago · MTU 1420.

### 04 Nodes
- Search field (with a count chip of 42).
- Segmented control: All / Recommended / Dedicated.
- **Glass list.** Each row has:
  - 42 pt code badge; the selected row's badge uses the signal→steel gradient with dark text
  - city name, with an optional tag (PQ / RELAY / DEDICATED)
  - `ID · REGION` and a 34×3 load bar
  - 16-bar live latency sparkline
  - RTT in mono 14: `ok` under 50 ms, `warn` under 150 ms, otherwise `threat`
- Selected row background: horizontal gradient signal 12% → 2%.
- Tapping a row sets the node and connects.

| Code | City | Region | ID | Data centre | RTT | Load | Exit IP | Tag |
|---|---|---|---|---|---|---|---|---|
| SYD | Sydney | AU-EAST | SYD-03 | Equinix SY4 | 14 | 42 | 203.0.113.42 | PQ |
| MEL | Melbourne | AU-SE | MEL-01 | NEXTDC M2 | 22 | 31 | 203.0.113.87 | |
| AKL | Auckland | NZ-N | AKL-02 | Spark DC | 38 | 18 | 198.51.100.9 | |
| SIN | Singapore | AP-SE | SIN-01 | Digital Realty | 92 | 64 | 198.51.100.140 | RELAY |
| TYO | Tokyo | AP-NE | TYO-04 | AT Tokyo CC1 | 118 | 57 | 192.0.2.61 | |
| LAX | Los Angeles | US-W | LAX-02 | CoreSite LA1 | 146 | 49 | 192.0.2.200 | |
| FRA | Frankfurt | EU-C | FRA-01 | Interxion | 268 | 22 | 192.0.2.18 | DEDICATED |

### 05 Traffic
- Title, with a live indicator `LIVE · {node}`.
- **Hero card:**
  - "THROUGHPUT ↓" eyebrow above a 52 pt value + Mbps; ↑ upload and PK (peak) on the right.
  - **Chart:** 326×150, 48 samples at 1 Hz, y-range 0–220 Mbps. Layers, bottom to top:
    1. dashed gridlines
    2. area fill, signal 34% → 0
    3. 3 pt blurred glow line (σ 3)
    4. 1.6 pt line with a horizontal gradient: signal 15% → signal → white at "now"
    5. dashed steel upload line
  - Axis labels: T-48s / T-24s / NOW.
  - Port the chart to Swift Charts (`AreaMark` + `LineMark`, `.interpolationMethod(.monotone)`).
- **Tiles:** SESSION GB · JITTER ms · PACKETS M.
- **Per-app usage list:** name, host, value, and a 3 pt bar with glow.
  - GitHub Enterprise: 1.24 GB, signal
  - AWS Console: 640 MB, steel
  - Slack: 212 MB, ok
  - Figma: 96 MB, warn

### 06 Access (zero trust)
- Title "Access", eyebrow "POLICY · ACME-STRICT".
- **Posture card:**
  - 84 pt trust ring: score 94, `ok` arc with glow, dotted outer tick ring.
  - "Device posture: compliant" and "LAST CHECK 00:42 AGO · CROWDSTRIKE".
  - Chips: iOS 26.1, Disk encrypted, MDM enrolled, Biometrics, Patch age 4d. Patch age turns `warn` when posture enforcement is off.
- Segmented control: All · 24 / Granted · 19 / Pending · 3.
- **Resource list** (abbreviation badge, mono host, meta, state pill):
  - git.acme.internal: GRANTED
  - prod-db-01: MFA (warn)
  - bastion-syd, "SSH 22 · JIT · 58m left": GRANTED
  - jenkins.ci: GRANTED
  - finance.acme: DENIED (threat)
- Tapping an MFA row should trigger step-up auth via `LAContext`; this is not shown in the mock.

### 07 Security
- Title, with "● 3 ACTIVE" in threat.
- **Radar render:** 320×280, centred at y 104.
- **HUD corners:** "SWEEP 1.1 rad/s", "RANGE 24H", "DNS · IP · TLS", "22 SIGNALS".
- **Counters:** THREATS 1,284 · TRACKERS 9,412 · PHISHING 7.
- **Kill switch card:** ARMED/DISARMED eyebrow, switch, and description copy.
  - Armed: "All traffic is blocked if the tunnel drops. Enforced by workspace policy."
  - Disarmed: "Traffic can leak during reconnects. Your admin has been notified."
- **Alerts list:**
  - C2 beacon blocked: 185.220.101.4 · Tor exit, 2m (threat)
  - Untrusted Wi-Fi joined: Cafe_Guest · auto-protected, 41m (warn)
  - Tunnel renegotiated: SYD-03 → SYD-04 · 0 loss, 1h (signal)
  - Posture check passed: iOS 26.1 · disk encrypted, 3h (ok)
- In production the kill switch maps to `includeAllNetworks = true` and `enforceRoutes = true` on `NETunnelProviderManager`.

### 08 Protocol
- Eyebrow "ADMIN-LOCKED · 2".
- **Radio cards:** the selected card gets a signal border at 55%, a 4 pt halo at 10% and a cyan drop glow.

| Protocol | Tag | Description | Spec chips |
|---|---|---|---|
| SHAIP Mesh | RECOMMENDED | WireGuard core · multi-hop · ML-KEM-768 hybrid | UDP 443, ChaCha20-Poly1305, PQ |
| WireGuard | | Single hop · lowest latency | UDP 51820, Curve25519 |
| IKEv2 / IPsec | | Native iOS fallback for restricted networks | UDP 500/4500, AES-256-GCM |

- **TUNNEL switches** (default in brackets):
  - Post-quantum handshake [on]
  - Split tunneling [off]
  - On-demand [on]
  - Posture enforcement [on]
- **Advanced tiles:** Port UDP 443 · MTU 1420 · Keepalive 25 s.

### 09 Team & plan
- Profile: 60 pt glass avatar with a signal halo, "Maya Chen", "SECURITY ADMIN · ACME CORP".
- **Plan card:**
  - "Business · Annual" with an ACTIVE pill.
  - Segmented seat meter: 148 used (signal→steel gradient with glow) and 52 free (hatched).
  - SEATS 148/200 · DEVICES 311 · RENEWS 14.03.27.
- **Team list** ("96 ONLINE"): avatar with a presence dot, name, role, and current node.
- **This-user devices:** iPhone 17 Pro, MacBook Pro 14".

### 10 Lock screen
- **Dynamic Island** (compact, 200×37): shield in the state colour on the left, RTT on the right.
- Date in 19/600 and the SF Pro Rounded 112 clock.
- Dimmed mesh render in the background (opacity 0.85).
- **Live Activity card** (bottom 118):
  - Gradient app glyph, "Protected · Sydney", "SYD-03 · SHAIP MESH", session timer.
  - DOWN and RTT.
  - Glass "Tap to disconnect" button: an `AppIntent`, `DisconnectTunnelIntent`.
- **Expanded island** (not drawn): city + timer on the leading side, RTT/Down on the trailing side, the disconnect intent at the bottom.

## 3D renderers (`shaip-engine.js`)
All three scenes share one setup:
- Projection: rotate Y by `a`, tilt X by `b`, then `s = cam/(cam+Z)` with cam 3.2 (3.6 for the globe).
- Depth factor `d = (1−Z)/2` drives alpha (≈ `.15 + .85·d²`) and size, so near points are brighter and larger.
- Blending is additive.
- Glows are pre-rendered radial sprites: a white core, then the colour at 10%, falling to 0 at 100%. In Metal, use a point sprite with a radial falloff in the fragment shader.
- The backing store renders at ≥3× device scale ("Ultra"). Pause rendering when offscreen.

**Mesh (`net`)**
- **Nodes:** three shells, all seeded and deterministic.
  - Core: 14%, radius 0.08–0.28
  - Mid: 38%, Fibonacci sphere at r ≈ 0.6
  - Outer: Fibonacci sphere at r ≈ 1.0
  - Default total 170 (tweakable 60–260).
- **Links:** k-nearest within the same or an adjacent shell (k = 4, outer shell 3), plus 6 trunk links from outer hubs to the core.
- **Pulse wave:** a radial wave sweeps outward with period ≈ 3.1 s. Nodes within 0.14 of the wavefront brighten their links (×3.2) and grow (×2.1).
- **Packets:** 44 link packets, each a white sprite head with a 6-step trail.
- **Orbit rings:** three tilted rings at r 1.22 / 1.4 / 1.1 with counter-rotations; the middle ring is dashed. Each carries one bright satellite.
- **Hubs:** 6 outer hubs with expanding pulse rings (period ≈ 1.4 s).
- **Floor:** a perspective grid at y −1.3 with radial fade, plus an elliptical signal reflection under the mesh.
- **HUD:** corner-bracket target reticles on 4 front-facing hubs, with leader lines and labels (`SYD-03 / ACTIVE · 14ms`, `SIN-01 / RELAY · 92ms`, …). Labels fade in as depth > 0.58, and leaders flip side to stay on-screen.
- **Rotation:** yaw `0.00012 rad/ms`, pitch `−0.3 ± 0.08`.

**Globe**
- **Body:** dark sphere shaded by a radial gradient (highlight top-left), a signal rim stroke, and an atmosphere halo from R·0.92 to R·1.4.
- **Land:** a 4,200-point Fibonacci sphere masked by 19 continent ellipses. Land points are signal-coloured squares; ocean is every 5th point, dimmed steel.
- **Graticule:** every 30° longitude and 30° latitude, steel at low alpha.
- **Scan line:** a latitude sweep of ±62° in signal.
- **Routes:** 12 great-circle arcs lifted 25% at the midpoint, drawn faint. Over each arc, a light streak (12-segment fading tail) travels with a white head.
- **Hubs:** 12 city hubs. SYD gets a double pulse ring, and 4 cities get HUD labels.

**Radar**
- 4 range rings, crosshair, and a 120-tick bezel with every 10th tick long.
- Conic sweep wedge (1.3 rad) with a leading line at 1.1 rad/s.
- 22 blips classed ok/warn/threat. Each blip fades as `(1 − Δθ/2π)^2.5` since the sweep last passed it.
- Threat blips get HUD labels: "C2 BEACON BLOCKED / 185.220.101.4", "PHISH DOMAIN / acme-sso.co".

## State and data
```swift
@Observable final class TunnelStore {
  var connected = true
  var selectedNode = 0            // Nodes list index
  var proto: Proto = .mesh        // .mesh | .wireguard | .ikev2
  var killSwitch = true
  var multiHop = true
  var privateDNS = true
  var splitTunnel = false
  var postureEnforced = true
  var onDemand = true
  var pqHandshake = true
  var nodeFilter = 0              // All / Recommended / Dedicated
  var accessFilter = 0            // All / Granted / Pending
  var telemetry: Telemetry        // 1 Hz: downMbps, upMbps, rttMs, jitterMs, lossPct, bytes, packets
  var history: RingBuffer<Sample> // 48 samples
  var sessionStart: Date?
}
```
- The mock generates telemetry with sine functions. In production, read it from `NETunnelProviderSession.sendProviderMessage` every second: bytes rx/tx deltas → Mbps, plus WireGuard handshake time and RTT from the keepalive.
- The Live Activity updates via `Activity.update` at most once every 15 s. The timer uses `Text(timerInterval:)`.
- Connecting from any surface (orb, node row, lock screen intent) updates every screen.

## Motion
- State colour changes (blobs, orb, mesh palette): 0.5–0.6 s ease-in-out.
- Switches, segmented controls and tab pills: system spring (`.smooth`).
- Orb tap: scale to 0.94 then back to 1.0 with `.bouncy`, plus haptic. The progress arc animates with `.linear`.
- Mesh speed eases to 25% when disconnected (don't stop it).
- Respect Reduce Motion: freeze rotation, keep the pulses static, and hide packets.

## Accessibility
- Dynamic Type on all non-mono text. Mono data can stay fixed but must be ≥ 9 pt.
- The orb is a button labelled "Disconnect VPN" / "Connect VPN", with the value "Protected via Sydney".
- Render canvases are `accessibilityHidden(true)`; their data also appears in text elsewhere.
- Status colour always comes with a text label (PROTECTED, ARMED, GRANTED).

## Assets
- No raster assets.
- All icons map to SF Symbols: `checkmark.shield`, `globe`, `qrcode`, `scope`, `slider.horizontal.3`, `bell.badge`, `power`, `magnifyingglass`, `lock`, `point.3.connected.trianglepath.dotted`, `network.badge.shield.half.filled`, `square.3.layers.3d`, `person.badge.key`, `key`.
- All IPs are RFC 5737 documentation ranges; replace them with live data.

## Files
- `SHAIP iOS v2.dc.html`: the full design. The `renderVals()` logic class holds all data, copy and state logic.
- `shaip-engine.js`: the reference 3D renderers (`net`, `globe`, `radar`). Treat it as the maths spec for the Metal port.
- `support.js`: the runtime needed to open the HTML reference.
- Tweakable props in the reference: `quality` (Ultra/Standard), `density`, `hud`, `floor`.
