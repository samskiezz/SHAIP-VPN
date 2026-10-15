# SHAIP — iOS app

Native SwiftUI implementation of the **SHAIP iOS** design handover
(`design_handoff_shaip_ios/`: `README.md`, `SHAIP iOS.dc.html`, `support.js`).

This is the exact app the handoff recommends: SwiftUI, iOS 26+, Liquid Glass,
all **eight** screens, the design's tokens / copy / layout / data / 3-D maths
ported directly — no web substitute, no screens cut.

## Build

Requires a **Mac with Xcode 26** (the iOS 26 SDK). SwiftUI, Canvas, UIKit and
`.glassEffect` are Apple-only frameworks, so the final build happens in Xcode —
there is no Linux/CI build of the UI.

```bash
cd clients/ios
brew install xcodegen          # if you don't have it
xcodegen generate              # writes SHAIP.xcodeproj from project.yml
open SHAIP.xcodeproj           # then ⌘R to an iOS 26 simulator or device
```

To run on a physical device, set `DEVELOPMENT_TEAM` in `project.yml` (or your
team in Xcode's Signing & Capabilities) and rebuild.

> `project.yml` targets iPhone only, portrait, deployment target iOS 26.0.
> `xcodegen` is only a convenience for regenerating the project file; the
> sources under `SHAIP/` are the app.

## What maps to what

| File | Design source | Contents |
|------|---------------|----------|
| `Theme.swift` | `ACC`, `renderVals()` token block | `AppTheme`/`Accent`, the `ACC` palettes, `Color(hex:)`/`rgba()`, and the exact Dark/Light `Tokens` sets |
| `Data.swift` | `SERVERS`, `PROTOS`, `CITIES`, `ARCS`, `TABS` | the 7 servers, 3 protocols, 12 globe cities, 12 arcs, 4 tab items — verbatim |
| `Mathx.swift` | `gen()`, `pr()`, `renderVals()` | mesh/globe generation, perspective projection, live-stat curves, jitter, session timer |
| `Scene.swift` | `draw()` | `SceneCanvas` — the particle mesh (`net`) and node globe (`globe`), a direct port of `draw()` on `Canvas`+`TimelineView(.animation)` |
| `Glass.swift` | `.glass` / `.glassHi` CSS | `GlassSurface` (Liquid Glass with `.ultraThinMaterial` fallback), `.place()` absolute positioning, `IOSSwitch` |
| `Chrome.swift` | template / `.tab` / blobs | `Screen` 390×844 device scaler, `FloatingTabBar`, `Blob` |
| `AppState.swift` | `state = {…}` + props | the interaction state, tweakable props (theme/accent/density), the 1 Hz clock, haptics |
| `Screens_A.swift` | phones 01–04 | Onboarding, Connect, Network globe, Nodes |
| `Screens_B.swift` | phones 05–08 | Live traffic, Protocol, Account & plan, Kill switch & alerts |
| `ContentView.swift` / `SHAIPApp.swift` | — | app shell (paged through all 8 screens, shared state, system light/dark) |

## Verification

SwiftUI itself can't be compiled off-device, but the risk is in the ported
**maths and data**, not the view declarations — so that core
(`Data.swift` + `Mathx.swift`, both Foundation-only) is compiled and unit-checked
on the Swift 6.0.3 toolchain. The checks assert the exact design invariants:

```
SERVERS=7 · SYD/FRA rows exact · PROTOS=3 · cities=12 arcs=12 tabs=4
mesh pts=120, 251 links all < 0.42, degree bounded
globe pts=560, hubs=12, all points on the unit sphere
origin projects to centre · projection finite
f,g positive · jitter bounded ±2
session timer: off → "--:--:--", base 5025s → 01:23:45, +42s → 01:24:27
```

The view files are written against the iOS 26 SDK and cross-checked line-by-line
against `SHAIP iOS.dc.html`; they build in Xcode 26.

## Navigation

The design fixes the eight screens and the four-item floating tab bar, not the
graph that connects them. The shell pages through all eight screens in design
order on one shared `AppState`, so — exactly like the reference, where every
phone re-renders from one state object — toggling the orb, picking a node,
switching protocol or arming the kill switch updates every screen at once. The
tab bar jumps to Connect / Network / Traffic / Settings; swiping reaches
Onboarding, Nodes, Account and Security. This wiring is the only part not
specified by the design; each individual screen is an exact port.
