import SwiftUI

// Per-canvas scratch: accumulated phase (speed varies with connected state) and
// lazily-generated geometry. Held in @State so it persists across frames.
final class SceneState {
    var phase: Double = 0
    var last: Double? = nil
    var mesh: (pts: [[Double]], links: [(Int, Int, Double)])? = nil
    var meshN: Int = -1
    var globe: (pts: [[Double]], hubs: [[Double]])? = nil
}

@inline(__always)
private func dot(_ ctx: inout GraphicsContext, _ x: Double, _ y: Double, _ r: Double, _ c: Color) {
    ctx.fill(Path(ellipseIn: CGRect(x: x - r, y: y - r, width: r * 2, height: r * 2)), with: .color(c))
}

@inline(__always)
private func seg(_ ctx: inout GraphicsContext, _ x0: Double, _ y0: Double, _ x1: Double, _ y1: Double, _ c: Color, _ lw: Double) {
    var p = Path()
    p.move(to: CGPoint(x: x0, y: y0))
    p.addLine(to: CGPoint(x: x1, y: y1))
    ctx.stroke(p, with: .color(c), lineWidth: lw)
}

/// The particle mesh (`data-net="net"`) and node globe (`data-net="globe"`) —
/// a direct port of draw() using manual perspective projection.
struct SceneCanvas: View {
    let mode: String          // "net" or "globe"
    let connected: Bool
    let tokens: Tokens
    let density: Int
    @State private var s = SceneState()

    var body: some View {
        TimelineView(.animation) { tl in
            Canvas { ctx, size in
                draw(&ctx, size, ms: tl.date.timeIntervalSinceReferenceDate * 1000)
            }
        }
    }

    private func draw(_ ctx: inout GraphicsContext, _ size: CGSize, ms ts: Double) {
        let w = size.width, h = size.height
        if w == 0 { return }
        let dark = tokens.dark
        let A = tokens.accentHex
        let on = connected || mode == "globe"
        let c1 = on ? (dark ? A[0] : A[2]) : (dark ? "#8A90A0" : "#6B7080")
        let c2 = on ? (dark ? A[1] : A[3]) : (dark ? "#5A6070" : "#9097A6")
        let sp = on ? 1.0 : 0.3
        if s.last == nil { s.last = ts }
        s.phase += (ts - s.last!) * sp
        s.last = ts
        let ph = s.phase
        let a = ph * 0.00016, b = 0.38 + sin(ph * 0.00021) * 0.14
        let ca = cos(a), sa = sin(a), cb = cos(b), sb = sin(b)
        let R = Double(min(w, h)) * (mode == "globe" ? 0.42 : 0.4) * (on ? 1 : 0.92 + sin(ts * 0.002) * 0.02)
        let cx = Double(w) / 2, cy = Double(h) / 2
        func pr(_ p: [Double]) -> (Double, Double, Double, Double) {
            project(p[0], p[1], p[2], ca: ca, sa: sa, cb: cb, sb: sb, R: R, cx: cx, cy: cy)
        }
        ctx.blendMode = dark ? .plusLighter : .normal

        if mode == "globe" {
            if s.globe == nil { s.globe = genGlobe() }
            let G = s.globe!
            // atmosphere halo
            let atm = GraphicsContext.Shading.radialGradient(
                Gradient(stops: [
                    .init(color: Color(hex: c2, opacity: 0), location: 0),
                    .init(color: Color(hex: c2, opacity: dark ? 0.18 : 0.12), location: 0.3),
                    .init(color: Color(hex: c2, opacity: 0), location: 1),
                ]),
                center: CGPoint(x: cx, y: cy), startRadius: R * 0.85, endRadius: R * 1.25)
            ctx.fill(Path(ellipseIn: CGRect(x: cx - R * 1.25, y: cy - R * 1.25, width: R * 2.5, height: R * 2.5)), with: atm)
            // surface points
            for p in G.pts {
                let q = pr(p); let d = (1 - q.2) / 2
                dot(&ctx, q.0, q.1, 0.6 + 0.9 * q.3 * d, Color(hex: d > 0.5 ? c1 : c2, opacity: 0.08 + 0.55 * d * d))
            }
            // arcs + travelling packet
            for (k, arc) in ARCS.enumerated() {
                let A0 = G.hubs[arc.0], B0 = G.hubs[arc.1]
                var seg3: [(Double, Double, Double, Double)] = []
                seg3.reserveCapacity(29)
                for i in 0...28 {
                    let tt = Double(i) / 28
                    let x = A0[0] + (B0[0] - A0[0]) * tt
                    let y = A0[1] + (B0[1] - A0[1]) * tt
                    let z = A0[2] + (B0[2] - A0[2]) * tt
                    let L = hypot3(x, y, z)
                    let lift = (1 + 0.22 * sin(Double.pi * tt)) / L
                    seg3.append(pr([x * lift, y * lift, z * lift]))
                }
                for i in 1..<seg3.count {
                    let d = (1 - seg3[i].2) / 2
                    seg(&ctx, seg3[i - 1].0, seg3[i - 1].1, seg3[i].0, seg3[i].1, Color(hex: c1, opacity: 0.08 + 0.6 * d * d), 1.2)
                }
                let idx = Int(((ph * 0.00035 + Double(k) * 0.137).truncatingRemainder(dividingBy: 1)) * 28)
                let pt = seg3[min(idx, 28)]; let d = (1 - pt.2) / 2
                dot(&ctx, pt.0, pt.1, 2.2, Color(hex: dark ? "#FFFFFF" : c1, opacity: 0.25 + 0.75 * d))
            }
            // hubs
            for (i, p) in G.hubs.enumerated() {
                let q = pr(p); let d = (1 - q.2) / 2
                if d < 0.35 { continue }
                let glow = GraphicsContext.Shading.radialGradient(
                    Gradient(stops: [
                        .init(color: Color(hex: c1, opacity: 0.7 * d), location: 0),
                        .init(color: Color(hex: c1, opacity: 0), location: 1),
                    ]),
                    center: CGPoint(x: q.0, y: q.1), startRadius: 0, endRadius: 14)
                ctx.fill(Path(ellipseIn: CGRect(x: q.0 - 14, y: q.1 - 14, width: 28, height: 28)), with: glow)
                dot(&ctx, q.0, q.1, i == 0 ? 3.6 : 2.4, Color(hex: dark ? "#FFFFFF" : c1, opacity: d))
                if i == 0 {
                    let pr2 = (ts * 0.0012).truncatingRemainder(dividingBy: 1)
                    var ring = Path()
                    ring.addArc(center: CGPoint(x: q.0, y: q.1), radius: 4 + pr2 * 18, startAngle: .zero, endAngle: .degrees(360), clockwise: false)
                    ctx.stroke(ring, with: .color(Color(hex: c1, opacity: (1 - pr2) * d)), lineWidth: 1.5)
                }
            }
            ctx.blendMode = .normal
            return
        }

        // particle mesh
        if s.mesh == nil || s.meshN != density { s.mesh = genMesh(density); s.meshN = density }
        let G = s.mesh!
        let P = G.pts.map { pr($0) }
        // radial core glow
        let core = GraphicsContext.Shading.radialGradient(
            Gradient(stops: [
                .init(color: Color(hex: c1, opacity: on ? (dark ? 0.22 : 0.14) : 0.06), location: 0),
                .init(color: Color(hex: c2, opacity: 0), location: 1),
            ]),
            center: CGPoint(x: cx, y: cy), startRadius: 0, endRadius: R * 0.9)
        ctx.fill(Path(ellipseIn: CGRect(x: cx - R * 0.9, y: cy - R * 0.9, width: R * 1.8, height: R * 1.8)), with: core)
        // links
        for (i, j, dd) in G.links {
            let d = ((1 - P[i].2) + (1 - P[j].2)) / 4
            let col = Color(hex: d > 0.5 ? c1 : c2, opacity: (1 - dd / 0.42) * (0.1 + 0.55 * d))
            seg(&ctx, P[i].0, P[i].1, P[j].0, P[j].1, col, 1)
        }
        // travelling packets
        if on && !G.links.isEmpty {
            for k in 0..<16 {
                let (i, j, _) = G.links[(k * 37) % G.links.count]
                let tt = (ph * 0.0007 + Double(k) * 0.173).truncatingRemainder(dividingBy: 1)
                let x = P[i].0 + (P[j].0 - P[i].0) * tt
                let y = P[i].1 + (P[j].1 - P[i].1) * tt
                let d = ((1 - P[i].2) + (1 - P[j].2)) / 4
                dot(&ctx, x, y, 1.8, Color(hex: dark ? "#FFFFFF" : c1, opacity: 0.3 + 0.7 * d))
            }
        }
        // points (every 9th is a hub r3, else r1.6; colour c1 unless i%3==0)
        for (i, q) in P.enumerated() {
            let d = (1 - q.2) / 2
            let r = (i % 9 == 0 ? 3.0 : 1.6) * q.3
            dot(&ctx, q.0, q.1, r, Color(hex: i % 3 != 0 ? c1 : c2, opacity: 0.2 + 0.8 * d))
        }
        ctx.blendMode = .normal
    }
}
