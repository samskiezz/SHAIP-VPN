import Foundation

// The threat radar (`radar`), a line-for-line port of genRadar()/drawRadar().

public enum BlipClass: Int, Sendable {
    case ok = 0, warn = 1, threat = 2
}

public struct Blip: Sendable {
    public var a: Double
    public var r: Double
    public var s: BlipClass
}

public struct RadarGeometry: Sendable {
    public var blips: [Blip]
    /// Indices of the threat blips, in order; HUD label n belongs to threat n.
    public var threats: [Int] { blips.indices.filter { blips[$0].s == .threat } }
}

/// `genRadar()`: 22 seeded blips. The class draw short-circuits like the JS
/// (`r() < .18 ? 2 : r() < .45 ? 1 : 0`), so a blip consumes three or four numbers.
public func genRadar() -> RadarGeometry {
    var rng = Mulberry32(seed: 5)
    var B: [Blip] = []
    for _ in 0..<22 {
        let a = rng.next() * 6.283
        let r = 0.18 + 0.76 * rng.next()
        let s: BlipClass = rng.next() < 0.18 ? .threat : rng.next() < 0.45 ? .warn : .ok
        B.append(Blip(a: a, r: r, s: s))
    }
    return RadarGeometry(blips: B)
}

func drawRadar(_ d: inout DrawList, w: Double, h: Double, G: RadarGeometry, o: SceneParams, ph: Double, ts: Double, C: Palette) {
    let cx = w / 2, cy = h / 2, R = min(w, h) * o.rF, A = (ph * 0.0011).truncatingRemainder(dividingBy: 6.2832)
    d.emit(.gradientRect(x: 0, y: 0, w: w, h: h, gradient: RadialGradientSpec(
        x0: cx, y0: cy, r0: 0, x1: cx, y1: cy, r1: R * 1.2,
        stops: [GradientStop(offset: 0, color: rgba(C.c1, 0.1)), GradientStop(offset: 1, color: rgba(C.c1, 0))])))
    for k in 1...4 {
        d.emit(.ring(x: cx, y: cy, r: R * Double(k) / 4, color: rgba(C.c1, k == 4 ? 0.35 : 0.12), width: 0.7))
    }
    let cross = rgba(C.c1, 0.08)
    d.emit(.line(x0: cx - R, y0: cy, x1: cx + R, y1: cy, color: cross, width: 0.7))
    d.emit(.line(x0: cx, y0: cy - R, x1: cx, y1: cy + R, color: cross, width: 0.7))
    for k in 0..<120 {
        let a = Double(k) / 120 * 6.2832, l: Double = k % 10 != 0 ? 4 : 9
        d.emit(.line(x0: cx + cos(a) * (R + 3), y0: cy + sin(a) * (R + 3),
                     x1: cx + cos(a) * (R + 3 + l), y1: cy + sin(a) * (R + 3 + l),
                     color: rgba(C.c1, k % 10 != 0 ? 0.25 : 0.6), width: 0.7))
    }

    d.setBlend(.additive)
    let span = 1.3, f = span / 6.2832
    d.emit(.conicDisc(x: cx, y: cy, r: R, gradient: ConicGradientSpec(
        angle: A - span, x: cx, y: cy,
        stops: [GradientStop(offset: 0, color: rgba(C.c1, 0)), GradientStop(offset: f, color: rgba(C.c1, 0.34)),
                GradientStop(offset: min(1, f + 0.002), color: rgba(C.c1, 0)), GradientStop(offset: 1, color: rgba(C.c1, 0))])))
    d.emit(.line(x0: cx, y0: cy, x1: cx + cos(A) * R, y1: cy + sin(A) * R, color: rgba(C.c1, 0.9), width: 1.2))

    var n = 0
    for b in G.blips {
        let dt = ((A - b.a).truncatingRemainder(dividingBy: 6.2832) + 6.2832).truncatingRemainder(dividingBy: 6.2832)
        let al = pow(1 - dt / 6.2832, 2.5)
        let col = b.s == .threat ? C.bad : b.s == .warn ? C.warn : C.c1
        let x = cx + cos(b.a) * b.r * R, y = cy + sin(b.a) * b.r * R
        d.glow(col, x, y, b.s != .ok ? 26 : 16, 0.15 + 0.85 * al)
        if b.s == .threat {
            if o.hud, n < o.radarLabels.count, al > 0.35 {
                let lab = o.radarLabels[n]
                hudLabel(&d, c1: C.bad, x: x, y: y, cx: cx, w: w, lab.title, lab.detail, al: min(1, (al - 0.35) * 3))
            }
            n += 1
        }
    }
    d.glow(C.c1, cx, cy, 30, 1)
}
