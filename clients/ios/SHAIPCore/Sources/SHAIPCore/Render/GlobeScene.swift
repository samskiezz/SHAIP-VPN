import Foundation

// The node globe (`globe`), a line-for-line port of genGlobe()/drawGlobe().

/// Continent ellipses (lat, lon, lat radius, lon radius) that mask the Fibonacci sphere into land.
public let LAND: [(Double, Double, Double, Double)] = [
    (48, -100, 18, 28), (62, -110, 10, 30), (20, -100, 10, 10), (-12, -58, 20, 13), (-35, -65, 10, 7),
    (52, 12, 9, 18), (60, 40, 10, 30), (8, 20, 22, 18), (-22, 25, 12, 12), (48, 95, 16, 45),
    (30, 80, 8, 18), (22, 78, 9, 7), (12, 103, 9, 9), (0, 115, 6, 14), (-25, 134, 11, 17),
    (72, -40, 7, 16), (36, 138, 6, 5), (64, -150, 6, 12), (-6, 142, 4, 7),
]

/// Globe hubs, in the fixed order the route arcs index into. LAX (a node in the Nodes table)
/// replaces the handoff's SFO, and MEL is appended, so every listed node exists on the globe.
public let CITIES: [(lat: Double, lon: Double, code: String)] = [
    (-33.9, 151.2, "SYD"), (1.3, 103.8, "SIN"), (35.7, 139.7, "TYO"), (50.1, 8.7, "FRA"),
    (51.5, -0.1, "LON"), (40.7, -74, "NYC"), (33.9, -118.4, "LAX"), (-23.5, -46.6, "GRU"),
    (19, 72.8, "BOM"), (-36.8, 174.7, "AKL"), (43.7, -79.4, "YYZ"), (25.2, 55.3, "DXB"),
    (-37.8, 145, "MEL"),
]

/// The 12 great-circle routes between hubs.
public let ARCS: [(Int, Int)] = [(0, 1), (0, 2), (1, 3), (3, 4), (4, 5), (5, 6), (0, 9), (1, 8), (8, 11), (11, 3), (6, 2), (5, 7)]

func isLand(_ la: Double, _ lo: Double) -> Bool {
    LAND.contains { a, b, ra, rb in
        var dl = lo - b
        if dl > 180 { dl -= 360 }
        if dl < -180 { dl += 360 }
        let u = (la - a) / ra, v = dl / rb
        return u * u + v * v < 1
    }
}

public struct GlobeGeometry: Sendable {
    public var land: [V3]
    public var sea: [V3]
    public var grid: [[V3]]
    public var hubs: [V3]
    public var arcs: [[V3]]
}

/// `genGlobe()`: 4,200-point land mask (every 5th ocean point kept), 30° graticule, hubs and the
/// arcs lifted 25% at their midpoint.
public func genGlobe() -> GlobeGeometry {
    var land: [V3] = [], sea: [V3] = []
    for (i, v) in fib(4200).enumerated() {
        let la = asin(v.y) * 180 / Double.pi, lo = atan2(v.z, v.x) * 180 / Double.pi
        if isLand(la, lo) { land.append(v) } else if i % 5 == 0 { sea.append(v) }
    }
    var grid: [[V3]] = []
    for lo in stride(from: -180, to: 180, by: 30) {
        grid.append(stride(from: -90, through: 90, by: 6).map { ll(Double($0), Double(lo)) })
    }
    for la in stride(from: -60, through: 60, by: 30) {
        grid.append(stride(from: -180, through: 180, by: 6).map { ll(Double(la), Double($0)) })
    }
    let hubs = CITIES.map { ll($0.lat, $0.lon) }
    let arcs: [[V3]] = ARCS.map { i, j in
        let A = hubs[i], B = hubs[j]
        return (0...40).map { k in
            let t = Double(k) / 40
            let x = A.x + (B.x - A.x) * t, y = A.y + (B.y - A.y) * t, z = A.z + (B.z - A.z) * t
            let L = jsHypot(x, y, z), f = (1 + 0.25 * sin(Double.pi * t)) / L
            return V3(x * f, y * f, z * f)
        }
    }
    return GlobeGeometry(land: land, sea: sea, grid: grid, hubs: hubs, arcs: arcs)
}

func drawGlobe(_ d: inout DrawList, w: Double, h: Double, G: GlobeGeometry, o: SceneParams, ph: Double, ts: Double, C: Palette) {
    let cx = w / 2, cy = h / 2, R = min(w, h) * o.rF, cam = 3.6, Rs = R * cam / (cam * cam - 1).squareRoot()
    let pr = Projector(a: ph * 0.00009 + 2.2, b: -0.32, cx: cx, cy: cy, R: R, cam: cam)

    d.emit(.gradientRect(x: 0, y: 0, w: w, h: h, gradient: RadialGradientSpec(
        x0: cx, y0: cy, r0: Rs * 0.92, x1: cx, y1: cy, r1: Rs * 1.4,
        stops: [GradientStop(offset: 0, color: rgba(C.c1, 0.3)), GradientStop(offset: 0.2, color: rgba(C.c1, 0.1)),
                GradientStop(offset: 0.5, color: rgba(C.c2, 0.05)), GradientStop(offset: 1, color: rgba(C.c2, 0))])))
    d.emit(.gradientDisc(x: cx, y: cy, r: Rs, gradient: RadialGradientSpec(
        x0: cx - Rs * 0.35, y0: cy - Rs * 0.45, r0: Rs * 0.05, x1: cx, y1: cy, r1: Rs,
        stops: [GradientStop(offset: 0, color: RGBA(RGB(46, 70, 130), 0.55)),
                GradientStop(offset: 0.6, color: RGBA(RGB(10, 16, 34), 0.92)),
                GradientStop(offset: 1, color: RGBA(RGB(3, 5, 12), 0.98))])))
    d.emit(.ring(x: cx, y: cy, r: Rs, color: rgba(C.c1, 0.45), width: 1))

    d.setBlend(.additive)
    for line in G.grid {
        var prev = pr(line[0])
        for k in 1..<line.count {
            let q = pr(line[k])
            if q.d > 0.45 { d.emit(.line(x0: prev.x, y0: prev.y, x1: q.x, y1: q.y, color: rgba(C.c2, 0.02 + 0.14 * q.d * q.d), width: 0.6)) }
            prev = q
        }
    }
    for v in G.sea {
        let q = pr(v)
        if q.d < 0.5 { continue }
        d.emit(.rect(x: q.x - 0.4, y: q.y - 0.4, w: 0.8, h: 0.8, color: RGBA(C.c2, 0.18 * q.d)))
    }
    for v in G.land {
        let q = pr(v)
        if q.d < 0.44 { continue }
        let r = (0.5 + 0.9 * q.d) * q.s
        d.emit(.rect(x: q.x - r / 2, y: q.y - r / 2, w: r, h: r, color: RGBA(C.c1, 0.12 + 0.78 * pow(q.d, 1.6))))
    }

    let sl = sin(ph * 0.00035) * 62
    var prev: Projected?
    for lo in stride(from: -180, through: 180, by: 4) {
        let q = pr(ll(sl, Double(lo)))
        if let p = prev, q.d > 0.5 { d.emit(.line(x0: p.x, y0: p.y, x1: q.x, y1: q.y, color: rgba(C.c1, 0.55 * q.d), width: 1.2)) }
        prev = q
    }

    for (k, arc) in G.arcs.enumerated() {
        let S = arc.map { pr($0) }
        for s in 1..<S.count {
            d.emit(.line(x0: S[s - 1].x, y0: S[s - 1].y, x1: S[s].x, y1: S[s].y, color: rgba(C.c1, 0.04 + 0.22 * S[s].d * S[s].d), width: 0.8))
        }
        if o.reduceMotion { continue }
        let t = (ph * 0.00026 + Double(k) * 0.137).truncatingRemainder(dividingBy: 1), head = t * 40
        var s = max(1, Int((head - 12).rounded(.down)))
        while Double(s) <= min(40, head) {
            let f = 1 - (head - Double(s)) / 12
            d.emit(.line(x0: S[s - 1].x, y0: S[s - 1].y, x1: S[s].x, y1: S[s].y, color: rgba(C.c1, f * (0.2 + 0.8 * S[s].d)), width: 1.8))
            s += 1
        }
        let q = S[min(40, Int(jsRound(head)))]
        d.glow(.white, q.x, q.y, 12, 0.3 + 0.7 * q.d)
    }

    for (i, p) in G.hubs.enumerated() {
        let q = pr(p)
        if q.d < 0.42 { continue }
        let a = i == o.active
        d.glow(C.c1, q.x, q.y, a ? 46 : 26, q.d)
        d.emit(.disc(x: q.x, y: q.y, r: a ? 2.6 : 1.6, color: rgba(.white, q.d)))
        if a && o.link > 0 {
            for m in 0..<2 {
                let p2 = (ts * 0.0008 + Double(m) * 0.5).truncatingRemainder(dividingBy: 1)
                d.emit(.ring(x: q.x, y: q.y, r: 4 + p2 * 24, color: rgba(C.c1, (1 - p2) * 0.7 * q.d * o.link), width: 1.2))
            }
        }
        if o.hud, let lab = o.hubLabels[i], q.d > 0.6 {
            hudLabel(&d, c1: C.c1, x: q.x, y: q.y, cx: cx, w: w, lab.title, lab.detail, al: min(1, (q.d - 0.6) * 5))
        }
    }
}
