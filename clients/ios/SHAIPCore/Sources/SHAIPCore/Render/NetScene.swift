import Foundation

// The particle mesh (`net`), a line-for-line port of genNet()/drawNet() in design/shaip-engine.js.

public struct NetNode: Sendable {
    public var p: V3
    /// Shell: 0 core, 1 mid, 2 outer.
    public var k: Int
    /// Distance from the centre (drives the pulse wave).
    public var r: Double
}

public struct NetLink: Sendable {
    public var i: Int
    public var j: Int
    public var d: Double
    /// Trunk links run from an outer hub to its nearest core node.
    public var trunk: Bool
}

public struct NetGeometry: Sendable {
    public var nodes: [NetNode]
    public var links: [NetLink]
    /// Six outer hub node indices (the first four carry HUD labels).
    public var hubs: [Int]
    /// Longest non-trunk link.
    public var maxd: Double
}

/// `genNet(n)`: seeded, deterministic mesh of n nodes in three shells, k-nearest links within the
/// same or an adjacent shell (k = 4, outer shell 3) plus 6 hub-to-core trunks.
public func genNet(_ n: Int) -> NetGeometry {
    var rng = Mulberry32(seed: 11)
    func r() -> Double { rng.next() }
    let nc = max(10, Int(jsRound(Double(n) * 0.14))), nm = Int(jsRound(Double(n) * 0.38)), no = n - nc - nm
    var P: [NetNode] = []
    P.reserveCapacity(n)
    for _ in 0..<nc {
        let u = r() * 2 - 1, t = r() * 6.283, s = (1 - u * u).squareRoot(), q = 0.08 + 0.2 * r()
        P.append(NetNode(p: V3(s * cos(t) * q, u * q, s * sin(t) * q), k: 0, r: 0))
    }
    for v in fib(nm) {
        let q = 0.56 + 0.1 * r()
        let x = v.x * q + (r() - 0.5) * 0.05
        let y = v.y * q + (r() - 0.5) * 0.05
        let z = v.z * q + (r() - 0.5) * 0.05
        P.append(NetNode(p: V3(x, y, z), k: 1, r: 0))
    }
    for v in fib(no) {
        let q = 0.97 + 0.06 * r()
        P.append(NetNode(p: V3(v.x * q, v.y * q, v.z * q), k: 2, r: 0))
    }
    for i in P.indices { P[i].r = jsHypot(P[i].p.x, P[i].p.y, P[i].p.z) }
    func D(_ a: NetNode, _ b: NetNode) -> Double {
        jsHypot(a.p.x - b.p.x, a.p.y - b.p.y, a.p.z - b.p.z)
    }

    var L: [NetLink] = []
    var seen = Set<Int>()
    for (i, a) in P.enumerated() {
        var c: [(d: Double, j: Int)] = []
        for (j, b) in P.enumerated() where i != j && abs(a.k - b.k) <= 1 {
            c.append((D(a, b), j))
        }
        // JS sorts stably by distance; candidates are built in index order, so (d, j) is equivalent.
        c.sort { $0.d != $1.d ? $0.d < $1.d : $0.j < $1.j }
        for (d, j) in c.prefix(a.k == 2 ? 3 : 4) {
            let key = i < j ? i * n + j : j * n + i
            if seen.insert(key).inserted { L.append(NetLink(i: i, j: j, d: d, trunk: false)) }
        }
    }
    var hubs: [Int] = []
    for i in 0..<6 {
        hubs.append(nc + nm + Int((Double(i) * Double(no) / 6 + Double(no) / 12).rounded(.down)))
    }
    for h in hubs {
        var best = 0, bd = 9.0
        for j in 0..<nc {
            let d = D(P[h], P[j])
            if d < bd { bd = d; best = j }
        }
        L.append(NetLink(i: h, j: best, d: bd, trunk: true))
    }
    let maxd = L.lazy.filter { !$0.trunk }.map(\.d).max() ?? 1
    return NetGeometry(nodes: P, links: L, hubs: hubs, maxd: maxd)
}

/// Per-frame inputs shared by the three scenes.
struct SceneParams {
    var mix: Double          // 1 connected … 0 disconnected (eased); mesh palette/speed/alpha follow it
    var link: Double         // the same eased connection value, for scenes that stay in colour
    var cyF: Double
    var rF: Double
    var hudClear: Double
    var hud: Bool
    var floor: Bool
    var reduceMotion: Bool
    var labels: [HUDText]
    var active: Int
    var hubLabels: [Int: HUDText]
    var radarLabels: [HUDText]
}

func drawNet(_ d: inout DrawList, w: Double, h: Double, G: NetGeometry, o: SceneParams, ph: Double, ts: Double, C: Palette) {
    let cx = w / 2, cy = h * o.cyF, R = min(w, h) * o.rF, mix = o.mix
    func lerp(_ a: Double, _ b: Double) -> Double { a + (b - a) * mix }
    let pr = Projector(a: ph * 0.00012, b: -0.3 - 0.08 * sin(ph * 0.00017), cx: cx, cy: cy, R: R)

    d.emit(.gradientRect(x: 0, y: 0, w: w, h: h, gradient: RadialGradientSpec(
        x0: cx, y0: cy, r0: 0, x1: cx, y1: cy, r1: R * 1.5,
        stops: [GradientStop(offset: 0, color: rgba(C.c1, lerp(0.04, 0.15))),
                GradientStop(offset: 0.45, color: rgba(C.c2, lerp(0.02, 0.06))),
                GradientStop(offset: 1, color: rgba(C.c2, 0))])))

    if o.floor {
        let fy = -1.3, E = 2.2, S = 0.275
        for ax in 0..<2 {
            for k in -8...8 {
                var prev: Projected?
                for m in 0...16 {
                    let u = Double(k) * S, v = -E + Double(m) * E / 8
                    let x = ax == 1 ? u : v, z = ax == 1 ? v : u
                    let q = pr(x, fy, z)
                    if let p = prev {
                        let al = 0.17 * (1 - jsHypot(x, z) / E)
                        if al > 0 { d.emit(.line(x0: p.x, y0: p.y, x1: q.x, y1: q.y, color: rgba(C.c2, al), width: 0.6)) }
                    }
                    prev = q
                }
            }
        }
        // The reflection gradient lives in the ellipse's local (translated, y-scaled) space.
        let fq = pr(0, fy, 0)
        d.emit(.gradientEllipse(tx: fq.x, ty: fq.y, sx: 1, sy: 0.3, r: R * 1.2, gradient: RadialGradientSpec(
            x0: 0, y0: 0, r0: 0, x1: 0, y1: 0, r1: R * 1.2,
            stops: [GradientStop(offset: 0, color: rgba(C.c1, lerp(0.05, 0.2))),
                    GradientStop(offset: 1, color: rgba(C.c1, 0))])))
    }

    d.setBlend(.additive)
    for (rr, tilt, sp, i) in [(1.22, 0.9, 0.00021, 0), (1.4, -0.5, -0.00014, 1), (1.1, 1.9, 0.00028, 2)] {
        let ct = cos(tilt), st = sin(tilt), rot = ph * sp, cr = cos(rot), sr = sin(rot)
        func pt(_ t: Double) -> Projected {
            let x = cos(t) * rr, z = sin(t) * rr, y2 = -z * st, z2 = z * ct
            return pr(x * cr + z2 * sr, y2, -x * sr + z2 * cr)
        }
        var prev = pt(0)
        let width = i == 1 ? 0.6 : 0.8
        for s in 1...120 {
            let q = pt(Double(s) / 120 * 6.2832)
            if !(i == 1 && s % 3 == 0) {
                d.emit(.line(x0: prev.x, y0: prev.y, x1: q.x, y1: q.y,
                             color: rgba(i == 2 ? C.c2 : C.c1, (0.04 + 0.3 * q.d * q.d) * lerp(0.5, 1)), width: width))
            }
            prev = q
        }
        if mix > 0 {
            let q = pt(ph * 0.0005 * Double(i + 1))
            d.glow(C.c1, q.x, q.y, 30 * q.s, (0.3 + 0.7 * q.d) * mix)
        }
    }

    let P = G.nodes.map { pr($0.p) }
    let wv = (ph * 0.00032).truncatingRemainder(dividingBy: 1) * 1.5 - 0.1
    let glow = G.nodes.map { max(0, 1 - abs($0.r - wv) / 0.14) * mix }
    for l in G.links {
        let A = P[l.i], B = P[l.j], dd = (A.d + B.d) / 2, lit = max(glow[l.i], glow[l.j])
        let base = l.trunk ? 0.14 : 0.05 + (1 - l.d / G.maxd) * 0.12
        let width = l.trunk ? 0.9 : 0.4 + 0.7 * dd
        let color = rgba(lit > 0.2 || l.trunk ? C.c1 : C.c2, (base + 0.36 * dd * dd) * (1 + lit * 2.2) * lerp(0.5, 1))
        d.emit(.line(x0: A.x, y0: A.y, x1: B.x, y1: B.y, color: color, width: width))
    }

    if mix > 0 && !o.reduceMotion {
        let L = G.links, K = min(44, L.count)
        for k in 0..<K {
            let l = L[(k * 61 + 7) % L.count], A = P[l.i], B = P[l.j], dd = (A.d + B.d) / 2
            let t = (ph * (0.0005 + Double(k % 5) * 0.00012) + Double(k) * 0.287).truncatingRemainder(dividingBy: 1)
            for m in stride(from: 6, through: 1, by: -1) {
                let tt = t - Double(m) * 0.03
                if tt < 0 { continue }
                d.emit(.rect(x: A.x + (B.x - A.x) * tt - 0.6, y: A.y + (B.y - A.y) * tt - 0.6, w: 1.2, h: 1.2,
                             color: rgba(C.c1, (1 - Double(m) / 7) * (0.3 + 0.7 * dd) * mix)))
            }
            let x = A.x + (B.x - A.x) * t, y = A.y + (B.y - A.y) * t
            d.glow(.white, x, y, 9, (0.3 + 0.7 * dd) * mix)
        }
    }

    // Far to near (larger Z is farther); ties keep index order, as the reference's stable sort.
    let order = P.indices.sorted { P[$0].z != P[$1].z ? P[$0].z > P[$1].z : $0 < $1 }
    let hubSet = Set(G.hubs)
    for i in order {
        let q = P[i], n = G.nodes[i], gl = glow[i], hub = hubSet.contains(i)
        let base = hub ? 3 : n.k == 0 ? 1.9 : n.k == 1 ? 1.45 : 1.15
        let r = base * q.s * (1 + gl * 1.1)
        let col = hub || n.k == 0 ? C.c1 : (i % 4 != 0 ? C.c2 : C.c1)
        let al = min(1, (0.15 + 0.85 * q.d * q.d) * lerp(0.55, 1) + gl * 0.4)
        d.glow(col, q.x, q.y, r * (hub ? 9 : 6), al)
        d.emit(.disc(x: q.x, y: q.y, r: r * 0.5, color: rgba(.white, al * (hub ? 0.95 : 0.6))))
    }

    for (idx, hI) in G.hubs.enumerated() {
        let q = P[hI]
        if q.d < 0.5 || !(mix > 0) { continue }
        let p = (ts * 0.0007 + Double(idx) * 0.19).truncatingRemainder(dividingBy: 1)
        d.emit(.ring(x: q.x, y: q.y, r: 4 + p * 18, color: rgba(C.c1, (1 - p) * 0.55 * q.d * mix), width: 1))
    }

    if o.hud {
        for (idx, hI) in G.hubs.prefix(4).enumerated() {
            let q = P[hI]
            if q.d < 0.58 { continue }
            let lab = idx < o.labels.count ? o.labels[idx] : HUDText("", "")
            if o.hudClear > 0 && jsHypot(q.x - cx, q.y - cy) < o.hudClear { continue }
            hudLabel(&d, c1: C.c1, x: q.x, y: q.y, cx: cx, w: w, lab.title, mix >= 0.5 ? lab.detail : "STANDBY",
                     al: min(1, (q.d - 0.58) * 5) * lerp(0.5, 1))
        }
    }
}
