import Foundation

/// A point or vector in the renderers' unit space.
public struct V3: Hashable, Sendable {
    public var x: Double
    public var y: Double
    public var z: Double

    @inline(__always) public init(_ x: Double, _ y: Double, _ z: Double) {
        self.x = x; self.y = y; self.z = z
    }
}

/// The engine's seeded generator (mulberry32), bit-for-bit, so meshes and radars are identical
/// to the design reference on every device.
public struct Mulberry32: Sendable {
    private var seed: UInt32

    public init(seed: Int32) { self.seed = UInt32(bitPattern: seed) }

    public mutating func next() -> Double {
        seed = seed &+ 0x6D2B_79F5
        var t = (seed ^ (seed >> 15)) &* (1 | seed)
        t = (t &+ ((t ^ (t >> 7)) &* (61 | t))) ^ t
        return Double(t ^ (t >> 14)) / 4_294_967_296
    }
}

/// `fib(n)`: n points on the unit sphere (Fibonacci lattice).
public func fib(_ n: Int) -> [V3] {
    var o: [V3] = []
    o.reserveCapacity(n)
    for i in 0..<n {
        let y = 1 - (Double(i) + 0.5) / Double(n) * 2
        let r = (1 - y * y).squareRoot()
        let th = Double(i) * 2.399963
        o.append(V3(cos(th) * r, y, sin(th) * r))
    }
    return o
}

/// `ll(lat, lon)`: degrees to a unit vector (y up).
public func ll(_ la: Double, _ lo: Double) -> V3 {
    let p = la * Double.pi / 180, l = lo * Double.pi / 180
    return V3(cos(p) * cos(l), sin(p), cos(p) * sin(l))
}

/// `Math.hypot` exactly as V8 computes it (scaled by the largest magnitude, Kahan-compensated), so
/// the mesh's nearest-neighbour distances — and therefore its links — match the reference exactly.
@inline(__always) public func jsHypot(_ a: Double, _ b: Double) -> Double {
    jsHypot(a, b, 0, count: 2)
}

@inline(__always) public func jsHypot(_ a: Double, _ b: Double, _ c: Double) -> Double {
    jsHypot(a, b, c, count: 3)
}

@inline(__always) private func jsHypot(_ a: Double, _ b: Double, _ c: Double, count: Int) -> Double {
    let v0 = abs(a), v1 = abs(b), v2 = abs(c)
    var m = 0.0
    if v0 > m { m = v0 }
    if v1 > m { m = v1 }
    if count == 3, v2 > m { m = v2 }
    if m == .infinity { return .infinity }
    if m == 0 { return 0 }
    var sum = 0.0, comp = 0.0
    @inline(__always) func add(_ v: Double) {
        let n = v / m
        let summand = n * n - comp
        let pre = sum + summand
        comp = (pre - sum) - summand
        sum = pre
    }
    add(v0)
    add(v1)
    if count == 3 { add(v2) }
    return sum.squareRoot() * m
}

/// A projected point: screen x/y, view-space depth Z, perspective scale s, and depth factor
/// d = clamp((1 − Z) / 2) that drives alpha and size (near points brighter and larger).
public struct Projected: Sendable {
    public var x: Double
    public var y: Double
    public var z: Double
    public var s: Double
    public var d: Double
}

/// `proj(a, b, cx, cy, R, cam)`: rotate about Y by `a`, tilt about X by `b`, then perspective
/// `s = cam / (cam + Z)`.
public struct Projector: Sendable {
    let ca: Double, sa: Double, cb: Double, sb: Double
    let cx: Double, cy: Double, R: Double, cam: Double

    public init(a: Double, b: Double, cx: Double, cy: Double, R: Double, cam: Double = 3.2) {
        ca = cos(a); sa = sin(a); cb = cos(b); sb = sin(b)
        self.cx = cx; self.cy = cy; self.R = R; self.cam = cam
    }

    @inline(__always) public func callAsFunction(_ x: Double, _ y: Double, _ z: Double) -> Projected {
        let X = x * ca + z * sa
        var Z = -x * sa + z * ca
        let Y = y * cb - Z * sb
        Z = y * sb + Z * cb
        let s = cam / (cam + Z)
        return Projected(x: cx + X * R * s, y: cy - Y * R * s, z: Z, s: s, d: max(0, min(1, (1 - Z) / 2)))
    }

    @inline(__always) public func callAsFunction(_ p: V3) -> Projected { self(p.x, p.y, p.z) }
}

/// JS `Math.round` for the magnitudes used here: ties go towards +∞ (Swift's default goes away
/// from zero, which differs for negative halves such as −1.5).
@inline(__always) public func jsRound(_ x: Double) -> Double { (x + 0.5).rounded(.down) }
