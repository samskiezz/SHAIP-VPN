import Foundation

// Portable maths ported line-for-line from the design's draw() / renderVals().
// Foundation-only (no SwiftUI/CoreGraphics) so it can be unit-checked off-device.

// 3-argument hypot, matching JS Math.hypot(a,b,c).
@inline(__always) func hypot3(_ a: Double, _ b: Double, _ c: Double) -> Double {
    (a * a + b * b + c * c).squareRoot()
}

// gen('net', n): points in a sphere (cube-root distributed radius 0.3–1) + links
// (pairs closer than 0.42, max 5 links per point). Exact port.
func genMesh(_ n: Int) -> (pts: [[Double]], links: [(Int, Int, Double)]) {
    var pts: [[Double]] = []
    pts.reserveCapacity(n)
    for _ in 0..<n {
        let u = Double.random(in: 0..<1) * 2 - 1
        let th = Double.random(in: 0..<1) * Double.pi * 2
        let r = 0.3 + 0.7 * cbrt(Double.random(in: 0..<1))
        let s = (1 - u * u).squareRoot()
        pts.append([s * cos(th) * r, u * r, s * sin(th) * r])
    }
    var links: [(Int, Int, Double)] = []
    var deg = [Int](repeating: 0, count: n)
    for i in 0..<n {
        for j in (i + 1)..<n {
            if deg[i] > 4 || deg[j] > 4 { continue }
            let d = hypot3(pts[i][0] - pts[j][0], pts[i][1] - pts[j][1], pts[i][2] - pts[j][2])
            if d < 0.42 { links.append((i, j, d)); deg[i] += 1; deg[j] += 1 }
        }
    }
    return (pts, links)
}

// gen('globe'): 560 Fibonacci-sphere points + the 12 city hubs. Exact port.
func genGlobe() -> (pts: [[Double]], hubs: [[Double]]) {
    let N = 560
    var pts: [[Double]] = []
    pts.reserveCapacity(N)
    for i in 0..<N {
        let y = 1 - (Double(i) / Double(N - 1)) * 2
        let r = (1 - y * y).squareRoot()
        let th = Double(i) * 2.39996
        pts.append([cos(th) * r, y, sin(th) * r])
    }
    let hubs: [[Double]] = CITIES.map { (la, lo) in
        let p = la * Double.pi / 180, l = lo * Double.pi / 180
        return [cos(p) * cos(l), sin(p), cos(p) * sin(l)]
    }
    return (pts, hubs)
}

// pr(x,y,z) from draw(): rotate Y by `a`, tilt X by `b`, perspective s = 3/(3+Z).
// Returns (screenX, screenY, Z, s).
@inline(__always)
func project(_ x: Double, _ y: Double, _ z: Double,
             ca: Double, sa: Double, cb: Double, sb: Double,
             R: Double, cx: Double, cy: Double) -> (Double, Double, Double, Double) {
    let X = x * ca + z * sa
    var Z = -x * sa + z * ca
    let Y = y * cb - Z * sb
    Z = y * sb + Z * cb
    let s = 3 / (3 + Z)
    return (cx + X * R * s, cy - Y * R * s, Z, s)
}

// Live-stat curves (download/upload Mbps), jitter and session timer from renderVals().
func f(_ k: Int) -> Double { let x = Double(k); return 150 + 28 * sin(x * 0.55) + 16 * sin(x * 1.7 + 1) + 8 * sin(x * 3.1) }
func g(_ k: Int) -> Double { let x = Double(k); return 38 + 10 * sin(x * 0.8 + 2) + 6 * sin(x * 2.3) }
func jitter(_ t: Int) -> Int { Int((sin(Double(t) * 1.3) * 2).rounded()) }

func sessionTimer(_ on: Bool, _ t: Int) -> String {
    if !on { return "--:--:--" }
    let sec = 5025 + t
    return String(format: "%02d:%02d:%02d", sec / 3600, (sec / 60) % 60, sec % 60)
}
