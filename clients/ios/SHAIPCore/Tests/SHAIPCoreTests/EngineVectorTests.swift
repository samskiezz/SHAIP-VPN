import Foundation
import Testing
@testable import SHAIPCore

// Cross-language check of the render engines against design/shaip-engine.js.
//
// Fixtures/engine-vectors.json is produced by scripts/engine-vectors.mjs, which drives the
// reference engine's own draw() through a recording canvas. Each scenario is a timeline of
// (timestamp, option) frames; for the recorded frames we must reproduce the op counts and the
// FNV-1a 64 hash of the canonical op text, i.e. every draw call, in order, to 1e-4.

// MARK: canonical text — keep in step with the recorder in scripts/engine-vectors.mjs

private func q(_ v: Double) -> String { String(Int((v * 1e4 + 0.5).rounded(.down))) }
private func col(_ c: RGBA) -> String { "\(c.rgb.r),\(c.rgb.g),\(c.rgb.b),\(q(c.a))" }
private func stops(_ s: [GradientStop]) -> String { s.map { "\(q($0.offset)),\(col($0.color))" }.joined(separator: ",") }
private func grad(_ g: RadialGradientSpec) -> String {
    [q(g.x0), q(g.y0), q(g.r0), q(g.x1), q(g.y1), q(g.r1), stops(g.stops)].joined(separator: ",")
}

extension DrawOp {
    var canonical: String {
        switch self {
        case .blend(let b): return "B,\(b.rawValue)"
        case let .line(x0, y0, x1, y1, c, w): return "L,\(q(x0)),\(q(y0)),\(q(x1)),\(q(y1)),\(col(c)),\(q(w))"
        case let .ring(x, y, r, c, w): return "R,\(q(x)),\(q(y)),\(q(r)),\(col(c)),\(q(w))"
        case let .disc(x, y, r, c): return "D,\(q(x)),\(q(y)),\(q(r)),\(col(c))"
        case let .rect(x, y, w, h, c): return "Q,\(q(x)),\(q(y)),\(q(w)),\(q(h)),\(col(c))"
        case let .sprite(c, x, y, s, a): return "S,\(c.r),\(c.g),\(c.b),\(q(x)),\(q(y)),\(q(s)),\(q(a))"
        case let .text(t, x, y, al, c): return "T,\(t),\(q(x)),\(q(y)),\(al.rawValue),\(col(c))"
        case let .gradientRect(x, y, w, h, g): return "GR,\(q(x)),\(q(y)),\(q(w)),\(q(h)),\(grad(g))"
        case let .gradientDisc(x, y, r, g): return "GD,\(q(x)),\(q(y)),\(q(r)),\(grad(g))"
        case let .gradientEllipse(tx, ty, sx, sy, r, g): return "GE,\(q(tx)),\(q(ty)),\(q(sx)),\(q(sy)),\(q(r)),\(grad(g))"
        case let .conicDisc(x, y, r, g): return "GC,\(q(x)),\(q(y)),\(q(r)),\(q(g.angle)),\(q(g.x)),\(q(g.y)),\(stops(g.stops))"
        }
    }

    var kind: String { String(canonical.prefix { $0 != "," }) }
}

private func fnv1a64(_ s: String) -> String {
    var h: UInt64 = 0xcbf2_9ce4_8422_2325
    for b in s.utf8 {
        h ^= UInt64(b)
        h = h &* 0x0000_0100_0000_01b3
    }
    let hex = String(h, radix: 16)
    return String(repeating: "0", count: 16 - hex.count) + hex
}

// MARK: fixture

private struct Fixture {
    let root: [String: Any]

    nonisolated(unsafe) static let shared: Fixture = {
        let url = Bundle.module.url(forResource: "engine-vectors", withExtension: "json", subdirectory: "Fixtures")!
        let obj = try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        return Fixture(root: obj)
    }()

    var scenarios: [[String: Any]] { root["scenarios"] as! [[String: Any]] }
    var base: [String: Any] { root["base"] as! [String: Any] }
    var geometry: [String: Any] { root["geometry"] as! [String: Any] }
}

private func labels(_ v: Any?) -> [HUDText] {
    (v as? [[String]] ?? []).map { HUDText($0[0], $0[1]) }
}

private func hubLabels(_ v: Any?) -> [Int: HUDText] {
    var out: [Int: HUDText] = [:]
    for (k, l) in v as? [String: [String]] ?? [:] { out[Int(k)!] = HUDText(l[0], l[1]) }
    return out
}

private func double(_ v: Any?) -> Double? {
    if let d = v as? Double { return d }
    if let s = v as? String { return Double(s) }
    if let n = v as? NSNumber { return n.doubleValue }
    return nil
}

/// Replays one scenario and returns (frame index → ops) for its recorded frames.
private func replay(_ sc: [String: Any], base: [String: Any]) -> [Int: [DrawOp]] {
    let mode = SceneMode(rawValue: sc["gfx"] as! String)!
    let w = double(sc["w"])!, h = double(sc["h"])!
    let data = sc["data"] as? [String: Any] ?? [:]
    let layout = SceneLayout(cy: double(data["cy"]) ?? 0.5,
                             r: double(data["r"]) ?? (mode == .globe ? 0.38 : mode == .radar ? 0.4 : 0.34),
                             hudClear: double(data["hudClear"]) ?? 0)
    let recorded = Set((sc["recorded"] as! [[String: Any]]).map { $0["frame"] as! Int })
    let renderer = SceneRenderer(mode: mode)
    var out: [Int: [DrawOp]] = [:]
    for (i, f) in (sc["frames"] as! [[String: Any]]).enumerated() {
        var o = SceneOptions()
        o.connected = f["connected"] as? Bool ?? true
        o.density = f["density"] as? Int ?? base["density"] as! Int
        o.hud = f["hud"] as? Bool ?? base["hud"] as! Bool
        o.floor = f["floor"] as? Bool ?? base["floor"] as! Bool
        o.reduceMotion = f["reduceMotion"] as? Bool ?? false
        o.labels = labels(base["labels"])
        o.activeHub = f["active"] as? Int ?? base["active"] as! Int
        o.hubLabels = hubLabels(f["hubLabels"] ?? base["hubLabels"])
        o.radarLabels = labels(base["radar"])
        let ops = renderer.frame(width: w, height: h, ts: double(f["ts"])!, layout: layout, options: o)
        if recorded.contains(i) { out[i] = ops }
    }
    return out
}

// MARK: tests

@Suite("Render engines reproduce design/shaip-engine.js")
struct EngineVectorTests {
    @Test("seeded generator matches mulberry32")
    func rng() {
        let g = Fixture.shared.geometry
        var r11 = Mulberry32(seed: 11), r5 = Mulberry32(seed: 5)
        // the fixture stores k for each output k / 2^32, which survives JSON exactly
        #expect((0..<8).map { _ in Int(r11.next() * 4_294_967_296) } == (g["rng11"] as! [Int]))
        #expect((0..<8).map { _ in Int(r5.next() * 4_294_967_296) } == (g["rng5"] as! [Int]))
    }

    @Test("mesh, globe and radar geometry match", arguments: [60, 170, 210])
    func netGeometry(n: Int) {
        let ref = (Fixture.shared.geometry["net"] as! [String: Any])[String(n)] as! [String: Any]
        let G = genNet(n)
        #expect(G.nodes.count == ref["nodes"] as! Int)
        #expect(G.links.count == ref["links"] as! Int)
        #expect(G.links.filter(\.trunk).count == ref["trunks"] as! Int)
        #expect(G.hubs == ref["hubs"] as! [Int])
        #expect(abs(G.maxd - (ref["maxd"] as! Double)) < 1e-12)   // JSON doubles lose the last ulp on Linux
        let text = G.nodes.map { "\($0.k),\(q($0.p.x)),\(q($0.p.y)),\(q($0.p.z)),\(q($0.r))" }.joined(separator: "\n")
            + "\n#\n" + G.links.map { "\($0.i),\($0.j),\(q($0.d)),\($0.trunk ? 1 : 0)" }.joined(separator: "\n")
            + "\n#\n" + G.hubs.map(String.init).joined(separator: ",") + "," + q(G.maxd)
        #expect(fnv1a64(text) == ref["fnv"] as! String)
    }

    @Test func globeAndRadarGeometry() {
        let g = Fixture.shared.geometry
        let globe = g["globe"] as! [String: Any], radar = g["radar"] as! [String: Any]
        let G = genGlobe()
        #expect(G.land.count == globe["land"] as! Int)
        #expect(G.sea.count == globe["sea"] as! Int)
        #expect(G.grid.count == globe["grid"] as! Int)
        #expect(G.hubs.count == globe["hubs"] as! Int)
        #expect(G.arcs.count == globe["arcs"] as! Int)
        let pts = [G.land, G.sea].map { $0.map { "\(q($0.x)),\(q($0.y)),\(q($0.z))" }.joined(separator: ";") }.joined(separator: "#")
        #expect(fnv1a64(pts) == globe["fnv"] as! String)
        let R = genRadar()
        #expect(R.blips.count == radar["blips"] as! Int)
        #expect(R.threats == radar["threats"] as! [Int])
        #expect(R.blips.filter { $0.s == .warn }.count == radar["warns"] as! Int)
        #expect(fnv1a64(R.blips.map { "\(q($0.a)),\(q($0.r)),\($0.s.rawValue)" }.joined(separator: ";")) == radar["fnv"] as! String)
    }

    @Test("every recorded frame matches op for op",
          arguments: Fixture.shared.scenarios.map { $0["name"] as! String })
    func frames(scenario name: String) throws {
        let fx = Fixture.shared
        let sc = try #require(fx.scenarios.first { $0["name"] as? String == name })
        let got = replay(sc, base: fx.base)
        let dump = ProcessInfo.processInfo.environment["SHAIP_DUMP_DIR"]
        for rec in sc["recorded"] as! [[String: Any]] {
            let i = rec["frame"] as! Int
            let ops = try #require(got[i])
            let lines = ops.map(\.canonical)
            if let dump {
                try? (lines.joined(separator: "\n") + "\n").write(toFile: "\(dump)/\(name)-\(i).txt", atomically: true, encoding: .utf8)
            }
            var counts: [String: Int] = [:]
            for op in ops { counts[op.kind, default: 0] += 1 }
            #expect(ops.count == rec["ops"] as! Int, "\(name) #\(i): op count")
            #expect(counts == rec["counts"] as! [String: Int], "\(name) #\(i): op kinds")
            let head = rec["head"] as! [String]
            for (k, line) in head.enumerated() where k < lines.count {
                #expect(lines[k] == line, "\(name) #\(i): op \(k)")
            }
            #expect(fnv1a64(lines.joined(separator: "\n")) == rec["fnv"] as! String, "\(name) #\(i): op stream hash")
        }
    }
}
