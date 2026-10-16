import Foundation
import Testing
@testable import SHAIPCore

@Suite("Catalogue, telemetry and screen logic")
struct CatalogTests {
    private var telemetry: [String: Any] {
        let url = Bundle.module.url(forResource: "engine-vectors", withExtension: "json", subdirectory: "Fixtures")!
        let obj = try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        return obj["telemetry"] as! [String: Any]
    }

    @Test("node table matches the handoff, sorted by RTT, every node on the globe")
    func nodes() {
        let n = Catalog.nodes
        #expect(n.map(\.code) == ["SYD", "MEL", "AKL", "SIN", "TYO", "LAX", "FRA"])
        #expect(n.map(\.ms) == n.map(\.ms).sorted(), "SORT · RTT ASC")
        #expect(n[0].id == "SYD-03" && n[0].dc == "Equinix SY4" && n[0].exitIP == "203.0.113.42" && n[0].tag == .pq)
        #expect(n[6].id == "FRA-01" && n[6].region == "EU-C" && n[6].load == 22 && n[6].tag == .dedicated)
        for node in n { #expect(CITIES[node.hub].code == node.code, "\(node.code) hub") }
        #expect(n.map(\.rttTone) == [.ok, .ok, .ok, .warn, .warn, .warn, .threat])
    }

    @Test("segments filter the lists they label")
    func filters() {
        #expect(Catalog.nodes.filter(NodeFilter.recommended.includes).map(\.code) == ["SYD", "MEL", "AKL"])
        #expect(Catalog.nodes.filter(NodeFilter.dedicated.includes).map(\.code) == ["FRA"])
        #expect(Catalog.resources.filter(AccessFilter.granted.includes).count == 3)
        #expect(Catalog.resources.filter(AccessFilter.pending.includes).map(\.host) == ["prod-db-01"])
    }

    @Test("HUD labels never repeat a node ID and follow the selection")
    func labels() {
        for node in Catalog.nodes {
            let mesh = Catalog.meshLabels(node: node, rtt: node.ms)
            #expect(mesh.count == 4 && mesh[0].title == node.id && Set(mesh.map(\.title)).count == 4)
            let on = Catalog.globeLabels(node: node, rtt: node.ms, connected: true)
            #expect(on[node.hub] == HUDText(node.id, "\(node.ms)ms · ACTIVE"))
            #expect(Catalog.globeLabels(node: node, rtt: node.ms, connected: false)[node.hub]?.detail == "STANDBY")
        }
        #expect(Catalog.radarLabels.count == 2 && genRadar().threats.count == Catalog.activeThreats)
    }

    @Test("telemetry strings match renderVals (toFixed, Math.round)")
    func telemetryStrings() {
        let t = telemetry
        let ticks = t["ticks"] as! [Int]
        let node = Catalog.nodes[0]
        for (i, k) in ticks.enumerated() {
            let s = MockTelemetry.sample(tick: k, node: node)
            #expect(Format.fixed(s.downMbps, 1) == (t["down"] as! [String])[i], "down \(k)")
            #expect(Format.fixed(s.downMbps, 0) == (t["downInt"] as! [String])[i], "down int \(k)")
            #expect(Format.fixed(s.upMbps, 1) == (t["up"] as! [String])[i], "up \(k)")
            #expect(s.rttMs == (t["rtt14"] as! [Int])[i], "rtt \(k)")
            #expect(Format.fixed(s.jitterMs, 1) == (t["jitter"] as! [String])[i], "jitter \(k)")
            #expect(Format.fixed(s.sessionGB, 2) == (t["session"] as! [String])[i], "session \(k)")
            #expect(Format.fixed(s.packetsM, 2) == (t["packets"] as! [String])[i], "packets \(k)")
        }
        let bars = t["bars"] as! [[[String]]]
        for (ri, row) in [0, 3, 6].enumerated() {
            for (ti, tick) in [0, 1, 77].enumerated() {
                #expect(MockTelemetry.sparkline(row: row, tick: tick).map { Format.fixed($0, 1) } == bars[ri][ti])
            }
        }
    }

    @Test("history keeps the past when the tunnel drops, and PK is the real peak")
    func history() {
        var h = ThroughputHistory(endingAt: 0)
        #expect(h.down.count == 48 && h.down.last == MockTelemetry.down(0) && h.down.first == MockTelemetry.down(-47))
        #expect(h.peak <= 202 && h.peak == h.down.max())      // 150 + 28 + 16 + 8; the handoff hard-coded 212.4
        for _ in 0..<10 { h.push(down: 0, up: 0) }
        #expect(h.down.suffix(10).allSatisfy { $0 == 0 } && h.down.prefix(38).allSatisfy { $0 > 0 })
        #expect(h.peak > 0)
    }

    @Test("session clock and orb arc")
    func clock() {
        #expect(Format.clock(nil) == "--:--:--")
        #expect(Format.clock(5025) == "01:23:45")
        #expect(Format.clock(0) == "00:00:00")
        #expect(Format.clock(36_000 + 59) == "10:00:59")
        #expect(Format.orbArc(sessionSeconds: nil) == 0)
        #expect(Format.orbArc(sessionSeconds: 30) == 300 / 629.0)
        #expect(Format.orbArc(sessionSeconds: 59) == 590 / 629.0)
    }

    @Test("easing is monotone and lands exactly on 0 and 1")
    func easing() {
        #expect(ease(0) == 0 && ease(1) == 1 && ease(0.5) == 0.5)
        var prev = -1.0
        for i in 0...100 { let v = ease(Double(i) / 100); #expect(v >= prev); prev = v }
    }
}
