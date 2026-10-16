import Foundation

/// One 1 Hz telemetry reading. In production it comes from the tunnel provider
/// (`NETunnelProviderSession.sendProviderMessage`): rx/tx byte deltas → Mbps, the WireGuard
/// handshake time and the keepalive RTT. `MockTelemetry` reproduces the design's sine curves.
public struct TelemetrySample: Hashable, Sendable {
    public var downMbps: Double
    public var upMbps: Double
    public var rttMs: Int
    public var jitterMs: Double
    public var lossPct: Double
    public var sessionGB: Double
    public var packetsM: Double
}

public enum MockTelemetry {
    /// `f(k)`: download Mbps.
    public static func down(_ k: Int) -> Double {
        let x = Double(k)
        return 150 + 28 * sin(x * 0.55) + 16 * sin(x * 1.7 + 1) + 8 * sin(x * 3.1)
    }

    /// `g(k)`: upload Mbps.
    public static func up(_ k: Int) -> Double {
        let x = Double(k)
        return 38 + 10 * sin(x * 0.8 + 2) + 6 * sin(x * 2.3)
    }

    /// Base RTT plus ±2 ms of jitter, rounded the way JS rounds (ties towards +∞).
    public static func rtt(base: Int, tick: Int) -> Int {
        base + Int(jsRound(sin(Double(tick) * 1.3) * 2))
    }

    public static func sample(tick t: Int, node: Node) -> TelemetrySample {
        TelemetrySample(downMbps: down(t), upMbps: up(t), rttMs: rtt(base: node.ms, tick: t),
                        jitterMs: 1.2 + abs(sin(Double(t))) * 0.6, lossPct: 0.02,
                        sessionGB: 2.41 + Double(t) * 0.018, packetsM: 1.84 + Double(t) * 0.0021)
    }

    /// Node-row sparkline: 16 bar heights (pt), 3…16.
    public static func sparkline(row: Int, tick: Int) -> [Double] {
        (0..<16).map { k in 3 + 13 * abs(sin(Double(k) * 1.7 + Double(row) * 0.9 + Double(tick) * 0.35)) }
    }
}

/// The 48-sample, 1 Hz throughput history behind the Traffic chart (T−47 s … now).
public struct ThroughputHistory: Hashable, Sendable {
    public static let capacity = 48
    public private(set) var down: [Double]
    public private(set) var up: [Double]

    /// Seeded as if connected for the past 48 s, as the design opens.
    public init(endingAt tick: Int) {
        let ks = (tick - Self.capacity + 1)...tick
        down = ks.map(MockTelemetry.down)
        up = ks.map(MockTelemetry.up)
    }

    /// Append the newest sample; zeros while disconnected, so the past stays visible.
    public mutating func push(down d: Double, up u: Double) {
        down.removeFirst(); down.append(d)
        up.removeFirst(); up.append(u)
    }

    /// Window peak (the design's "PK").
    public var peak: Double { down.max() ?? 0 }
}

public enum Format {
    /// `hh:mm:ss`, or `--:--:--` with no session.
    public static func clock(_ seconds: Int?) -> String {
        guard let s = seconds, s >= 0 else { return "--:--:--" }
        func two(_ v: Int) -> String { v < 10 ? "0\(v)" : "\(v)" }
        return "\(two(s / 3600)):\(two((s / 60) % 60)):\(two(s % 60))"
    }

    /// Fixed decimals, as JS `toFixed` for the values the screens show.
    public static func fixed(_ v: Double, _ digits: Int) -> String {
        String(format: "%.\(digits)f", v)
    }

    /// Progress arc around the orb: 300…590 of a 629 circumference, cycling every 30 s of session.
    public static func orbArc(sessionSeconds s: Int?) -> Double {
        guard let s else { return 0 }
        return (300 + Double(s % 30) * 10) / 629
    }

    /// "Ns ago" since the last WireGuard handshake (rekeys every 120 s).
    public static func handshake(tick: Int) -> String { "\(tick % 120)s ago" }
}
