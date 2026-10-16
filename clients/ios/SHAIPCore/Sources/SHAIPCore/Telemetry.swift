import Foundation

/// Turns the tunnel's cumulative byte counters into rates. Nothing here is
/// estimated: a rate is bytes that actually crossed the tunnel, divided by the
/// time between two snapshots.
public struct RateMeter: Sendable {
    private var last: (received: UInt64, sent: UInt64, at: Date)?

    public init() {}

    /// Mbit/s down and up since the previous snapshot. The first snapshot, or
    /// one whose counters went backwards (a new tunnel), yields zero.
    public mutating func update(received: UInt64, sent: UInt64, at now: Date) -> (down: Double, up: Double) {
        defer { last = (received, sent, now) }
        guard let last, received >= last.received, sent >= last.sent else { return (0, 0) }
        let dt = now.timeIntervalSince(last.at)
        guard dt > 0.05 else { return (0, 0) }
        let mbps = { (bytes: UInt64) in Double(bytes) * 8 / dt / 1_000_000 }
        return (mbps(received - last.received), mbps(sent - last.sent))
    }

    public mutating func reset() { last = nil }
}

/// The 48-sample, 1 Hz throughput history behind the Traffic chart (T−47 s … now).
public struct ThroughputHistory: Hashable, Sendable {
    public static let capacity = 48
    public private(set) var down: [Double]
    public private(set) var up: [Double]

    /// Empty (all zeros): the chart starts at the first real measurement.
    public init() {
        down = Array(repeating: 0, count: Self.capacity)
        up = Array(repeating: 0, count: Self.capacity)
    }

    /// Append the newest sample; zeros while disconnected, so the past stays visible.
    public mutating func push(down d: Double, up u: Double) {
        down.removeFirst(); down.append(d)
        up.removeFirst(); up.append(u)
    }

    /// Window peak.
    public var peak: Double { down.max() ?? 0 }

    /// A chart ceiling just above the window's largest value (≥ 1 Mbit/s).
    public var scale: Double {
        let top = max(down.max() ?? 0, up.max() ?? 0)
        guard top > 1 else { return 1 }
        let magnitude = pow(10, floor(log10(top)))
        return (top / magnitude).rounded(.up) * magnitude
    }
}

public enum Format {
    /// `hh:mm:ss`, or `--:--:--` with no session.
    public static func clock(_ seconds: Int?) -> String {
        guard let s = seconds, s >= 0 else { return "--:--:--" }
        func two(_ v: Int) -> String { v < 10 ? "0\(v)" : "\(v)" }
        return "\(two(s / 3600)):\(two((s / 60) % 60)):\(two(s % 60))"
    }

    /// Fixed decimals.
    public static func fixed(_ v: Double, _ digits: Int) -> String {
        String(format: "%.\(digits)f", v)
    }

    /// A rate in Mbit/s with sensible precision (`0.42`, `8.6`, `141`).
    public static func mbps(_ v: Double) -> String {
        v < 1 ? fixed(v, 2) : v < 100 ? fixed(v, 1) : fixed(v, 0)
    }

    /// Bytes in binary units (`812 B`, `3.4 KB`, `1.24 GB`).
    public static func bytes(_ n: UInt64) -> (value: String, unit: String) {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = Double(n), i = 0
        while v >= 1024, i < units.count - 1 { v /= 1024; i += 1 }
        return (i == 0 ? "\(n)" : fixed(v, v < 10 ? 2 : v < 100 ? 1 : 0), units[i])
    }

    /// A count with a metric suffix (`950`, `12.4K`, `3.10M`).
    public static func count(_ n: UInt64) -> String {
        n < 1000 ? "\(n)" : n < 1_000_000 ? fixed(Double(n) / 1000, 1) + "K" : fixed(Double(n) / 1_000_000, 2) + "M"
    }

    /// Progress arc around the orb: 300…590 of a 629 circumference, cycling every 30 s of session.
    public static func orbArc(sessionSeconds s: Int?) -> Double {
        guard let s else { return 0 }
        return (300 + Double(s % 30) * 10) / 629
    }

    /// The first `n` hex characters of an identity, grouped for reading.
    public static func fingerprint(_ hex: String?, groups: Int = 4) -> String {
        guard let hex, !hex.isEmpty else { return "—" }
        let chars = Array(hex.prefix(groups * 4))
        return stride(from: 0, to: chars.count, by: 4).map { String(chars[$0..<min($0 + 4, chars.count)]) }.joined(separator: " ")
    }
}
