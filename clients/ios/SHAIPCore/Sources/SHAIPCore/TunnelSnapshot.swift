import Foundation

/// What the tunnel extension reports to the app (as JSON over
/// `sendProviderMessage`), built from the Rust core's `ShaipStatus`. Every
/// field is measured or negotiated, never estimated: if something is not
/// known it is `nil`, and the app shows a dash.
public struct TunnelSnapshot: Codable, Hashable, Sendable {
    public enum State: String, Codable, Sendable {
        /// A server-confirmed session carries traffic.
        case connected
        /// The last session failed; a new one is being negotiated. Traffic is
        /// dropped meanwhile, not sent around the tunnel.
        case reconnecting
        case stopped
    }

    public var state: State
    /// Tunnel address and prefix the server assigned, e.g. `10.77.0.23/24`.
    public var tunnelAddress: String?
    /// Resolver pushed by the server (reached through the tunnel), if any.
    public var dns: String?
    public var mtu: Int
    /// Smoothed keepalive round-trip time.
    public var rttMs: Double?
    /// When the link came up (a rekey does not reset it).
    public var upSince: Date?
    public var reconnects: Int
    public var rekeys: Int
    public var bytesSent: UInt64
    public var bytesReceived: UInt64
    public var packetsSent: UInt64
    public var packetsReceived: UInt64
    /// Datagrams that did not authenticate (replays, tampering, strays).
    public var packetsRejected: UInt64
    /// Outbound packets dropped while no session was up.
    public var droppedOffline: UInt64
    /// IPv6 packets the extension dropped (the tunnel carries IPv4 only, so
    /// IPv6 is routed into it and discarded rather than leaking outside).
    public var ipv6Dropped: UInt64
    /// The server's UDP address as resolved.
    public var serverAddress: String?
    /// The server's identity id, proven by the handshake (hex, 16 bytes).
    public var serverIdentity: String?
    public var lastError: String?
    public var sampledAt: Date

    public init(state: State, tunnelAddress: String? = nil, dns: String? = nil, mtu: Int = 0, rttMs: Double? = nil,
                upSince: Date? = nil, reconnects: Int = 0, rekeys: Int = 0, bytesSent: UInt64 = 0, bytesReceived: UInt64 = 0,
                packetsSent: UInt64 = 0, packetsReceived: UInt64 = 0, packetsRejected: UInt64 = 0, droppedOffline: UInt64 = 0,
                ipv6Dropped: UInt64 = 0, serverAddress: String? = nil, serverIdentity: String? = nil, lastError: String? = nil,
                sampledAt: Date = Date()) {
        self.state = state
        self.tunnelAddress = tunnelAddress
        self.dns = dns
        self.mtu = mtu
        self.rttMs = rttMs
        self.upSince = upSince.map(Self.wholeMilliseconds)
        self.reconnects = reconnects
        self.rekeys = rekeys
        self.bytesSent = bytesSent
        self.bytesReceived = bytesReceived
        self.packetsSent = packetsSent
        self.packetsReceived = packetsReceived
        self.packetsRejected = packetsRejected
        self.droppedOffline = droppedOffline
        self.ipv6Dropped = ipv6Dropped
        self.serverAddress = serverAddress
        self.serverIdentity = serverIdentity
        self.lastError = lastError
        self.sampledAt = Self.wholeMilliseconds(sampledAt)
    }

    /// Dates travel as whole milliseconds; keeping them at that precision
    /// makes the JSON round trip exact.
    static func wholeMilliseconds(_ d: Date) -> Date {
        Date(timeIntervalSince1970: Double(Int64((d.timeIntervalSince1970 * 1000).rounded())) / 1000)
    }

    public static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .custom { date, encoder in
            var c = encoder.singleValueContainer()
            try c.encode(Int64((date.timeIntervalSince1970 * 1000).rounded()))
        }
        return e
    }()

    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { decoder in
            Date(timeIntervalSince1970: Double(try decoder.singleValueContainer().decode(Int64.self)) / 1000)
        }
        return d
    }()

    public func encoded() throws -> Data { try Self.encoder.encode(self) }

    public static func decode(_ data: Data) throws -> TunnelSnapshot { try decoder.decode(TunnelSnapshot.self, from: data) }
}

/// IPv4 helpers for the C ABI's host-order integers.
public enum IPv4 {
    /// `0x0A4D0017` → `"10.77.0.23"`; nil for 0 (none).
    public static func string(_ v: UInt32) -> String? {
        guard v != 0 else { return nil }
        return "\(v >> 24).\((v >> 16) & 0xFF).\((v >> 8) & 0xFF).\(v & 0xFF)"
    }

    /// `24` → `"255.255.255.0"`.
    public static func mask(prefix: Int) -> String {
        let p = max(0, min(32, prefix))
        let bits: UInt32 = p == 0 ? 0 : UInt32.max << UInt32(32 - p)
        return string(bits) ?? "0.0.0.0"
    }

    /// The host of `ip:port` for an IPv4 endpoint.
    public static func host(ofEndpoint s: String) -> String? {
        guard !s.hasPrefix("["), let colon = s.lastIndex(of: ":") else { return nil }
        let h = String(s[..<colon])
        return h.split(separator: ".").count == 4 ? h : nil
    }
}
