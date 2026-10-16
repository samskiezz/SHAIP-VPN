import Foundation

// Data and copy from the design's renderVals(), as plain values the app renders. In production
// the nodes come from the signed directory (`GET /api/directory`), access from the policy engine,
// and the rest from the control plane; the shapes here are what the screens consume.

/// Semantic colour roles; the app maps them to the design tokens.
public enum Tone: String, Sendable, CaseIterable {
    case signal, steel, ok, warn, threat, secondary
}

public enum NodeTag: String, Sendable {
    case pq = "PQ", relay = "RELAY", dedicated = "DEDICATED"
}

public struct Node: Identifiable, Hashable, Sendable {
    public let code: String
    public let city: String
    public let region: String
    /// Node ID, e.g. `SYD-03`.
    public let id: String
    /// Data centre.
    public let dc: String
    /// Base RTT in ms.
    public let ms: Int
    /// Load in percent.
    public let load: Int
    public let exitIP: String
    public let tag: NodeTag?
    /// Index of this node's city in the globe's hub list.
    public let hub: Int

    /// RTT tone: ok under 50 ms, warn under 150 ms, otherwise threat.
    public var rttTone: Tone { ms < 50 ? .ok : ms < 150 ? .warn : .threat }
}

public enum NodeFilter: Int, CaseIterable, Sendable {
    case all, recommended, dedicated

    public var label: String { ["All", "Recommended", "Dedicated"][rawValue] }

    /// Recommended = green RTT (< 50 ms); Dedicated = dedicated nodes.
    public func includes(_ n: Node) -> Bool {
        switch self {
        case .all: true
        case .recommended: n.ms < 50
        case .dedicated: n.tag == .dedicated
        }
    }
}

public enum TunnelProtocol: String, CaseIterable, Identifiable, Sendable {
    case mesh, wireguard, ikev2

    public var id: String { rawValue }
    public var name: String {
        switch self {
        case .mesh: "SHAIP Mesh"
        case .wireguard: "WireGuard"
        case .ikev2: "IKEv2 / IPsec"
        }
    }
    public var tag: String? { self == .mesh ? "RECOMMENDED" : nil }
    public var summary: String {
        switch self {
        case .mesh: "WireGuard core · multi-hop · ML-KEM-768 hybrid"
        case .wireguard: "Single hop · lowest latency"
        case .ikev2: "Native iOS fallback for restricted networks"
        }
    }
    public var specs: [String] {
        switch self {
        case .mesh: ["UDP 443", "ChaCha20-Poly1305", "PQ"]
        case .wireguard: ["UDP 51820", "Curve25519"]
        case .ikev2: ["UDP 500/4500", "AES-256-GCM"]
        }
    }
}

public struct AppUsage: Identifiable, Hashable, Sendable {
    public let name: String, host: String, value: String
    public let share: Double
    public let tone: Tone
    public var id: String { name }
}

public struct PostureCheck: Identifiable, Hashable, Sendable {
    public let label: String
    public let ok: Bool
    public var id: String { label }
}

public enum AccessState: String, Sendable {
    case granted = "GRANTED", mfa = "MFA", denied = "DENIED"

    public var tone: Tone { self == .granted ? .ok : self == .mfa ? .warn : .threat }
}

public struct AccessResource: Identifiable, Hashable, Sendable {
    public let badge: String, host: String, meta: String
    public var state: AccessState
    public var id: String { host }
}

public enum AccessFilter: Int, CaseIterable, Sendable {
    case all, granted, pending

    public func includes(_ r: AccessResource) -> Bool {
        switch self {
        case .all: true
        case .granted: r.state == .granted
        case .pending: r.state == .mfa
        }
    }
}

public struct ThreatCounter: Identifiable, Hashable, Sendable {
    public let label: String, value: String
    public let tone: Tone
    public var id: String { label }
}

public struct SecurityAlert: Identifiable, Hashable, Sendable {
    public let title: String, meta: String, age: String
    public let tone: Tone
    public var id: String { title }
}

public struct TeamMember: Identifiable, Hashable, Sendable {
    public let initials: String, name: String, role: String
    public let location: String
    public let presence: Tone
    public var id: String { initials }
}

public struct DeviceRow: Identifiable, Hashable, Sendable {
    public let name: String, meta: String, state: String
    public let tone: Tone
    public var id: String { name }
}

public enum Catalog {
    public static let nodes: [Node] = [
        Node(code: "SYD", city: "Sydney", region: "AU-EAST", id: "SYD-03", dc: "Equinix SY4", ms: 14, load: 42, exitIP: "203.0.113.42", tag: .pq, hub: 0),
        Node(code: "MEL", city: "Melbourne", region: "AU-SE", id: "MEL-01", dc: "NEXTDC M2", ms: 22, load: 31, exitIP: "203.0.113.87", tag: nil, hub: 12),
        Node(code: "AKL", city: "Auckland", region: "NZ-N", id: "AKL-02", dc: "Spark DC", ms: 38, load: 18, exitIP: "198.51.100.9", tag: nil, hub: 9),
        Node(code: "SIN", city: "Singapore", region: "AP-SE", id: "SIN-01", dc: "Digital Realty", ms: 92, load: 64, exitIP: "198.51.100.140", tag: .relay, hub: 1),
        Node(code: "TYO", city: "Tokyo", region: "AP-NE", id: "TYO-04", dc: "AT Tokyo CC1", ms: 118, load: 57, exitIP: "192.0.2.61", tag: nil, hub: 2),
        Node(code: "LAX", city: "Los Angeles", region: "US-W", id: "LAX-02", dc: "CoreSite LA1", ms: 146, load: 49, exitIP: "192.0.2.200", tag: nil, hub: 6),
        Node(code: "FRA", city: "Frankfurt", region: "EU-C", id: "FRA-01", dc: "Interxion", ms: 268, load: 22, exitIP: "192.0.2.18", tag: .dedicated, hub: 3),
    ]

    /// Fleet-wide totals shown beside the lists (the lists show the nearest nodes / top resources).
    public static let edgeNodes = 42, regions = 18, routes = 12
    public static let accessTotals: [AccessFilter: Int] = [.all: 24, .granted: 19, .pending: 3]

    public static let apps: [AppUsage] = [
        AppUsage(name: "GitHub Enterprise", host: "git.acme.internal", value: "1.24 GB", share: 0.82, tone: .signal),
        AppUsage(name: "AWS Console", host: "ap-southeast-2", value: "640 MB", share: 0.48, tone: .steel),
        AppUsage(name: "Slack", host: "acme.slack.com", value: "212 MB", share: 0.22, tone: .ok),
        AppUsage(name: "Figma", host: "figma.com", value: "96 MB", share: 0.11, tone: .warn),
    ]

    /// "Patch age" turns warn when posture enforcement is off.
    public static func posture(enforced: Bool) -> [PostureCheck] {
        [PostureCheck(label: "iOS 26.1", ok: true), PostureCheck(label: "Disk encrypted", ok: true),
         PostureCheck(label: "MDM enrolled", ok: true), PostureCheck(label: "Biometrics", ok: true),
         PostureCheck(label: "Patch age 4d", ok: enforced)]
    }

    public static let trustScore = 94

    public static let resources: [AccessResource] = [
        AccessResource(badge: "GT", host: "git.acme.internal", meta: "HTTPS · Engineering", state: .granted),
        AccessResource(badge: "DB", host: "prod-db-01", meta: "Postgres 5432 · SRE", state: .mfa),
        AccessResource(badge: "SH", host: "bastion-syd", meta: "SSH 22 · JIT · 58m left", state: .granted),
        AccessResource(badge: "CI", host: "jenkins.ci", meta: "HTTPS · Platform", state: .granted),
        AccessResource(badge: "FN", host: "finance.acme", meta: "HTTPS · Finance only", state: .denied),
    ]

    public static let counters: [ThreatCounter] = [
        ThreatCounter(label: "THREATS", value: "1,284", tone: .threat),
        ThreatCounter(label: "TRACKERS", value: "9,412", tone: .steel),
        ThreatCounter(label: "PHISHING", value: "7", tone: .warn),
    ]

    public static let alerts: [SecurityAlert] = [
        SecurityAlert(title: "C2 beacon blocked", meta: "185.220.101.4 · Tor exit", age: "2m", tone: .threat),
        SecurityAlert(title: "Untrusted Wi-Fi joined", meta: "Cafe_Guest · auto-protected", age: "41m", tone: .warn),
        SecurityAlert(title: "Tunnel renegotiated", meta: "SYD-03 → SYD-04 · 0 loss", age: "1h", tone: .signal),
        SecurityAlert(title: "Posture check passed", meta: "iOS 26.1 · disk encrypted", age: "3h", tone: .ok),
    ]

    /// Threat blips currently active on the radar (genRadar's threat class).
    public static let activeThreats = 3
    public static let radarLabels = [HUDText("C2 BEACON BLOCKED", "185.220.101.4"), HUDText("PHISH DOMAIN", "acme-sso.co")]

    public static let advanced: [(key: String, value: String)] = [("PORT", "UDP 443"), ("MTU", "1420"), ("KEEPALIVE", "25 s")]
    public static let adminLocked = 2

    public static let plan = (name: "Business · Annual", seatsUsed: 148, seatsTotal: 200, devices: 311, renews: "14.03.27")
    public static let teamOnline = 96

    /// The signed-in user's row follows the tunnel.
    public static func team(connected: Bool, node: Node) -> [TeamMember] {
        [TeamMember(initials: "MC", name: "Maya Chen", role: "Security admin · you",
                    location: connected ? node.id : "OFFLINE", presence: connected ? .ok : .secondary),
         TeamMember(initials: "JR", name: "Jonah Reyes", role: "SRE", location: "SIN-01", presence: .ok),
         TeamMember(initials: "PA", name: "Priya Anand", role: "Engineering", location: "MEL-01", presence: .ok),
         TeamMember(initials: "TK", name: "Tom Kowalski", role: "Finance", location: "Idle 2h", presence: .warn)]
    }

    public static func devices(connected: Bool) -> [DeviceRow] {
        [DeviceRow(name: "iPhone 17 Pro", meta: "iOS 26.1 · this device", state: connected ? "TUNNEL UP" : "IDLE", tone: connected ? .ok : .secondary),
         DeviceRow(name: "MacBook Pro 14\"", meta: "macOS 26 · SYD-03", state: "TUNNEL UP", tone: .ok)]
    }

    /// Mesh HUD: the selected node first (ACTIVE), then up to three others — never the same ID twice.
    public static func meshLabels(node: Node, rtt: Int) -> [HUDText] {
        let others = [HUDText("SIN-01", "RELAY · 92ms"), HUDText("TYO-04", "STANDBY · 118ms"),
                      HUDText("FRA-01", "DEDICATED · 268ms"), HUDText("SYD-03", "STANDBY · 14ms")]
        return [HUDText(node.id, "ACTIVE · \(rtt)ms")] + others.filter { $0.title != node.id }.prefix(3)
    }

    /// Globe HUD: four landmark hubs plus the selected node's hub, which reads ACTIVE or STANDBY.
    public static func globeLabels(node: Node, rtt: Int, connected: Bool) -> [Int: HUDText] {
        var l: [Int: HUDText] = [0: HUDText("SYD-03", "14ms"), 1: HUDText("SIN-01", "92ms · RELAY"),
                                 2: HUDText("TYO-04", "118ms"), 9: HUDText("AKL-02", "38ms")]
        l[node.hub] = HUDText(node.id, connected ? "\(rtt)ms · ACTIVE" : "STANDBY")
        return l
    }
}
