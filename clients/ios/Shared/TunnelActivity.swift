import ActivityKit
import AppIntents
import Foundation

/// The lock-screen Live Activity and Dynamic Island for a tunnel session.
/// Every value is real: the app fills it from the tunnel extension's status.
/// It updates at most every 15 s; the session clock ticks on its own via
/// `Text(timerInterval:)`, so it never needs per-second updates.
struct TunnelActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        /// A confirmed session is carrying traffic right now.
        var connected: Bool
        /// The tunnel is negotiating a new session (traffic is held meanwhile).
        var reconnecting: Bool
        /// The server's name as configured.
        var server: String
        /// The tunnel address the server assigned, if any.
        var tunnelAddress: String?
        var sessionStart: Date?
        /// Measured download rate.
        var downMbps: Double?
        /// Measured keepalive round-trip time.
        var rttMs: Int?
    }

    /// The server label, for the activity's static part.
    var server: String
}

enum TunnelIntentAction: Sendable {
    case connect, disconnect
}

/// Live Activity intents run in the app's process; the app installs the handler at launch.
@MainActor
enum TunnelIntentBridge {
    static var handler: (@MainActor (TunnelIntentAction) -> Void)?
}

/// "Disconnect" on the lock screen and in the expanded island.
struct DisconnectTunnelIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Disconnect VPN"

    func perform() async throws -> some IntentResult {
        await MainActor.run { TunnelIntentBridge.handler?(.disconnect) }
        return .result()
    }
}

/// "Connect", shown while the tunnel is down.
struct ConnectTunnelIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Connect VPN"

    func perform() async throws -> some IntentResult {
        await MainActor.run { TunnelIntentBridge.handler?(.connect) }
        return .result()
    }
}
