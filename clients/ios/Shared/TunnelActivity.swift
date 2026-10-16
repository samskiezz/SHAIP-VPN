import ActivityKit
import AppIntents
import Foundation

/// The lock-screen Live Activity and Dynamic Island for a tunnel session (design screen 10).
/// The app updates it at most every 15 s; the session clock ticks on its own via
/// `Text(timerInterval:)`, so it never needs per-second updates.
struct TunnelActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        var connected: Bool
        var city: String
        var node: String
        /// Protocol name, uppercased as the design shows it ("SHAIP MESH").
        var proto: String
        var sessionStart: Date?
        var downMbps: Int?
        var rttMs: Int?
    }

    var workspace: String
}

enum TunnelIntentAction: Sendable {
    case connect, disconnect
}

/// Live Activity intents run in the app's process; the app installs the handler at launch.
@MainActor
enum TunnelIntentBridge {
    static var handler: (@MainActor (TunnelIntentAction) -> Void)?
}

/// "Tap to disconnect" on the lock screen and in the expanded island.
struct DisconnectTunnelIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Disconnect VPN"

    func perform() async throws -> some IntentResult {
        await MainActor.run { TunnelIntentBridge.handler?(.disconnect) }
        return .result()
    }
}

/// "Tap to connect", shown while the tunnel is down.
struct ConnectTunnelIntent: LiveActivityIntent {
    static let title: LocalizedStringResource = "Connect VPN"

    func perform() async throws -> some IntentResult {
        await MainActor.run { TunnelIntentBridge.handler?(.connect) }
        return .result()
    }
}
