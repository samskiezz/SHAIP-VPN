import SwiftUI
import Observation
import SHAIPCore

/// The app's single source of truth (the handoff's `TunnelStore`). Every screen reads it, so
/// connecting from any surface — the orb, a node row, a lock-screen intent — updates every screen.
///
/// The tunnel itself is mocked with the design's telemetry curves. In production `connected`
/// drives a `NETunnelProviderManager` (SHAIP Mesh/WireGuard via the packet-tunnel extension,
/// IKEv2 via `NEVPNProtocolIKEv2`), the kill switch maps to `includeAllNetworks` +
/// `enforceRoutes`, and telemetry comes from `sendProviderMessage` once a second.
@MainActor
@Observable
final class TunnelStore {
    static let shared = TunnelStore()

    var connected = true {
        didSet { if connected != oldValue { connectionChanged() } }
    }
    var selectedNode = 0 {
        didSet { if selectedNode != oldValue { refreshTelemetry(); syncActivity(force: true) } }
    }
    var proto: TunnelProtocol = .mesh {
        didSet { if proto != oldValue { syncActivity(force: true) } }
    }
    var killSwitch = true
    var multiHop = true
    var privateDNS = true
    var splitTunnel = false
    var postureEnforced = true
    var onDemand = true
    var pqHandshake = true
    var nodeFilter: NodeFilter = .all
    var accessFilter: AccessFilter = .all
    var resources = Catalog.resources
    /// Unread alerts badge on the Connect bell.
    var unreadAlerts = true
    /// Globe HUD layer (the Network screen's layers button).
    var globeHUD = true

    /// 1 Hz clock (the design's `t`).
    private(set) var tick = 0
    private(set) var now = Date()
    private(set) var telemetry: TelemetrySample
    private(set) var history: ThroughputHistory
    private(set) var sessionStart: Date?

    @ObservationIgnored private var clock: Task<Void, Never>?
    @ObservationIgnored private let activity = LiveActivityController()

    init() {
        history = ThroughputHistory(endingAt: 0)
        telemetry = MockTelemetry.sample(tick: 0, node: Catalog.nodes[0])
        // The design opens mid-session, at 01:23:45.
        sessionStart = Date().addingTimeInterval(-5025)
    }

    var node: Node { Catalog.nodes[selectedNode] }
    var rtt: Int { telemetry.rttMs }
    var sessionSeconds: Int? {
        guard connected, let start = sessionStart else { return nil }
        return max(0, Int(now.timeIntervalSince(start)))
    }

    func start() {
        guard clock == nil else { return }
        syncActivity(force: true)
        clock = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                self?.advance()
            }
        }
    }

    func toggleConnection() { connected.toggle() }

    /// Tapping a node row selects it and connects.
    func connect(to index: Int) {
        selectedNode = index
        if !connected { connected = true }
    }

    private func advance() {
        tick += 1
        now = Date()
        refreshTelemetry()
        history.push(down: connected ? telemetry.downMbps : 0, up: connected ? telemetry.upMbps : 0)
        syncActivity(force: false)
    }

    private func refreshTelemetry() {
        telemetry = MockTelemetry.sample(tick: tick, node: node)
    }

    private func connectionChanged() {
        // A reconnect is a new session; the handoff's mock resumed the old clock.
        sessionStart = connected ? Date() : nil
        now = Date()
        syncActivity(force: true)
    }

    private func syncActivity(force: Bool) {
        activity.sync(.init(connected: connected, city: node.city, node: node.id, proto: proto.name.uppercased(),
                            sessionStart: connected ? sessionStart : nil,
                            downMbps: connected ? Int(telemetry.downMbps.rounded()) : nil,
                            rttMs: connected ? rtt : nil), force: force)
    }

    // MARK: Scene options

    var meshOptions: SceneOptions {
        var o = SceneOptions()
        o.connected = connected
        o.labels = Catalog.meshLabels(node: node, rtt: rtt)
        return o
    }

    var globeOptions: SceneOptions {
        var o = SceneOptions()
        o.connected = connected
        o.hud = globeHUD
        o.activeHub = node.hub
        o.hubLabels = Catalog.globeLabels(node: node, rtt: rtt, connected: connected)
        return o
    }

    var radarOptions: SceneOptions {
        var o = SceneOptions()
        o.radarLabels = Catalog.radarLabels
        return o
    }
}
