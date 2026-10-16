import Foundation
import NetworkExtension
import Observation
import PQAnonFFI
import SHAIPCore
import UIKit

/// The app's single source of truth. Every value it exposes is real: the
/// connection state is iOS's (`NEVPNStatus`), and everything about the session
/// — rates, RTT, addresses, counters — comes from the tunnel extension's
/// `TunnelSnapshot`, i.e. from the Rust core that carries the traffic. When
/// something is not known it is `nil` and the screens show a dash.
@MainActor
@Observable
final class TunnelStore {
    static let shared = TunnelStore()

    /// The configured server; nil until set up.
    private(set) var config: ServerConfig?
    private(set) var status: NEVPNStatus = .invalid
    /// The latest status from the extension (nil while the tunnel is off).
    private(set) var snapshot: TunnelSnapshot?
    /// When iOS reports the tunnel came up.
    private(set) var connectedSince: Date?
    /// Measured from the extension's byte counters, once a second.
    private(set) var downMbps: Double = 0
    private(set) var upMbps: Double = 0
    private(set) var history = ThroughputHistory()
    /// Why the last attempt or session failed, as the core or iOS reported it.
    private(set) var lastError: String?
    /// `NETunnelProviderProtocol.includeAllNetworks`: iOS blocks traffic
    /// outside the tunnel while the VPN is on.
    private(set) var killSwitch = false
    /// On-demand: iOS keeps the VPN connected on any network.
    private(set) var onDemand = false
    /// This device's id from enrollment, if it enrolled.
    private(set) var deviceID: String? = UserDefaults.standard.string(forKey: "shaip.deviceID")
    private(set) var loaded = false
    private(set) var now = Date()

    @ObservationIgnored private var manager: NETunnelProviderManager?
    @ObservationIgnored private var poll: Task<Void, Never>?
    @ObservationIgnored private var observer: NSObjectProtocol?
    @ObservationIgnored private var meter = RateMeter()
    @ObservationIgnored private let activity = LiveActivityController()

    // MARK: Derived state

    /// A server-confirmed session is carrying traffic right now.
    var connected: Bool { status == .connected && snapshot?.state != .reconnecting }
    /// The tunnel is renegotiating (iOS: reasserting); traffic is held, not leaked.
    var reconnecting: Bool { status == .reasserting || (status == .connected && snapshot?.state == .reconnecting) }
    var connecting: Bool { status == .connecting }
    /// The VPN is switched on (up, coming up, or reconnecting).
    var isOn: Bool { [.connected, .connecting, .reasserting].contains(status) }
    var sessionSeconds: Int? {
        guard isOn, let start = snapshot?.upSince ?? connectedSince else { return nil }
        return max(0, Int(now.timeIntervalSince(start)))
    }
    var rttMs: Int? { connected ? snapshot?.rttMs.map { Int($0.rounded()) } : nil }
    var enrolled: Bool { AppGroup.enrolledCertificatePath != nil }

    /// A one-line state for status pills: what is true, nothing more.
    var stateLabel: String {
        if reconnecting { return "RECONNECTING" }
        switch status {
        case .connected: return "CONNECTED"
        case .connecting: return "CONNECTING"
        case .disconnecting: return "DISCONNECTING"
        default: return "NOT CONNECTED"
        }
    }

    // MARK: Loading and configuration

    func load() async {
        do {
            manager = try await NETunnelProviderManager.loadAllFromPreferences().first
        } catch {
            lastError = "Could not read the VPN configuration: \(error.localizedDescription)"
        }
        if let manager { adopt(manager) }
        loaded = true
    }

    private func adopt(_ m: NETunnelProviderManager) {
        let proto = m.protocolConfiguration as? NETunnelProviderProtocol
        config = ServerConfig(providerConfiguration: proto?.providerConfiguration)
        killSwitch = proto?.includeAllNetworks ?? false
        onDemand = m.isOnDemandEnabled
        observeStatus(of: m.connection)
        statusChanged()
    }

    /// Save `config` as this iPhone's VPN (iOS asks the user to allow it the
    /// first time).
    func install(_ config: ServerConfig) async throws {
        try config.validate()
        let m = manager ?? NETunnelProviderManager()
        apply(config: config, killSwitch: killSwitch, onDemand: onDemand, to: m)
        try await m.saveToPreferences()
        try await m.loadFromPreferences() // required before the first start
        manager = m
        adopt(m)
    }

    /// Remove the VPN configuration from this iPhone.
    func removeConfiguration() async {
        disconnect()
        try? await manager?.removeFromPreferences()
        manager = nil
        config = nil
        snapshot = nil
        status = .invalid
        stopPolling()
    }

    private func apply(config: ServerConfig, killSwitch: Bool, onDemand: Bool, to m: NETunnelProviderManager) {
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppGroup.tunnelBundleID
        proto.serverAddress = config.address
        proto.providerConfiguration = config.providerConfiguration
        proto.includeAllNetworks = killSwitch
        proto.excludeLocalNetworks = false
        m.protocolConfiguration = proto
        m.localizedDescription = "SHAIP · \(config.label)"
        m.isEnabled = true
        let rule = NEOnDemandRuleConnect()
        rule.interfaceTypeMatch = .any
        m.onDemandRules = [rule]
        m.isOnDemandEnabled = onDemand
    }

    private func saveSettings() async {
        guard let m = manager, let config else { return }
        apply(config: config, killSwitch: killSwitch, onDemand: onDemand, to: m)
        do {
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
        } catch {
            lastError = "Could not save the setting: \(error.localizedDescription)"
            adopt(m) // show what is actually saved
        }
    }

    /// Takes effect the next time the tunnel connects.
    func setKillSwitch(_ on: Bool) async {
        killSwitch = on
        await saveSettings()
    }

    func setOnDemand(_ on: Bool) async {
        onDemand = on
        await saveSettings()
    }

    // MARK: Connect / disconnect

    func connect() {
        guard let m = manager else { return }
        do {
            lastError = nil
            try m.connection.startVPNTunnel()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func disconnect() {
        // With on-demand on, iOS would reconnect at once; turning the VPN off
        // here turns that off too, as the Settings app does.
        if onDemand {
            Task { await setOnDemand(false) }
        }
        manager?.connection.stopVPNTunnel()
    }

    func toggleConnection() {
        isOn ? disconnect() : connect()
    }

    // MARK: Enrollment

    /// Enroll this device with a `pqanon://enroll` link: the core proves
    /// possession of this device's identity key and stores the certificate
    /// the control plane issues next to it.
    func enroll(link: String) async throws {
        guard let config, let cp = config.controlPlane, let authority = config.enrollAuthorityPub,
              let ca = config.deviceCAPub else {
            throw CoreError(message: "This server's config has no [enroll] section, so this device cannot enroll with it.")
        }
        guard let identity = AppGroup.identityPath else {
            throw CoreError(message: "The shared app container is unavailable (App Group entitlement).")
        }
        let name = UIDevice.current.name
        let id: String = try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                var err: UnsafeMutablePointer<CChar>?
                if let id = takeString(pqanon_enroll(link, cp, authority, ca, identity, name, &err)) {
                    cont.resume(returning: id)
                } else {
                    cont.resume(throwing: CoreError(message: takeString(err) ?? "Enrollment failed."))
                }
            }
        }
        deviceID = id
        UserDefaults.standard.set(id, forKey: "shaip.deviceID")
    }

    // MARK: Status

    private func observeStatus(of connection: NEVPNConnection) {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: connection, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.statusChanged() }
        }
    }

    private func statusChanged() {
        guard let c = manager?.connection else { return }
        status = c.status
        connectedSince = c.connectedDate
        now = Date()
        if isOn {
            startPolling()
        } else {
            stopPolling()
            snapshot = nil
            meter.reset()
            downMbps = 0
            upMbps = 0
            if status == .disconnected {
                c.fetchLastDisconnectError { [weak self] error in
                    guard let error else { return }
                    Task { @MainActor in self?.lastError = error.localizedDescription }
                }
            }
        }
        syncActivity(force: true)
    }

    private func startPolling() {
        guard poll == nil else { return }
        poll = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func stopPolling() {
        poll?.cancel()
        poll = nil
    }

    /// Ask the extension for its status and derive the rates from it.
    private func refresh() async {
        now = Date()
        guard isOn, let session = manager?.connection as? NETunnelProviderSession else { return }
        let data: Data? = await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(AppGroup.statusMessage) { cont.resume(returning: $0) }
            } catch {
                cont.resume(returning: nil)
            }
        }
        guard let data, let snap = try? TunnelSnapshot.decode(data) else { return }
        let r = meter.update(received: snap.bytesReceived, sent: snap.bytesSent, at: snap.sampledAt)
        downMbps = r.down
        upMbps = r.up
        history.push(down: r.down, up: r.up)
        if let e = snap.lastError, snap.state == .reconnecting { lastError = e }
        if snap.state == .connected { lastError = nil }
        snapshot = snap
        syncActivity(force: false)
    }

    private func syncActivity(force: Bool) {
        guard let config else { return }
        activity.sync(.init(connected: connected, reconnecting: reconnecting, server: config.label,
                            tunnelAddress: snapshot?.tunnelAddress,
                            sessionStart: isOn ? (snapshot?.upSince ?? connectedSince) : nil,
                            downMbps: connected ? downMbps : nil, rttMs: rttMs),
                      server: config.label, force: force)
    }

    // MARK: Scene

    /// The ambient mesh: lit while connected. It carries no labels — every
    /// number the app shows is on the cards, from the tunnel itself.
    var meshOptions: SceneOptions {
        var o = SceneOptions()
        o.connected = connected
        o.hud = false
        return o
    }
}
