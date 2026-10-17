import Foundation
import NetworkExtension
import os
import ShaipFFI
import SHAIPCore

/// The VPN itself. The Rust core (`shaip_session_*`, the same code `shaip
/// run` uses on Linux) keeps a SHAIP session to the server up — keepalive,
/// reconnection, rekeying — and this provider moves IP packets between iOS and
/// it:
///
/// - All IPv4 is routed into the tunnel; DNS goes to the resolver the server
///   pushed (reached through the tunnel), for every domain.
/// - The tunnel carries IPv4 only, so IPv6 is routed into it as well and
///   dropped here: it never leaves outside the tunnel.
/// - When the device changes networks the session is renegotiated at once
///   instead of waiting for the dead-peer timer.
/// - The app asks for a `TunnelSnapshot` once a second (`handleAppMessage`).
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "com.shaip.vpn.tunnel", category: "tunnel")
    /// Guards `session` and the fields below: no call may use the session
    /// once `stopTunnel` has taken it to free it.
    private let lock = NSLock()
    private var session: OpaquePointer?
    private var running = false
    /// iOS stopped the tunnel before the first handshake finished.
    private var stopRequested = false
    private var appliedAddress: UInt32 = 0
    private var remoteAddress = ""
    private var ipv6Dropped: UInt64 = 0
    private var lastSatisfiedPath: NWPath?

    private var monitor: DispatchSourceTimer?
    private var pathObservation: NSKeyValueObservation?
    private let receiverDone = DispatchSemaphore(value: 0)
    private let work = DispatchQueue(label: "com.shaip.vpn.tunnel.work")

    // MARK: Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let config = ServerConfig(providerConfiguration: proto.providerConfiguration) else {
            completionHandler(CoreError(message: "No server is configured. Open SHAIP to set one up."))
            return
        }
        guard let identity = AppGroup.identityPath else {
            completionHandler(CoreError(message: "The shared app container is unavailable (App Group entitlement)."))
            return
        }
        let certificate = AppGroup.enrolledCertificatePath
        work.async { [self] in
            var err: UnsafeMutablePointer<CChar>?
            let started: OpaquePointer?
            if let certificate {
                started = shaip_session_start(config.address, config.mlDsaPub, config.edPub, identity, certificate, 15_000, &err)
            } else {
                started = shaip_session_start(config.address, config.mlDsaPub, config.edPub, identity, nil, 15_000, &err)
            }
            guard let s = started else {
                let message = takeString(err) ?? "Could not connect to \(config.address)."
                // Private: the message can name the server, and iOS logs end up
                // in diagnostics reports.
                log.error("connect failed: \(message, privacy: .private)")
                completionHandler(CoreError(message: message))
                return
            }
            var st = ShaipStatus()
            shaip_session_status(s, &st)
            guard st.assigned_ipv4 != 0 else {
                // An echo-mode (test) server: nothing could be routed.
                shaip_session_free(s)
                completionHandler(CoreError(message: "The server did not assign a tunnel address, so it cannot carry traffic (it is not running with --tun)."))
                return
            }
            let remote = takeString(shaip_session_server_addr(s)).flatMap(IPv4.host(ofEndpoint:))
                ?? ServerConfig.host(of: config.address) ?? config.address
            setTunnelNetworkSettings(Self.settings(for: st, remote: remote)) { [self] error in
                if let error {
                    log.error("applying network settings failed: \(error.localizedDescription, privacy: .private)")
                    shaip_session_free(s)
                    completionHandler(error)
                    return
                }
                lock.lock()
                if stopRequested {
                    lock.unlock()
                    shaip_session_free(s) // stopped while connecting
                    completionHandler(CoreError(message: "Stopped while connecting."))
                    return
                }
                session = s
                running = true
                appliedAddress = st.assigned_ipv4
                remoteAddress = remote
                lock.unlock()
                startReceiving(s)
                readPackets()
                startMonitor()
                observePath()
                AppGroup.protectKeyFiles() // the core creates the identity on first use
                log.info("tunnel up")
                completionHandler(nil)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        monitor?.cancel()
        monitor = nil
        pathObservation = nil
        lock.lock()
        let s = session
        let wasRunning = running
        session = nil
        running = false
        stopRequested = true
        lock.unlock()
        guard let s else {
            completionHandler()
            return
        }
        work.async { [receiverDone] in
            shaip_session_stop(s) // tells the server Close; the receiver's next call returns -1
            if wasRunning {
                receiverDone.wait() // it has let go of `s`
            }
            shaip_session_free(s)
            completionHandler()
        }
    }

    /// After sleep the NAT binding is likely gone: renegotiate straight away.
    override func wake() {
        withSession { _ = shaip_session_reconnect($0) }
    }

    // MARK: Settings

    private static func settings(for st: ShaipStatus, remote: String) -> NEPacketTunnelNetworkSettings {
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)
        let prefix = st.prefix_len == 0 ? 24 : Int(st.prefix_len)
        let v4 = NEIPv4Settings(addresses: [IPv4.string(st.assigned_ipv4) ?? "0.0.0.0"],
                                subnetMasks: [IPv4.mask(prefix: prefix)])
        v4.includedRoutes = [NEIPv4Route.default()]
        s.ipv4Settings = v4
        // IPv4-only tunnel: claim IPv6 too and drop it in readPackets, so it
        // cannot go around the tunnel. (A unique-local address the tunnel
        // never uses.)
        let v6 = NEIPv6Settings(addresses: ["fd70:716e:6f6e::2"], networkPrefixLengths: [64])
        v6.includedRoutes = [NEIPv6Route.default()]
        s.ipv6Settings = v6
        if let dns = IPv4.string(st.dns_ipv4) {
            let d = NEDNSSettings(servers: [dns])
            d.matchDomains = [""] // every lookup, not just some domains
            s.dnsSettings = d
        }
        s.mtu = NSNumber(value: st.mtu == 0 ? 1370 : Int(st.mtu))
        return s
    }

    // MARK: Packets

    /// iOS → tunnel. IPv4 goes to the core; IPv6 is dropped (see above).
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            self.lock.lock()
            guard self.running, let s = self.session else {
                self.lock.unlock()
                return
            }
            for (i, packet) in packets.enumerated() {
                if protocols[i].int32Value == AF_INET {
                    packet.withUnsafeBytes { raw in
                        _ = shaip_session_send(s, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
                    }
                } else {
                    self.ipv6Dropped += 1
                }
            }
            self.lock.unlock()
            self.readPackets()
        }
    }

    /// Tunnel → iOS, on a dedicated thread (the core's receive blocks). It
    /// ends when the session is stopped, then signals `receiverDone`.
    private func startReceiving(_ s: OpaquePointer) {
        let flow = packetFlow
        let done = receiverDone
        let inet = NSNumber(value: AF_INET)
        let thread = Thread {
            var buf = [UInt8](repeating: 0, count: Int(SHAIP_MAX_PACKET))
            receive: while true {
                var batch: [Data] = []
                // Wait for one packet, then take whatever else is ready (up
                // to 64) and hand them to iOS together.
                var timeout: UInt32 = 250
                while batch.count < 64 {
                    let n = buf.withUnsafeMutableBufferPointer { b in
                        shaip_session_recv(s, b.baseAddress, b.count, timeout, nil)
                    }
                    if n > 0 {
                        batch.append(Data(buf[0..<n]))
                        timeout = 0
                    } else if n == 0 {
                        break
                    } else {
                        if !batch.isEmpty {
                            flow.writePackets(batch, withProtocols: Array(repeating: inet, count: batch.count))
                        }
                        break receive // stopped
                    }
                }
                if !batch.isEmpty {
                    flow.writePackets(batch, withProtocols: Array(repeating: inet, count: batch.count))
                }
            }
            done.signal()
        }
        thread.name = "shaip-receive"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    // MARK: Status

    private func withSession(_ body: (OpaquePointer) -> Void) {
        lock.lock()
        defer { lock.unlock() }
        if running, let s = session {
            body(s)
        }
    }

    /// Once a second: mirror reconnects into iOS's "reasserting" state, and
    /// re-apply settings if the server ever assigns another address.
    private func startMonitor() {
        let t = DispatchSource.makeTimerSource(queue: work)
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.checkStatus() }
        t.resume()
        monitor = t
    }

    private func checkStatus() {
        var st = ShaipStatus()
        var applied: UInt32 = 0
        var remote = ""
        var live = false
        withSession { s in
            shaip_session_status(s, &st)
            applied = appliedAddress
            remote = remoteAddress
            live = true
        }
        guard live else { return }
        let reconnecting = st.state == SHAIP_STATE_RECONNECTING
        if reasserting != reconnecting {
            reasserting = reconnecting
        }
        if st.state == SHAIP_STATE_CONNECTED, st.assigned_ipv4 != 0, st.assigned_ipv4 != applied {
            log.info("the server assigned a new tunnel address; re-applying settings")
            let assigned = st.assigned_ipv4
            setTunnelNetworkSettings(Self.settings(for: st, remote: remote)) { [weak self] error in
                guard let self, error == nil else { return }
                self.lock.lock()
                self.appliedAddress = assigned
                self.lock.unlock()
            }
        }
    }

    /// A different usable network (Wi-Fi ↔ cellular, a new Wi-Fi): the old
    /// session's UDP flow cannot follow, so renegotiate now.
    private func observePath() {
        pathObservation = observe(\.defaultPath, options: [.new]) { [weak self] provider, _ in
            self?.pathChanged(provider.defaultPath)
        }
    }

    private func pathChanged(_ path: NWPath?) {
        guard let path, path.status == .satisfied else { return }
        lock.lock()
        let previous = lastSatisfiedPath
        lastSatisfiedPath = path
        lock.unlock()
        if let previous, !path.isEqual(to: previous) {
            log.info("network changed; renegotiating the session")
            withSession { _ = shaip_session_reconnect($0) }
        }
    }

    // MARK: App messages

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        var st = ShaipStatus()
        var lastError: String?
        var server: String?
        var v6: UInt64 = 0
        var live = false
        withSession { s in
            shaip_session_status(s, &st)
            lastError = takeString(shaip_session_last_error(s))
            server = takeString(shaip_session_server_addr(s))
            v6 = ipv6Dropped
            live = true
        }
        guard live else {
            completionHandler?(nil)
            return
        }
        completionHandler?(try? TunnelSnapshot(status: st, lastError: lastError, serverAddress: server, ipv6Dropped: v6).encoded())
    }
}
