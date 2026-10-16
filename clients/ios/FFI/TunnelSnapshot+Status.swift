import Foundation
import PQAnonFFI
import SHAIPCore

extension TunnelSnapshot {
    /// A snapshot of the Rust core's status (`pqanon_session_status`), plus
    /// what the extension itself counts.
    init(status st: PqanonStatus, lastError: String?, serverAddress: String?, ipv6Dropped: UInt64, at now: Date = Date()) {
        let state: State = st.state == PQANON_STATE_CONNECTED ? .connected
            : st.state == PQANON_STATE_RECONNECTING ? .reconnecting : .stopped
        let identity = withUnsafeBytes(of: st.server_identity) { raw in raw.map { String(format: "%02x", $0) }.joined() }
        self.init(
            state: state,
            tunnelAddress: IPv4.string(st.assigned_ipv4).map { "\($0)/\(st.prefix_len)" },
            dns: IPv4.string(st.dns_ipv4),
            mtu: Int(st.mtu),
            rttMs: st.rtt_us == 0 ? nil : Double(st.rtt_us) / 1000,
            upSince: st.up_since_unix_ms == 0 ? nil : Date(timeIntervalSince1970: Double(st.up_since_unix_ms) / 1000),
            reconnects: Int(st.reconnects),
            rekeys: Int(st.rekeys),
            bytesSent: st.stats.bytes_sent,
            bytesReceived: st.stats.bytes_received,
            packetsSent: st.stats.packets_sent,
            packetsReceived: st.stats.packets_received,
            packetsRejected: st.stats.packets_dropped,
            droppedOffline: st.dropped_offline,
            ipv6Dropped: ipv6Dropped,
            serverAddress: serverAddress,
            serverIdentity: identity.allSatisfy { $0 == "0" } ? nil : identity,
            lastError: lastError,
            sampledAt: now)
    }
}
