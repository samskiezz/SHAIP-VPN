import Foundation
import ShaipFFI
import SHAIPCore

// The tunnel extension's calls, in its order, against a live echo-mode shaipd:
// start → status → server address → send (Data.withUnsafeBytes, as readPackets) →
// recv (into [UInt8], as the receive thread) → snapshot → JSON round trip →
// reconnect (as on a network change) → stop → recv returns -1 → free.
//
// usage: FFIInterop <server host:port> <server_ml_dsa_pub hex> <server_ed_pub hex> <identity file> <identity_id hex>

func fail(_ why: String) -> Never {
    print("SWIFT FFI FAIL: \(why)")
    exit(1)
}

let args = CommandLine.arguments
guard args.count == 6 else { fail("usage: FFIInterop <server> <pq> <ed> <identity> <identity_id>") }
let config = ServerConfig(address: args[1], mlDsaPub: args[2], edPub: args[3])
do { try config.validate() } catch { fail("config: \(error)") }

var err: UnsafeMutablePointer<CChar>?
guard let s = shaip_session_start(config.address, config.mlDsaPub, config.edPub, args[4], nil, 5000, &err) else {
    fail("start: \(takeString(err) ?? "no message")")
}
var st = ShaipStatus()
shaip_session_status(s, &st)
guard st.state == SHAIP_STATE_CONNECTED else { fail("not connected (state \(st.state))") }
let remote = takeString(shaip_session_server_addr(s)).flatMap(IPv4.host(ofEndpoint:))
guard remote == ServerConfig.host(of: config.address) else { fail("remote \(remote ?? "nil")") }

var buf = [UInt8](repeating: 0, count: Int(SHAIP_MAX_PACKET))
func echo(_ tag: UInt8) -> Bool {
    let packet = Data((0..<300).map { UInt8(truncatingIfNeeded: $0) ^ tag })
    for _ in 0..<20 {
        packet.withUnsafeBytes { raw in
            _ = shaip_session_send(s, raw.bindMemory(to: UInt8.self).baseAddress, raw.count)
        }
        let n = buf.withUnsafeMutableBufferPointer { b in shaip_session_recv(s, b.baseAddress, b.count, 300, nil) }
        if n > 0, Data(buf[0..<n]) == packet { return true }
    }
    return false
}
guard echo(1) else { fail("echo") }

for _ in 0..<40 {
    shaip_session_status(s, &st)
    if st.rtt_us > 0 { break }
    usleep(100_000)
}
let snap = TunnelSnapshot(status: st, lastError: takeString(shaip_session_last_error(s)),
                          serverAddress: takeString(shaip_session_server_addr(s)), ipv6Dropped: 7)
guard snap.state == .connected, snap.rttMs != nil, snap.mtu == 1370, snap.ipv6Dropped == 7 else { fail("snapshot \(snap)") }
guard snap.serverIdentity == args[5].lowercased() else {
    fail("server identity \(snap.serverIdentity ?? "nil") ≠ shaipd's identity_id \(args[5])")
}
guard snap.bytesSent >= 300, snap.bytesReceived >= 300 else { fail("counters \(snap)") }
do {
    let json = try snap.encoded()
    guard try TunnelSnapshot.decode(json) == snap else { fail("JSON round trip") }
    print("snapshot: \(String(decoding: json, as: UTF8.self))")
} catch { fail("JSON: \(error)") }

let report = Protection.items(connected: true, snapshot: snap, killSwitch: true, onDemand: false)
guard report.first(where: { $0.id == "identity" })?.detail.contains(Format.fingerprint(snap.serverIdentity)) == true else {
    fail("protection report")
}

// A network change: renegotiate; packets flow on the new session.
guard shaip_session_reconnect(s) == 0 else { fail("reconnect call") }
for _ in 0..<100 {
    shaip_session_status(s, &st)
    if st.reconnects == 1 && st.state == SHAIP_STATE_CONNECTED { break }
    usleep(100_000)
}
guard st.reconnects == 1, st.state == SHAIP_STATE_CONNECTED else { fail("no reconnect") }
guard echo(2) else { fail("echo after reconnect") }

shaip_session_stop(s)
let after = buf.withUnsafeMutableBufferPointer { b in shaip_session_recv(s, b.baseAddress, b.count, 500, nil) }
guard after == -1 else { fail("recv after stop returned \(after)") }
shaip_session_status(s, &st)
guard TunnelSnapshot(status: st, lastError: nil, serverAddress: nil, ipv6Dropped: 0).state == .stopped else { fail("stopped state") }
shaip_session_free(s)
print("core \(shaipVersion): connected, echoed, measured RTT \(Format.fixed(snap.rttMs ?? 0, 2)) ms, identity \(Format.fingerprint(snap.serverIdentity)), reconnected, stopped")
print("SWIFT FFI OK")
