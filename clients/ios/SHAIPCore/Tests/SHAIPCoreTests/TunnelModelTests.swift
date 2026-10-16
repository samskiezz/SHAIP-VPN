import Foundation
import Testing
@testable import SHAIPCore

@Suite("Server config, tunnel snapshot, rates and the Protection report")
struct TunnelModelTests {
    static let pq = String(repeating: "ab", count: ServerConfig.mlDsaPubBytes)
    static let ed = String(repeating: "cd", count: ServerConfig.edPubBytes)

    /// The CLI's own client config (examples/client.toml) imports as is.
    static let cliConfig = """
    # PQ-ANON client config
    [client]
    identity    = "/home/user/.pqanon/client.id"
    tun_device  = "pqanon-c0"

    [server]
    address           = "vpn.example.com:443"
    # Pins: paste the output of `pqanond --identity <file> --print-public`.
    server_ml_dsa_pub = "\(pq)"
    server_ed_pub     = '\(ed)'

    [enroll]
    control_plane = "https://cp.example.com"
    authority_key = "\(String(repeating: "11", count: 32))"
    ca_key        = "\(String(repeating: "22", count: 32))"
    """

    @Test("a CLI client config imports, including the enrollment table")
    func parsesCLIConfig() throws {
        let c = try ServerConfig.parse(Self.cliConfig)
        #expect(c.address == "vpn.example.com:443")
        #expect(c.label == "vpn.example.com")
        #expect(c.mlDsaPub == Self.pq && c.edPub == Self.ed)
        #expect(c.controlPlane == "https://cp.example.com" && c.canEnroll)
        // Round trip through the provider configuration the extension reads.
        #expect(ServerConfig(providerConfiguration: c.providerConfiguration) == c)
    }

    @Test("configs the tunnel could not use are refused with a reason")
    func rejectsBadConfigs() {
        #expect(throws: ServerConfig.ConfigError.missing("[server] address")) {
            try ServerConfig.parse("[server]\nserver_ml_dsa_pub = \"\(Self.pq)\"\nserver_ed_pub = \"\(Self.ed)\"")
        }
        #expect(throws: ServerConfig.ConfigError.badAddress("vpn.example.com")) {
            try ServerConfig.parse("[server]\naddress = \"vpn.example.com\"\nserver_ml_dsa_pub = \"\(Self.pq)\"\nserver_ed_pub = \"\(Self.ed)\"")
        }
        #expect(throws: ServerConfig.ConfigError.badKey("server_ed_pub", expectedBytes: 32)) {
            try ServerConfig.parse("[server]\naddress = \"1.2.3.4:443\"\nserver_ml_dsa_pub = \"\(Self.pq)\"\nserver_ed_pub = \"hex...\"")
        }
        // The example file's placeholders are not keys.
        #expect(throws: ServerConfig.ConfigError.badKey("server_ml_dsa_pub", expectedBytes: 1952)) {
            try ServerConfig.parse("[server]\naddress = \"1.2.3.4:443\"\nserver_ml_dsa_pub = \"hex...\"\nserver_ed_pub = \"\(Self.ed)\"")
        }
        #expect(ServerConfig(providerConfiguration: ["address": "x:1"]) == nil)
    }

    @Test("host:port parsing, IPv6 included")
    func hosts() {
        #expect(ServerConfig.host(of: "203.0.113.7:443") == "203.0.113.7")
        #expect(ServerConfig.host(of: "[2001:db8::1]:443") == "2001:db8::1")
        #expect(ServerConfig.host(of: "noport") == nil)
        #expect(ServerConfig.host(of: ":443") == nil)
        #expect(IPv4.host(ofEndpoint: "203.0.113.7:443") == "203.0.113.7")
        #expect(IPv4.host(ofEndpoint: "[2001:db8::1]:443") == nil)
    }

    @Test("C ABI addresses and masks")
    func ipv4() {
        #expect(IPv4.string(0x0A4D_0017) == "10.77.0.23")
        #expect(IPv4.string(0) == nil)
        #expect(IPv4.mask(prefix: 24) == "255.255.255.0")
        #expect(IPv4.mask(prefix: 20) == "255.255.240.0")
        #expect(IPv4.mask(prefix: 0) == "0.0.0.0")
    }

    @Test("a snapshot survives the trip from the extension to the app")
    func snapshotJSON() throws {
        let up = Date(timeIntervalSince1970: 1_760_000_000.123)
        let s = TunnelSnapshot(state: .connected, tunnelAddress: "10.77.0.23/24", dns: "10.77.0.1", mtu: 1370, rttMs: 23.4,
                               upSince: up, reconnects: 2, rekeys: 1, bytesSent: 10, bytesReceived: 20,
                               serverAddress: "203.0.113.7:443", serverIdentity: "00112233445566778899aabbccddeeff",
                               sampledAt: up)
        let back = try TunnelSnapshot.decode(s.encoded())
        #expect(back == s)
        // Any date, even one with sub-millisecond precision, round-trips exactly.
        let now = TunnelSnapshot(state: .reconnecting, upSince: Date(), sampledAt: Date())
        #expect(try TunnelSnapshot.decode(now.encoded()) == now)
    }

    @Test("rates come from real byte deltas, and never from nothing")
    func rates() {
        var m = RateMeter()
        let t0 = Date(timeIntervalSince1970: 1000)
        let r0 = m.update(received: 5_000, sent: 1_000, at: t0)
        #expect(r0.down == 0 && r0.up == 0, "first sample: no rate yet")
        let r = m.update(received: 5_000 + 1_000_000, sent: 1_000 + 250_000, at: t0.addingTimeInterval(1))
        #expect(abs(r.down - 8) < 1e-9 && abs(r.up - 2) < 1e-9)
        // A new tunnel resets its counters: no negative or bogus rate.
        let r2 = m.update(received: 10, sent: 10, at: t0.addingTimeInterval(2))
        #expect(r2.down == 0 && r2.up == 0)
    }

    @Test("throughput history starts empty and scales to what it holds")
    func history() {
        var h = ThroughputHistory()
        #expect(h.down.count == 48 && h.peak == 0 && h.scale == 1)
        h.push(down: 141.2, up: 12)
        #expect(h.peak == 141.2 && h.scale == 200)
        h.push(down: 0.4, up: 0.1)
        #expect(h.down.last == 0.4)
    }

    @Test("formatting")
    func formatting() {
        #expect(Format.clock(5025) == "01:23:45" && Format.clock(nil) == "--:--:--")
        #expect(Format.mbps(0.423) == "0.42" && Format.mbps(8.61) == "8.6" && Format.mbps(141.4) == "141")
        let b1 = Format.bytes(812), b2 = Format.bytes(3 * 1024 + 400), b3 = Format.bytes(1_331_439_861)
        #expect(b1.value == "812" && b1.unit == "B")
        #expect(b2.value == "3.39" && b2.unit == "KB")
        #expect(b3.value == "1.24" && b3.unit == "GB")
        #expect(Format.count(950) == "950" && Format.count(12_400) == "12.4K" && Format.count(3_100_000) == "3.10M")
        #expect(Format.fingerprint("00112233445566778899aabbccddeeff") == "0011 2233 4455 6677")
        #expect(Format.fingerprint(nil) == "—")
    }

    @Test("the Protection report claims only what is true now")
    func protection() {
        let off = Protection.items(connected: false, snapshot: nil, killSwitch: false, onDemand: false)
        #expect(off.first?.id == "tunnel" && off.first?.status == .off)
        #expect(!off.contains { $0.id == "dns" || $0.id == "identity" }, "nothing about a tunnel that is not up")
        #expect(off.first { $0.id == "killswitch" }?.status == .off)

        var snap = TunnelSnapshot(state: .connected, dns: nil, rekeys: 3, serverIdentity: "00112233445566778899aabbccddeeff")
        var on = Protection.items(connected: true, snapshot: snap, killSwitch: true, onDemand: true)
        #expect(on.first { $0.id == "tunnel" }?.status == .on)
        #expect(on.first { $0.id == "dns" }?.status == .off, "no resolver pushed: say so")
        #expect(on.first { $0.id == "identity" }?.detail.contains("0011 2233 4455 6677") == true)
        #expect(on.first { $0.id == "rekey" }?.detail.contains("3 so far") == true)
        #expect(on.first { $0.id == "killswitch" }?.status == .on)

        snap.dns = "10.77.0.1"
        on = Protection.items(connected: true, snapshot: snap, killSwitch: false, onDemand: false)
        #expect(on.first { $0.id == "dns" }?.status == .on)
        // Reconnecting is not protected traffic.
        snap.state = .reconnecting
        #expect(Protection.items(connected: true, snapshot: snap, killSwitch: false, onDemand: false).first?.status == .off)

        // The limits never change and never read as a protection.
        #expect(Protection.limits.count == 6 && Protection.limits.allSatisfy { $0.status == .off })
        for banned in ["untraceable", "anonymous", "can't be", "cannot be", "unhackable", "military", "100%", "guarantee"] {
            for item in on + off + Protection.limits {
                #expect(!(item.title + item.detail).lowercased().contains(banned), "\(item.id) says \(banned)")
            }
        }
    }
}
