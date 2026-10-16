import Foundation

/// One line of the Protection screen, derived only from real state.
public struct ProtectionItem: Identifiable, Hashable, Sendable {
    public enum Status: String, Sendable {
        case on, off, unknown
    }

    public let id: String
    public let title: String
    public let detail: String
    public let status: Status

    public init(id: String, title: String, detail: String, status: Status) {
        self.id = id
        self.title = title
        self.detail = detail
        self.status = status
    }
}

/// What protects the user right now, and — always shown next to it — what
/// this VPN does not do. No line claims more than the code does.
public enum Protection {
    public static let rekeyMinutes = 20

    public static func items(connected: Bool, snapshot: TunnelSnapshot?, killSwitch: Bool, onDemand: Bool) -> [ProtectionItem] {
        let live = connected && snapshot?.state == .connected
        var out: [ProtectionItem] = []
        out.append(live
            ? ProtectionItem(id: "tunnel", title: "Encrypted tunnel",
                             detail: "Traffic between this iPhone and the server is encrypted with ChaCha20-Poly1305, under keys from a hybrid post-quantum handshake (ML-KEM-768 + X25519).",
                             status: .on)
            : ProtectionItem(id: "tunnel", title: "Encrypted tunnel",
                             detail: "Not connected. Your traffic is not going through the VPN.", status: .off))
        if live {
            out.append(ProtectionItem(id: "identity", title: "Server verified",
                                      detail: "The server proved it holds the keys this app was given (ML-DSA-65 + Ed25519)\(snapshot?.serverIdentity.map { ", identity \(Format.fingerprint($0))" } ?? "").",
                                      status: .on))
            if let dns = snapshot?.dns {
                out.append(ProtectionItem(id: "dns", title: "DNS through the tunnel",
                                          detail: "Lookups go to \(dns) inside the tunnel, not to your network's resolver.", status: .on))
            } else {
                out.append(ProtectionItem(id: "dns", title: "DNS through the tunnel",
                                          detail: "The server provided no resolver, so lookups use your network's resolver.", status: .off))
            }
            out.append(ProtectionItem(id: "ipv6", title: "IPv6 blocked",
                                      detail: "This tunnel carries IPv4 only, so IPv6 traffic is stopped while connected instead of going around it.",
                                      status: .on))
            out.append(ProtectionItem(id: "rekey", title: "Fresh keys",
                                      detail: "A new handshake replaces the session keys every \(rekeyMinutes) minutes\(snapshot.map { $0.rekeys > 0 ? " (\($0.rekeys) so far)" : "" } ?? "").",
                                      status: .on))
        }
        out.append(killSwitch
            ? ProtectionItem(id: "killswitch", title: "Kill switch",
                             detail: "iOS blocks traffic outside the tunnel while the VPN is on, including while it reconnects. Local network devices are blocked too.",
                             status: .on)
            : ProtectionItem(id: "killswitch", title: "Kill switch",
                             detail: "Off. If the tunnel drops, apps may reach the internet directly until it reconnects.",
                             status: .off))
        out.append(ProtectionItem(id: "ondemand", title: "Connect automatically",
                                  detail: onDemand ? "iOS reconnects the VPN on any network." : "Off. The VPN connects only when you turn it on.",
                                  status: onDemand ? .on : .off))
        return out
    }

    /// The limits, stated plainly. These do not change with settings.
    public static let limits: [ProtectionItem] = [
        ProtectionItem(id: "operator", title: "The VPN server sees your destinations",
                       detail: "This hides your traffic from your local network and internet provider, not from whoever runs the server.",
                       status: .off),
        ProtectionItem(id: "single-hop", title: "One hop, no mixnet",
                       detail: "Traffic goes straight to one server. Someone who can watch both sides of it could match traffic by timing.",
                       status: .off),
        ProtectionItem(id: "dpi", title: "It can still look like a VPN",
                       detail: "To your network every packet is random bytes, but their sizes and timing can still suggest an encrypted tunnel, and anyone with this server's config can recognize its handshakes.",
                       status: .off),
        ProtectionItem(id: "identity", title: "Websites can still recognize you",
                       detail: "Logins, cookies and browser fingerprinting work the same with or without a VPN.",
                       status: .off),
        ProtectionItem(id: "filtering", title: "No content filtering",
                       detail: "There is no ad, tracker or malware blocking.",
                       status: .off),
        ProtectionItem(id: "audit", title: "Not independently audited yet",
                       detail: "Don't rely on it where your safety depends on it.",
                       status: .off),
    ]
}
