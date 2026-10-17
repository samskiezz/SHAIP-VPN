import Foundation

/// The server this device tunnels to: where it is and the public keys it must
/// prove it holds. It is the `[server]` table of the same client config the
/// `shaip` CLI reads (examples/client.toml), so an operator hands out one file
/// for every platform; an optional `[enroll]` table carries what device
/// enrollment needs for servers that admit enrolled devices only.
public struct ServerConfig: Codable, Hashable, Sendable {
    /// Shown to the user (defaults to the address's host).
    public var label: String
    /// `host:port` of the shaipd UDP listener.
    public var address: String
    /// Pinned ML-DSA-65 public key, hex (`shaipd --print-public`).
    public var mlDsaPub: String
    /// Pinned Ed25519 public key, hex.
    public var edPub: String
    /// Control-plane base URL, for enrollment.
    public var controlPlane: String?
    /// Pinned enrollment-authority key, hex.
    public var enrollAuthorityPub: String?
    /// Pinned device-CA key, hex.
    public var deviceCAPub: String?

    public static let mlDsaPubBytes = 1952
    public static let edPubBytes = 32

    public init(label: String? = nil, address: String, mlDsaPub: String, edPub: String,
                controlPlane: String? = nil, enrollAuthorityPub: String? = nil, deviceCAPub: String? = nil) {
        self.address = address.trimmingCharacters(in: .whitespacesAndNewlines)
        self.label = label ?? ServerConfig.host(of: self.address) ?? self.address
        self.mlDsaPub = mlDsaPub.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        self.edPub = edPub.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        self.controlPlane = controlPlane
        self.enrollAuthorityPub = enrollAuthorityPub
        self.deviceCAPub = deviceCAPub
    }

    public enum ConfigError: Error, Equatable, CustomStringConvertible {
        case missing(String)
        case badAddress(String)
        case badKey(String, expectedBytes: Int)

        public var description: String {
            switch self {
            case .missing(let k): "The config has no \(k)."
            case .badAddress(let a): "“\(a)” is not a host:port address."
            case .badKey(let k, let n): "\(k) must be \(n) bytes of hex (\(n * 2) characters)."
            }
        }
    }

    /// Parse a shaip client config. Only the keys this app needs are read;
    /// everything else (the CLI's `[client]` table, comments) is ignored.
    public static func parse(_ text: String) throws -> ServerConfig {
        let t = tables(text)
        let server = t["server"] ?? [:]
        guard let address = server["address"] else { throw ConfigError.missing("[server] address") }
        guard let pq = server["server_ml_dsa_pub"] else { throw ConfigError.missing("[server] server_ml_dsa_pub") }
        guard let ed = server["server_ed_pub"] else { throw ConfigError.missing("[server] server_ed_pub") }
        let enroll = t["enroll"] ?? [:]
        let c = ServerConfig(label: server["label"], address: address, mlDsaPub: pq, edPub: ed,
                             controlPlane: enroll["control_plane"], enrollAuthorityPub: enroll["authority_key"],
                             deviceCAPub: enroll["ca_key"])
        try c.validate()
        return c
    }

    /// Reject a config the tunnel could not use.
    public func validate() throws {
        guard ServerConfig.host(of: address) != nil, let port = address.split(separator: ":").last.flatMap({ Int($0) }),
              (1...65535).contains(port) else { throw ConfigError.badAddress(address) }
        guard ServerConfig.isHex(mlDsaPub, bytes: ServerConfig.mlDsaPubBytes) else {
            throw ConfigError.badKey("server_ml_dsa_pub", expectedBytes: ServerConfig.mlDsaPubBytes)
        }
        guard ServerConfig.isHex(edPub, bytes: ServerConfig.edPubBytes) else {
            throw ConfigError.badKey("server_ed_pub", expectedBytes: ServerConfig.edPubBytes)
        }
    }

    /// Enrollment is possible (all three enrollment values are present).
    public var canEnroll: Bool {
        controlPlane != nil && enrollAuthorityPub != nil && deviceCAPub != nil
    }

    // MARK: NETunnelProviderProtocol.providerConfiguration

    public var providerConfiguration: [String: Any] {
        var d: [String: Any] = ["label": label, "address": address, "mlDsaPub": mlDsaPub, "edPub": edPub]
        if let controlPlane { d["controlPlane"] = controlPlane }
        if let enrollAuthorityPub { d["enrollAuthorityPub"] = enrollAuthorityPub }
        if let deviceCAPub { d["deviceCAPub"] = deviceCAPub }
        return d
    }

    public init?(providerConfiguration d: [String: Any]?) {
        guard let d, let address = d["address"] as? String, let pq = d["mlDsaPub"] as? String,
              let ed = d["edPub"] as? String else { return nil }
        self.init(label: d["label"] as? String, address: address, mlDsaPub: pq, edPub: ed,
                  controlPlane: d["controlPlane"] as? String, enrollAuthorityPub: d["enrollAuthorityPub"] as? String,
                  deviceCAPub: d["deviceCAPub"] as? String)
    }

    // MARK: Helpers

    /// The host part of `host:port` (IPv6 hosts in brackets).
    public static func host(of address: String) -> String? {
        if address.hasPrefix("["), let end = address.firstIndex(of: "]") {
            let h = String(address[address.index(after: address.startIndex)..<end])
            return h.isEmpty ? nil : h
        }
        let parts = address.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty else { return nil }
        return String(parts[0])
    }

    static func isHex(_ s: String, bytes: Int) -> Bool {
        s.count == bytes * 2 && s.allSatisfy(\.isHexDigit)
    }

    /// `[table] key = "value"` pairs. Strings may use double or single quotes.
    static func tables(_ text: String) -> [String: [String: String]] {
        var out: [String: [String: String]] = [:]
        var table = ""
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                table = line.dropFirst().dropLast().trimmingCharacters(in: .whitespaces)
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            var value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if let q = value.first, q == "\"" || q == "'", let close = value.dropFirst().firstIndex(of: q) {
                value = String(value[value.index(after: value.startIndex)..<close])
            } else if let hash = value.firstIndex(of: "#") {
                value = value[..<hash].trimmingCharacters(in: .whitespaces)
            }
            out[table, default: [:]][key] = value
        }
        return out
    }
}
