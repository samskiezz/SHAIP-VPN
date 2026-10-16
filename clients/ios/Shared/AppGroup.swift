import Foundation

/// Identifiers shared by the app and its extensions. Change them together
/// with project.yml (bundle ids, App Group entitlement).
enum AppGroup {
    /// The App Group whose container holds this device's identity and
    /// certificate, read by both the app (enrollment) and the tunnel extension.
    static let id = "group.com.shaip.vpn"
    /// The packet-tunnel extension's bundle id.
    static let tunnelBundleID = "com.shaip.vpn.tunnel"

    /// The shared container (nil if the entitlement is missing).
    static var container: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: id)
    }

    /// This device's long-term identity (ML-DSA-65 + Ed25519), created 0600 by
    /// the Rust core on first use.
    static var identityPath: String? { container?.appendingPathComponent("device.id").path }

    /// The device certificate enrollment stores next to the identity.
    static var certificatePath: String? { identityPath.map { $0 + ".cert" } }

    /// The certificate path if this device has enrolled.
    static var enrolledCertificatePath: String? {
        guard let p = certificatePath, FileManager.default.fileExists(atPath: p) else { return nil }
        return p
    }

    /// App → extension message asking for a `TunnelSnapshot`.
    static let statusMessage = Data("status".utf8)
}
