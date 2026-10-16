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

    /// Keep this device's identity and certificate out of iCloud and computer
    /// backups, and readable only after the device's first unlock (the tunnel
    /// reconnects while the phone is locked, so it can't be stricter). A
    /// restored or new phone enrolls again instead of inheriting this one's
    /// keys.
    static func protectKeyFiles() {
        for path in [identityPath, certificatePath].compactMap({ $0 }) where FileManager.default.fileExists(atPath: path) {
            var url = URL(fileURLWithPath: path)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? url.setResourceValues(values)
            try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                                                   ofItemAtPath: path)
        }
    }

    /// The certificate path if this device has enrolled.
    static var enrolledCertificatePath: String? {
        guard let p = certificatePath, FileManager.default.fileExists(atPath: p) else { return nil }
        return p
    }

    /// App → extension message asking for a `TunnelSnapshot`.
    static let statusMessage = Data("status".utf8)
}
