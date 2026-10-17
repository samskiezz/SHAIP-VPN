import SwiftUI
import SHAIPCore

/// Settings: the protocol this app actually speaks, the iOS VPN settings that
/// are real switches, the tunnel's real parameters, and versions.
struct SettingsView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.signal, size: 420, x: -220, y: 80, edge: .trailing, opacity: 0.1)]) {
            VStack(spacing: 10) {
                LargeTitle("Settings")
                protocolCard

                Eyebrow("VPN", tracking: 0.16, color: Tok.ink3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 8).padding(.top, 6)
                VStack(spacing: 0) {
                    switchRow("Kill switch",
                              store.isOn ? "Blocks traffic outside the tunnel. Takes effect the next time the VPN connects."
                                         : "Blocks traffic outside the tunnel while the VPN is on, including local devices.",
                              isOn: store.killSwitch, first: true) { on in Task { await store.setKillSwitch(on) } }
                    switchRow("Connect automatically", "iOS keeps the VPN connected on any network.",
                              isOn: store.onDemand) { on in Task { await store.setOnDemand(on) } }
                }
                .padding(.horizontal, 16)
                .glassCard(24, .tile)

                Eyebrow("TUNNEL", tracking: 0.16, color: Tok.ink3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 8).padding(.top, 6)
                HStack(spacing: 8) {
                    fact("PORT", store.config.flatMap { $0.address.split(separator: ":").last.map { "UDP \($0)" } } ?? "—")
                    fact("MTU", store.snapshot.map { "\($0.mtu)" } ?? "1370")
                    fact("KEEPALIVE", "10 s")
                    fact("REKEY", "\(Protection.rekeyMinutes) min")
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("SHAIP \(Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "") · core \(pqanonVersion)")
                        .mono(11, .medium).foregroundStyle(Tok.dim(0.55))
                    Text("Pre-release software. SHAIP VPN has not yet had an independent security audit.")
                        .ui(12, relativeTo: .footnote).foregroundStyle(Tok.dim(0.45)).fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8).padding(.top, 8)
            }
        }
        .toolbar(.hidden, for: .navigationBar)
    }

    /// The one protocol, with what it really uses.
    private var protocolCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text("SHAIP/1").ui(16, .semibold).em(-0.01, of: 16).foregroundStyle(Tok.ink)
                Chip(text: "THE ONLY PROTOCOL", size: 8, ink: Tok.signal, fill: Tok.signal.opacity(0.12), stroke: .clear, radius: 6, tracking: 0.14)
            }
            Text("Hybrid post-quantum handshake: the session key comes from both ML-KEM-768 and X25519, so breaking one is not enough. Both sides sign with ML-DSA-65 and Ed25519. Traffic is sealed with ChaCha20-Poly1305 and padded to common packet sizes.")
                .ui(12).foregroundStyle(Tok.ink2).fixedSize(horizontal: false, vertical: true)
            FlowLayout(spacing: 5) {
                ForEach(["UDP", "ML-KEM-768 + X25519", "ML-DSA-65 + Ed25519", "ChaCha20-Poly1305"], id: \.self) { Chip(text: $0) }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(24)
    }

    private func switchRow(_ label: String, _ sub: String, isOn: Bool, first: Bool = false, set: @escaping (Bool) -> Void) -> some View {
        Toggle(isOn: Binding(get: { isOn }, set: set)) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).ui(15, .medium).foregroundStyle(Tok.ink)
                Text(sub).ui(12).foregroundStyle(Tok.dim(0.48)).fixedSize(horizontal: false, vertical: true)
            }
        }
        .toggleStyle(GlassSwitchStyle())
        .sensoryFeedback(.selection, trigger: isOn)
        .padding(.vertical, 10)
        .overlay(alignment: .top) { if !first { Hairline() } }
    }

    private func fact(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(k).mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.ink3)
            Text(v).mono(12, .medium).foregroundStyle(Tok.ink).lineLimit(1).minimumScaleFactor(0.7)
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.white.opacity(0.04)))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(Color.white.opacity(0.1), lineWidth: 0.5))
        .accessibilityElement(children: .combine)
    }
}
