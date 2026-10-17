import SwiftUI
import SHAIPCore

/// Server: the one server this iPhone tunnels to, the identity the handshake
/// proved, and this device's enrollment. All of it from the config the user
/// imported and from the live session.
struct ServerView: View {
    @Environment(TunnelStore.self) private var store
    @State private var replacing = false
    @State private var enrolling = false
    @State private var confirmRemove = false

    var body: some View {
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.signal, size: 420, x: -220, y: 80, edge: .trailing, opacity: 0.1)]) {
            VStack(spacing: 10) {
                LargeTitle("Server")
                if let config = store.config {
                    serverCard(config)
                    identityCard
                    deviceCard(config)
                    actions
                }
            }
        }
        .toolbar(.hidden, for: .navigationBar)
        .sheet(isPresented: $replacing) {
            ImportConfigSheet { config in try await store.install(config) }.privacyCover()
        }
        .sheet(isPresented: $enrolling) {
            EnrollSheet(link: "").environment(store).privacyCover()
        }
        .confirmationDialog("Remove this server from your iPhone?", isPresented: $confirmRemove, titleVisibility: .visible) {
            Button("Remove", role: .destructive) { Task { await store.removeConfiguration() } }
        } message: {
            Text("The VPN configuration is deleted. This device's identity stays, so it can reconnect after you import the config again.")
        }
    }

    private func serverCard(_ c: ServerConfig) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                StatusPill(text: store.stateLabel, color: store.connected ? Tok.ok : Tok.ink2)
                Spacer()
                Chip(text: "SHAIP/1", ink: Tok.signal, fill: Tok.signal.opacity(0.12), stroke: .clear)
            }
            Text(c.label).ui(24, .semibold, relativeTo: .title2).em(-0.03, of: 24).foregroundStyle(Tok.ink).lineLimit(1).minimumScaleFactor(0.6)
            kv("ADDRESS", c.address)
            kv("CONNECTED TO", store.connected ? (store.snapshot?.serverAddress ?? "—") : "—")
            kv("TUNNEL IP", store.connected ? (store.snapshot?.tunnelAddress ?? "—") : "—")
            kv("RESOLVER", store.connected ? (store.snapshot?.dns ?? "none pushed") : "—")
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(30)
    }

    private var identityCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Eyebrow("SERVER IDENTITY", tracking: 0.16, color: Tok.ink3)
            if store.connected, let id = store.snapshot?.serverIdentity {
                Text(Format.fingerprint(id, groups: 8)).mono(14, .medium).foregroundStyle(Tok.ink)
                    .textSelection(.enabled)
                Text("Proven by the handshake: the server signed it with the ML-DSA-65 and Ed25519 keys in your config. Compare it with the identity_id your operator published.")
                    .ui(12, relativeTo: .footnote).foregroundStyle(Tok.dim(0.5)).fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Connect to verify. The tunnel refuses any server that cannot prove it holds the pinned keys.")
                    .ui(13, relativeTo: .footnote).foregroundStyle(Tok.dim(0.55)).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, 18).padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(26, .tile)
    }

    private func deviceCard(_ c: ServerConfig) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Eyebrow("THIS DEVICE", tracking: 0.16, color: Tok.ink3)
            if store.enrolled {
                Text("Enrolled").ui(15, .semibold).foregroundStyle(Tok.ok)
                if let id = store.deviceID {
                    Text("Device \(Format.fingerprint(id, groups: 4))").mono(12, .regular).foregroundStyle(Tok.dim(0.6))
                }
                Text("Servers that admit enrolled devices only will accept this iPhone until the device is revoked.")
                    .ui(12, relativeTo: .footnote).foregroundStyle(Tok.dim(0.5)).fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Not enrolled").ui(15, .semibold).foregroundStyle(Tok.ink2)
                Text(c.canEnroll
                     ? "If this server admits enrolled devices only, enroll with the link from your account page."
                     : "This server's config has no enrollment section; open servers don't need one.")
                    .ui(12, relativeTo: .footnote).foregroundStyle(Tok.dim(0.5)).fixedSize(horizontal: false, vertical: true)
                if c.canEnroll {
                    Button("Enroll this device") { enrolling = true }
                        .ui(14, .semibold).foregroundStyle(Tok.signal).padding(.top, 2)
                }
            }
        }
        .padding(.horizontal, 18).padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(26, .tile)
    }

    private var actions: some View {
        HStack(spacing: 8) {
            Button { replacing = true } label: {
                Label("Replace config", systemImage: "square.and.arrow.down").ui(14, .semibold).foregroundStyle(Tok.ink)
                    .frame(maxWidth: .infinity, minHeight: 48)
            }
            .buttonStyle(.plain)
            .liquidGlass(in: Capsule(style: .continuous))
            Button { confirmRemove = true } label: {
                Label("Remove", systemImage: "trash").ui(14, .semibold).foregroundStyle(Tok.threat)
                    .frame(maxWidth: .infinity, minHeight: 48)
            }
            .buttonStyle(.plain)
            .liquidGlass(in: Capsule(style: .continuous))
        }
        .padding(.top, 4)
    }

    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(k).mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.dim(0.42))
            Spacer(minLength: 12)
            Text(v).mono(12, .medium).foregroundStyle(Tok.ink).lineLimit(1).minimumScaleFactor(0.7)
        }
        .accessibilityElement(children: .combine)
    }
}
