import SwiftUI
import SHAIPCore

/// 08 Protocol (the Settings tab): tunnel protocol, tunnel switches and advanced values. The avatar
/// opens Team & plan.
struct ProtocolView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        @Bindable var store = store
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.signal, size: 420, x: -220, y: 80, edge: .trailing, opacity: 0.1)]) {
            VStack(spacing: 10) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Protocol").ui(34, .bold, relativeTo: .largeTitle).em(-0.03, of: 34).foregroundStyle(Tok.ink)
                            .accessibilityAddTraits(.isHeader)
                        Eyebrow("ADMIN-LOCKED · \(Catalog.adminLocked)", color: Tok.dim(0.45))
                    }
                    Spacer()
                    NavigationLink {
                        TeamView()
                    } label: {
                        Text("MC").ui(14, .semibold).foregroundStyle(Tok.ink)
                            .frame(width: 44, height: 44)
                            .liquidGlass(in: Circle(), border: .white.opacity(0.22))
                            .overlay(Circle().inset(by: -4).strokeBorder(Tok.signal.opacity(0.1), lineWidth: 4))
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Team and plan")
                }
                .padding(.horizontal, 8).padding(.bottom, 2)

                ForEach(TunnelProtocol.allCases) { p in
                    ProtocolCard(proto: p, selected: store.proto == p) {
                        withAnimation(.smooth(duration: 0.3)) { store.proto = p }
                    }
                }

                Eyebrow("TUNNEL", tracking: 0.16, color: Tok.ink3)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 8).padding(.top, 6)

                VStack(spacing: 0) {
                    switchRow("Post-quantum handshake", "ML-KEM-768 + X25519 hybrid", $store.pqHandshake, first: true)
                    switchRow("Split tunneling", "Route corporate subnets only", $store.splitTunnel)
                    switchRow("On-demand", "Reconnect on any network change", $store.onDemand)
                    switchRow("Posture enforcement", "Block access if device drifts", $store.postureEnforced)
                }
                .padding(.horizontal, 16)
                .glassCard(24, .tile)

                HStack(spacing: 8) {
                    ForEach(Catalog.advanced, id: \.key) { kv in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(kv.key).mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.ink3)
                            Text(kv.value).mono(12, .medium).foregroundStyle(Tok.ink)
                        }
                        .padding(.horizontal, 12).padding(.vertical, 9)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(Color.white.opacity(0.04)))
                        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(Color.white.opacity(0.1), lineWidth: 0.5))
                        .accessibilityElement(children: .combine)
                    }
                }
            }
        }
        .toolbar(.hidden, for: .navigationBar)
    }

    private func switchRow(_ label: String, _ sub: String, _ isOn: Binding<Bool>, first: Bool = false) -> some View {
        Toggle(isOn: isOn.animation(.smooth)) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).ui(15, .medium).foregroundStyle(Tok.ink)
                Text(sub).ui(12).foregroundStyle(Tok.dim(0.48))
            }
        }
        .toggleStyle(GlassSwitchStyle())
        .sensoryFeedback(.selection, trigger: isOn.wrappedValue)
        .padding(.vertical, 10)
        .overlay(alignment: .top) { if !first { Hairline() } }
    }
}

/// A protocol radio card. Selected: signal border at 55%, a 4 pt halo at 10% and a cyan drop glow.
private struct ProtocolCard: View {
    let proto: TunnelProtocol
    let selected: Bool
    let action: () -> Void

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: 24, style: .continuous)
        Button(action: action) {
            HStack(spacing: 12) {
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        Text(proto.name).ui(16, .semibold).em(-0.01, of: 16).foregroundStyle(Tok.ink)
                        if let tag = proto.tag {
                            Chip(text: tag, size: 8, ink: Tok.signal, fill: Tok.signal.opacity(0.12), stroke: .clear, radius: 6, tracking: 0.14)
                        }
                    }
                    Text(proto.summary).ui(12).foregroundStyle(Tok.ink2).fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: 5) {
                        ForEach(proto.specs, id: \.self) { Chip(text: $0) }
                    }
                }
                Spacer(minLength: 0)
                Circle()
                    .strokeBorder(selected ? Tok.signal : Color.white.opacity(0.25), lineWidth: 1.5)
                    .frame(width: 22, height: 22)
                    .overlay {
                        Circle().fill(selected ? Tok.signal : .clear).frame(width: 10, height: 10)
                            .shadow(color: selected ? Tok.signal : .clear, radius: 4)
                    }
            }
            .padding(.horizontal, 16).padding(.vertical, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .glassCard(24, GlassRecipe(top: 0.08, bottom: 0.02, border: 0.14, specular: selected ? 0.3 : 0.25, shadow: false),
                       border: selected ? Tok.signal.opacity(0.55) : nil)
            .background {
                if selected {
                    // 0 20 40 −18 cyan glow: a blurred, inset fill pushed down behind the card.
                    shape.fill(Tok.signal.opacity(0.22)).padding(.horizontal, 18).blur(radius: 18).offset(y: 16)
                    // 0 0 0 4 halo, entirely outside the edge.
                    shape.inset(by: -4).strokeBorder(Tok.signal.opacity(0.1), lineWidth: 4)
                }
            }
            .contentShape(shape)
        }
        .buttonStyle(.plain)
        .sensoryFeedback(.selection, trigger: selected)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}
