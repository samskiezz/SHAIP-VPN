import SwiftUI
import SHAIPCore

/// 03 Network: the live globe, the current-node chip (opens Nodes) and the active route card.
/// The layers button toggles the globe's HUD labels.
struct NetworkView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        ScreenScaffold {
            VStack(spacing: 0) {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Network").ui(34, .bold, relativeTo: .largeTitle).em(-0.03, of: 34).foregroundStyle(Tok.ink)
                            .accessibilityAddTraits(.isHeader)
                        Eyebrow("\(Catalog.edgeNodes) NODES · \(Catalog.regions) REGIONS · \(Catalog.routes) ROUTES", color: Tok.dim(0.45))
                    }
                    Spacer()
                    RoundGlassButton {
                        store.globeHUD.toggle()
                    } label: {
                        Image(systemName: "square.3.layers.3d").font(.system(size: 18)).foregroundStyle(store.globeHUD ? Tok.ink : Tok.ink2)
                    }
                    .sensoryFeedback(.selection, trigger: store.globeHUD)
                    .accessibilityLabel("Map labels")
                    .accessibilityValue(store.globeHUD ? "Shown" : "Hidden")
                }
                .padding(.leading, 8)

                SceneView(.globe, layout: SceneLayout(r: 0.4), options: store.globeOptions)
                    .frame(height: 420)
                    .overlay(alignment: .topLeading) {
                        NavigationLink {
                            NodesView()
                        } label: {
                            HStack(spacing: 8) {
                                GlowDot(color: store.connected ? Tok.ok : Tok.threat)
                                Text("\(store.node.id) · \(store.connected ? "\(store.rtt) ms" : "OFFLINE")")
                                    .mono(10, .medium).em(0.1, of: 10).foregroundStyle(Tok.ink).monospacedDigit()
                                Image(systemName: "chevron.right").font(.system(size: 8, weight: .bold)).foregroundStyle(Tok.ink3)
                            }
                            .padding(.horizontal, 12)
                            .frame(height: 30)
                            .liquidGlass(in: Capsule(style: .continuous))
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Node \(store.node.id), \(store.connected ? "\(store.rtt) milliseconds" : "offline")")
                        .accessibilityHint("Choose a node")
                        .padding(.leading, 16)
                        .padding(.top, 18)
                    }
                    .padding(.horizontal, -16)
                    .padding(.top, 10)

                RouteCard().padding(.top, 10)
            }
        }
        .toolbar(.hidden, for: .navigationBar)
    }
}

/// Active route: iPhone → {CODE} edge → SIN relay → Acme VPC, with a gradient connector; hops glow
/// while active and the relay reads "bypassed" when multi-hop is off.
struct RouteCard: View {
    @Environment(TunnelStore.self) private var store

    private struct Hop: Identifiable {
        let name: String, meta: String, active: Bool
        var id: String { name }
    }

    var body: some View {
        let on = store.connected, hop = store.multiHop
        let hops = [
            Hop(name: "iPhone", meta: "10.84.12.7", active: true),
            Hop(name: "\(store.node.code) edge", meta: on ? "\(store.rtt) ms" : "—", active: on),
            Hop(name: "SIN relay", meta: !hop ? "bypassed" : on ? "+41 ms" : "—", active: on && hop),
            Hop(name: "Acme VPC", meta: "ap-se-2", active: on),
        ]
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("Active route").ui(17, .semibold, relativeTo: .headline).em(-0.02, of: 17).foregroundStyle(Tok.ink)
                Spacer()
                Text(hop ? "MULTI-HOP · 3" : "DIRECT").mono(9, .semibold).em(0.14, of: 9).foregroundStyle(Tok.signal)
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Tok.signal.opacity(0.1)))
            }
            HStack(alignment: .top, spacing: 0) {
                ForEach(hops) { h in
                    VStack(spacing: 8) {
                        Circle()
                            .fill(h.active ? Tok.signal : Tok.dotRing)
                            .overlay(Circle().strokeBorder(h.active ? Tok.signal : Color.white.opacity(0.25), lineWidth: 2))
                            .frame(width: 13, height: 13)
                            .shadow(color: h.active ? Tok.signal.opacity(0.6) : .clear, radius: 6)
                        Text(h.name).ui(12, .semibold, relativeTo: .caption).em(-0.01, of: 12).foregroundStyle(Tok.ink)
                            .lineLimit(1).minimumScaleFactor(0.8)
                        Text(h.meta).mono(10, .regular).foregroundStyle(Tok.ink2).lineLimit(1).minimumScaleFactor(0.8)
                    }
                    .frame(maxWidth: .infinity)
                    .accessibilityElement(children: .combine)
                    .accessibilityValue(h.active ? "active" : "inactive")
                }
            }
            .background(alignment: .top) {
                GeometryReader { g in
                    LinearGradient(colors: [Tok.signal, Tok.steel], startPoint: .leading, endPoint: .trailing)
                        .frame(width: g.size.width * 0.76, height: 1)
                        .opacity(0.6)
                        .offset(x: g.size.width * 0.12, y: 6)
                }
            }
            HStack(spacing: 0) {
                stat("CIPHER", "ChaCha20")
                stat("HANDSHAKE", on ? Format.handshake(tick: store.tick) : "—")
                stat("MTU", "1420")
            }
            .padding(.top, 12)
            .overlay(alignment: .top) { Hairline(color: .white.opacity(0.1)) }
        }
        .padding(18)
        .glassCard(30)
        .animation(.easeInOut(duration: 0.55), value: on)
    }

    private func stat(_ k: String, _ v: String) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(k).mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.ink3)
            Text(v).mono(13, .medium).foregroundStyle(Tok.ink).monospacedDigit()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}
