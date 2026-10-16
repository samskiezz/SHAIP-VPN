import SwiftUI
import SHAIPCore

/// 02 Connect: workspace header, the live mesh with the connect orb, the status card and quick
/// actions. Tapping the status card opens Traffic.
struct ConnectView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(Router.self) private var router

    var body: some View {
        let on = store.connected
        ScreenScaffold {
            VStack(spacing: 0) {
                header
                ZStack {
                    SceneView(.net, layout: SceneLayout(cy: 0.5, r: 0.36, hudClear: 124), options: store.meshOptions)
                        .frame(height: 380)
                    OrbControl()
                }
                .padding(.horizontal, -16)
                .padding(.top, -10)
                NavigationLink {
                    TrafficView()
                } label: {
                    StatusCard()
                }
                .buttonStyle(.plain)
                .accessibilityHint("Opens live traffic")
                .padding(.top, 6)
                QuickActions().padding(.top, 20)
            }
        }
        .animation(.easeInOut(duration: 0.55), value: on)
        .toolbar(.hidden, for: .navigationBar)
    }

    private var header: some View {
        HStack {
            HStack(spacing: 10) {
                Text("A").font(.system(size: 13, weight: .bold)).foregroundStyle(Tok.bgMid)
                    .frame(width: 32, height: 32)
                    .background(Circle().fill(LinearGradient(colors: [Tok.signal, Tok.steel], startPoint: .topLeading, endPoint: .bottomTrailing)))
                Text("Acme Corp").ui(15, .semibold).em(-0.01, of: 15).foregroundStyle(Tok.ink)
                Text("PROD").mono(10, .medium).em(0.1, of: 10).foregroundStyle(Tok.dim(0.7))
                    .padding(.horizontal, 6).padding(.vertical, 3)
                    .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color.white.opacity(0.08)))
            }
            .padding(.leading, 6).padding(.trailing, 16)
            .frame(height: 44)
            .liquidGlass(in: Capsule(style: .continuous), interactive: false)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Workspace Acme Corp, production")
            Spacer()
            RoundGlassButton {
                store.unreadAlerts = false
                router.tab = .security
            } label: {
                Image(systemName: "bell").font(.system(size: 18, weight: .regular)).foregroundStyle(Tok.ink)
                    .overlay(alignment: .topTrailing) {
                        if store.unreadAlerts {
                            Circle().fill(Tok.threat).frame(width: 8, height: 8)
                                .overlay(Circle().strokeBorder(Tok.dotRing, lineWidth: 2).padding(-2))
                                .offset(x: 2, y: -1)
                        }
                    }
            }
            .accessibilityLabel(store.unreadAlerts ? "Alerts, unread" : "Alerts")
        }
        .padding(.top, 2)
    }
}

/// The 156 pt glass orb over the mesh: dotted tick ring (r 118), track and session progress arc
/// (r 100), power glyph, SECURED/OFFLINE and the tap hint. Tap toggles the tunnel.
struct OrbControl: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let on = store.connected
        let tint = on ? Tok.signal : Tok.dim(0.55)
        ZStack {
            Circle().stroke(Color.white.opacity(0.2), style: StrokeStyle(lineWidth: 6, dash: [0.7, 5.48]))
                .frame(width: 236, height: 236)
            Circle().stroke(on ? Tok.signal.opacity(0.18) : Color.white.opacity(0.08), lineWidth: 1)
                .frame(width: 200, height: 200)
            Circle().trim(from: 0, to: Format.orbArc(sessionSeconds: store.sessionSeconds))
                .stroke(tint, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .frame(width: 200, height: 200)
                .animation(arcAnimation, value: store.sessionSeconds)
            Button {
                store.toggleConnection()
            } label: {
                VStack(spacing: 6) {
                    Image(systemName: "power").font(.system(size: 26, weight: .semibold)).foregroundStyle(tint)
                    Text(on ? "SECURED" : "OFFLINE").mono(11, .semibold).em(0.18, of: 11).foregroundStyle(tint)
                    Text(on ? "Tap to disconnect" : "Tap to connect").ui(11, relativeTo: .caption2).foregroundStyle(Tok.ink2)
                }
                .frame(width: 156, height: 156)
                .background { OrbSurface(glow: on ? Tok.signal.opacity(0.28) : .clear) }
                .contentShape(Circle())
            }
            .buttonStyle(OrbButtonStyle())
            .sensoryFeedback(.impact(weight: .medium), trigger: on)
            .accessibilityLabel(on ? "Disconnect VPN" : "Connect VPN")
            .accessibilityValue(on ? "Protected via \(store.node.city)" : "Not protected")
        }
        .frame(width: 244, height: 244)
    }

    /// Linear between ticks; no animation when the 30 s cycle wraps or the arc empties.
    private var arcAnimation: Animation? {
        guard let s = store.sessionSeconds, s % 30 != 0 else { return nil }
        return .linear(duration: 1)
    }
}

private struct OrbSurface: View {
    let glow: Color

    var body: some View {
        Circle()
            .fill(Color(hex: 0x0A0E1A, opacity: 0.4)
                .shadow(.inner(color: .white.opacity(0.5), radius: 0, x: 0, y: 1))
                .shadow(.inner(color: .black.opacity(0.4), radius: 14, x: 0, y: -14)))
            .overlay {
                Circle().fill(RadialGradient(stops: [.init(color: .white.opacity(0.24), location: 0),
                                                     .init(color: .white.opacity(0.04), location: 0.6)],
                                             center: UnitPoint(x: 0.3, y: 0.18), startRadius: 0, endRadius: 125))
            }
            .glassEffect(.regular, in: Circle())
            .overlay { Circle().strokeBorder(Color.white.opacity(0.32), lineWidth: 0.5) }
            .shadow(color: .black.opacity(0.85), radius: 30, x: 0, y: 30)
            .shadow(color: glow, radius: 35)
    }
}

/// Orb tap: scale to 0.94 and back with `.bouncy`.
private struct OrbButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.94 : 1)
            .animation(.bouncy, value: configuration.isPressed)
    }
}

/// Status card: PROTECTED/EXPOSED pill and session timer, city, node · DC · protocol, exit IP and the
/// 4-up DOWN / UP / RTT / LOSS row.
struct StatusCard: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let on = store.connected, node = store.node, t = store.telemetry
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                StatusPill(text: on ? "PROTECTED" : "EXPOSED", color: on ? Tok.ok : Tok.threat)
                Spacer()
                Text(Format.clock(store.sessionSeconds)).mono(15, .medium).monospacedDigit().em(0.02, of: 15).foregroundStyle(Tok.ink)
                    .accessibilityLabel(on ? "Session time \(Format.clock(store.sessionSeconds))" : "No session")
            }
            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .lastTextBaseline, spacing: 12) {
                    Text(on ? node.city : "Not connected").ui(26, .semibold, relativeTo: .title).em(-0.035, of: 26)
                        .foregroundStyle(Tok.ink).lineLimit(1).minimumScaleFactor(0.7)
                    Spacer(minLength: 0)
                    VStack(alignment: .trailing, spacing: 4) {
                        Text("EXIT IP").mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.dim(0.4))
                        Text(on ? node.exitIP : "—").mono(13, .medium).foregroundStyle(Tok.ink)
                    }
                    .fixedSize()
                    .accessibilityElement(children: .combine)
                }
                // One line (it wrapped under EXIT IP in the handoff); shrinks for long DC names.
                Text("\(node.id) · \(node.dc) · \(store.proto.name)").mono(11, .regular).foregroundStyle(Tok.ink2)
                    .lineLimit(1).minimumScaleFactor(0.75)
            }
            HStack(spacing: 0) {
                metric("DOWN", on ? Format.fixed(t.downMbps, 0) : "—", "Mbps", first: true)
                metric("UP", on ? Format.fixed(t.upMbps, 0) : "—", "Mbps")
                metric("RTT", on ? String(t.rttMs) : "—", "ms")
                metric("LOSS", on ? Format.fixed(t.lossPct, 2) : "—", "%")
            }
            .padding(.top, 12)
            .overlay(alignment: .top) { Hairline(color: .white.opacity(0.1)) }
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(30)
        .contentShape(RoundedRectangle(cornerRadius: 30, style: .continuous))
    }

    private func metric(_ label: String, _ value: String, _ unit: String, first: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label).mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.ink3)
            HStack(alignment: .firstTextBaseline, spacing: 3) {
                Text(value).ui(19, .semibold, relativeTo: .title3).em(-0.03, of: 19).monospacedDigit().foregroundStyle(Tok.ink)
                    .lineLimit(1).minimumScaleFactor(0.7)
                Text(unit).mono(10, .regular).foregroundStyle(Tok.dim(0.45))
            }
        }
        .padding(.leading, first ? 0 : 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(alignment: .leading) { if !first { Rectangle().fill(Tok.hairline).frame(width: 0.5) } }
        .accessibilityElement(children: .combine)
    }
}

/// Quick actions: kill switch, multi-hop, private DNS. The border tints to 35% of the state colour.
struct QuickActions: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        @Bindable var store = store
        GlassEffectContainer(spacing: 8) {
            HStack(spacing: 8) {
                QuickTile(icon: "lock", label: "Kill switch", state: store.killSwitch ? "ARMED" : "DISARMED",
                          color: store.killSwitch ? Tok.ok : Tok.threat, tinted: true, isOn: $store.killSwitch, impact: true)
                QuickTile(icon: "point.3.connected.trianglepath.dotted", label: "Multi-hop", state: store.multiHop ? "3 HOPS" : "DIRECT",
                          color: store.multiHop ? Tok.signal : Tok.ink2, tinted: store.multiHop, isOn: $store.multiHop)
                QuickTile(icon: "network.badge.shield.half.filled", label: "Private DNS", state: store.privateDNS ? "FILTERING" : "OFF",
                          color: store.privateDNS ? Tok.steel : Tok.ink2, tinted: store.privateDNS, isOn: $store.privateDNS)
            }
        }
    }
}

private struct QuickTile: View {
    let icon: String
    let label: String
    let state: String
    let color: Color
    let tinted: Bool
    @Binding var isOn: Bool
    var impact = false

    var body: some View {
        Button {
            withAnimation(.smooth(duration: 0.3)) { isOn.toggle() }
        } label: {
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Image(systemName: icon).font(.system(size: 13, weight: .semibold)).foregroundStyle(color).frame(width: 15)
                    // "Private DNS" wrapped onto two lines in the handoff's 13 pt; keep one line.
                    Text(label).ui(13, .semibold, relativeTo: .footnote).em(-0.01, of: 13).foregroundStyle(Tok.ink)
                        .lineLimit(1).minimumScaleFactor(0.8)
                }
                Text(state).mono(9, .semibold).em(0.14, of: 9).foregroundStyle(color).lineLimit(1)
            }
            .padding(.horizontal, 12)
            .frame(maxWidth: .infinity, minHeight: 62, alignment: .leading)
            .contentShape(RoundedRectangle(cornerRadius: 22, style: .continuous))
        }
        .buttonStyle(.plain)
        .liquidGlass(in: RoundedRectangle(cornerRadius: 22, style: .continuous),
                     border: tinted ? color.opacity(0.35) : .white.opacity(0.14))
        .sensoryFeedback(impact ? .impact(weight: .medium) : .selection, trigger: isOn)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(state.capitalized)
        .accessibilityAddTraits([.isButton, .isToggle])
    }
}
