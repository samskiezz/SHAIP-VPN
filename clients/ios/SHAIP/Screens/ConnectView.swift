import SwiftUI
import SHAIPCore

/// Connect: the server, the ambient mesh with the connect orb, the session
/// card and quick settings. Every number is measured by the tunnel; tapping
/// the card opens Traffic.
struct ConnectView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(Router.self) private var router

    var body: some View {
        ScreenScaffold {
            VStack(spacing: 0) {
                header
                ZStack {
                    SceneView(.net, layout: SceneLayout(cy: 0.5, r: 0.36, hudClear: 124), options: store.meshOptions)
                        .frame(height: 380)
                        .accessibilityHidden(true)
                    OrbControl()
                }
                .padding(.horizontal, -16)
                .padding(.top, -10)
                Button {
                    router.tab = .traffic
                } label: {
                    StatusCard()
                }
                .buttonStyle(.plain)
                .accessibilityHint("Opens traffic")
                .padding(.top, 6)
                if let error = store.lastError, !store.connected {
                    Text(error).ui(13, relativeTo: .footnote).foregroundStyle(Tok.warn)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 8).padding(.top, 10)
                        .fixedSize(horizontal: false, vertical: true)
                }
                QuickActions().padding(.top, 20)
            }
        }
        .animation(.easeInOut(duration: 0.55), value: store.connected)
        .toolbar(.hidden, for: .navigationBar)
    }

    private var header: some View {
        HStack {
            HStack(spacing: 10) {
                Image(systemName: "server.rack").font(.system(size: 13, weight: .bold)).foregroundStyle(Tok.bgMid)
                    .frame(width: 32, height: 32)
                    .background(Circle().fill(LinearGradient(colors: [Tok.signal, Tok.steel], startPoint: .topLeading, endPoint: .bottomTrailing)))
                Text(store.config?.label ?? "No server").ui(15, .semibold).em(-0.01, of: 15).foregroundStyle(Tok.ink)
                    .lineLimit(1)
                Text(store.enrolled ? "ENROLLED" : "OPEN").mono(10, .medium).em(0.1, of: 10).foregroundStyle(Tok.dim(0.7))
                    .padding(.horizontal, 6).padding(.vertical, 3)
                    .background(RoundedRectangle(cornerRadius: 6, style: .continuous).fill(Color.white.opacity(0.08)))
            }
            .padding(.leading, 6).padding(.trailing, 16)
            .frame(height: 44)
            .liquidGlass(in: Capsule(style: .continuous), interactive: false)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Server \(store.config?.label ?? "none"), \(store.enrolled ? "this device is enrolled" : "not enrolled")")
            Spacer()
        }
        .padding(.top, 2)
    }
}

/// The 156 pt glass orb over the mesh: dotted tick ring, track and session arc,
/// power glyph, the state and the tap hint. Tap connects or disconnects.
struct OrbControl: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let on = store.connected
        let pending = store.connecting || store.reconnecting
        let tint = on ? Tok.signal : pending ? Tok.warn : Tok.dim(0.55)
        ZStack {
            Circle().stroke(Color.white.opacity(0.2), style: StrokeStyle(lineWidth: 6, dash: [0.7, 5.48]))
                .frame(width: 236, height: 236)
            Circle().stroke(on ? Tok.signal.opacity(0.18) : Color.white.opacity(0.08), lineWidth: 1)
                .frame(width: 200, height: 200)
            Circle().trim(from: 0, to: Format.orbArc(sessionSeconds: on ? store.sessionSeconds : nil))
                .stroke(tint, style: StrokeStyle(lineWidth: 2.5, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .frame(width: 200, height: 200)
                .animation(arcAnimation, value: store.sessionSeconds)
            Button {
                store.toggleConnection()
            } label: {
                VStack(spacing: 6) {
                    Image(systemName: "power").font(.system(size: 26, weight: .semibold)).foregroundStyle(tint)
                    Text(orbState).mono(11, .semibold).em(0.18, of: 11).foregroundStyle(tint)
                    Text(store.isOn ? "Tap to disconnect" : "Tap to connect").ui(11, relativeTo: .caption2).foregroundStyle(Tok.ink2)
                }
                .frame(width: 156, height: 156)
                .background { OrbSurface(glow: on ? Tok.signal.opacity(0.28) : .clear) }
                .contentShape(Circle())
            }
            .buttonStyle(OrbButtonStyle())
            .disabled(store.config == nil || store.status == .disconnecting)
            .sensoryFeedback(.impact(weight: .medium), trigger: on)
            .accessibilityLabel(store.isOn ? "Disconnect VPN" : "Connect VPN")
            .accessibilityValue(store.stateLabel.capitalized)
        }
        .frame(width: 244, height: 244)
    }

    private var orbState: String {
        if store.reconnecting { return "RECONNECTING" }
        switch store.status {
        case .connected: return "CONNECTED"
        case .connecting: return "CONNECTING"
        case .disconnecting: return "STOPPING"
        default: return "OFF"
        }
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

/// The session card: state and timer, the server, the tunnel address and
/// resolver, and DOWN / UP / RTT / DATA — all measured.
struct StatusCard: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let on = store.connected, snap = store.snapshot
        let total = (snap?.bytesSent ?? 0) + (snap?.bytesReceived ?? 0)
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                StatusPill(text: store.stateLabel, color: on ? Tok.ok : (store.connecting || store.reconnecting) ? Tok.warn : Tok.ink2)
                Spacer()
                Text(Format.clock(store.sessionSeconds)).mono(15, .medium).monospacedDigit().em(0.02, of: 15).foregroundStyle(Tok.ink)
                    .accessibilityLabel(store.sessionSeconds == nil ? "No session" : "Connected for \(Format.clock(store.sessionSeconds))")
            }
            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .lastTextBaseline, spacing: 12) {
                    Text(store.config?.label ?? "No server").ui(26, .semibold, relativeTo: .title).em(-0.035, of: 26)
                        .foregroundStyle(Tok.ink).lineLimit(1).minimumScaleFactor(0.6)
                    Spacer(minLength: 0)
                    VStack(alignment: .trailing, spacing: 4) {
                        Text("TUNNEL IP").mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.dim(0.4))
                        Text(on ? (snap?.tunnelAddress ?? "—") : "—").mono(13, .medium).foregroundStyle(Tok.ink)
                    }
                    .fixedSize()
                    .accessibilityElement(children: .combine)
                }
                Text(subtitle).mono(11, .regular).foregroundStyle(Tok.ink2).lineLimit(1).minimumScaleFactor(0.75)
            }
            HStack(spacing: 0) {
                metric("DOWN", on ? Format.mbps(store.downMbps) : "—", "Mbps", first: true)
                metric("UP", on ? Format.mbps(store.upMbps) : "—", "Mbps")
                metric("RTT", store.rttMs.map(String.init) ?? "—", "ms")
                let data = Format.bytes(total)
                metric("DATA", snap == nil ? "—" : data.value, data.unit)
            }
            .padding(.top, 12)
            .overlay(alignment: .top) { Hairline(color: .white.opacity(0.1)) }
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(30)
        .contentShape(RoundedRectangle(cornerRadius: 30, style: .continuous))
    }

    private var subtitle: String {
        guard store.connected, let snap = store.snapshot else {
            return store.config.map { "\($0.address) · PQANON/1" } ?? "Set up a server to connect"
        }
        return "DNS \(snap.dns ?? "unchanged") · MTU \(snap.mtu) · PQANON/1"
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

/// Quick settings that are real iOS VPN settings, plus where DNS goes.
struct QuickActions: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        GlassEffectContainer(spacing: 8) {
            HStack(spacing: 8) {
                QuickTile(icon: "lock", label: "Kill switch", state: store.killSwitch ? "ON" : "OFF",
                          color: store.killSwitch ? Tok.ok : Tok.ink2, tinted: store.killSwitch, impact: true) {
                    Task { await store.setKillSwitch(!store.killSwitch) }
                }
                QuickTile(icon: "arrow.triangle.2.circlepath", label: "Auto-connect", state: store.onDemand ? "ON" : "OFF",
                          color: store.onDemand ? Tok.signal : Tok.ink2, tinted: store.onDemand) {
                    Task { await store.setOnDemand(!store.onDemand) }
                }
                QuickTile(icon: "network", label: "DNS", state: dnsState,
                          color: store.snapshot?.dns != nil && store.connected ? Tok.steel : Tok.ink2,
                          tinted: store.snapshot?.dns != nil && store.connected, action: nil)
            }
        }
    }

    private var dnsState: String {
        guard store.connected else { return "—" }
        return store.snapshot?.dns != nil ? "VIA TUNNEL" : "YOUR NETWORK"
    }
}

private struct QuickTile: View {
    let icon: String
    let label: String
    let state: String
    let color: Color
    let tinted: Bool
    var impact = false
    /// nil: a status tile, not a control.
    let action: (() -> Void)?

    var body: some View {
        let content = VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 6) {
                Image(systemName: icon).font(.system(size: 13, weight: .semibold)).foregroundStyle(color).frame(width: 15)
                Text(label).ui(13, .semibold, relativeTo: .footnote).em(-0.01, of: 13).foregroundStyle(Tok.ink)
                    .lineLimit(1).minimumScaleFactor(0.8)
            }
            Text(state).mono(9, .semibold).em(0.14, of: 9).foregroundStyle(color).lineLimit(1).minimumScaleFactor(0.8)
        }
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity, minHeight: 62, alignment: .leading)
        .contentShape(RoundedRectangle(cornerRadius: 22, style: .continuous))

        Group {
            if let action {
                Button(action: { withAnimation(.smooth(duration: 0.3)) { action() } }) { content }
                    .buttonStyle(.plain)
                    .sensoryFeedback(impact ? .impact(weight: .medium) : .selection, trigger: state)
                    .accessibilityAddTraits([.isButton, .isToggle])
            } else {
                content
            }
        }
        .liquidGlass(in: RoundedRectangle(cornerRadius: 22, style: .continuous),
                     border: tinted ? color.opacity(0.35) : .white.opacity(0.14))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(state.capitalized)
    }
}
