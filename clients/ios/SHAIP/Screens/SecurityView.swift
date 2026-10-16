import SwiftUI
import SHAIPCore

/// 07 Security: the threat radar, counters, the kill switch and recent alerts.
/// In production the kill switch sets `includeAllNetworks` and `enforceRoutes` on the
/// NETunnelProviderManager.
struct SecurityView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        @Bindable var store = store
        ScreenScaffold {
            VStack(spacing: 10) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Security").ui(34, .bold, relativeTo: .largeTitle).em(-0.03, of: 34).foregroundStyle(Tok.ink)
                        .accessibilityAddTraits(.isHeader)
                    Spacer()
                    Text("● \(Catalog.activeThreats) ACTIVE").mono(10, .medium).em(0.14, of: 10).foregroundStyle(Tok.threat)
                        .accessibilityLabel("\(Catalog.activeThreats) active threats")
                }
                .padding(.horizontal, 8)

                ZStack(alignment: .top) {
                    SceneView(.radar, layout: SceneLayout(r: 0.4), options: store.radarOptions)
                        .frame(width: 320, height: 280)
                        .frame(maxWidth: .infinity)
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) { Text("SWEEP 1.1 rad/s"); Text("RANGE 24H") }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 2) { Text("DNS · IP · TLS"); Text("22 SIGNALS") }
                    }
                    .mono(9, .medium).em(0.12, of: 9).foregroundStyle(Tok.dim(0.4))
                    .padding(.top, 6)
                    .accessibilityHidden(true)
                }
                .padding(.top, 4)

                HStack(spacing: 8) {
                    ForEach(Catalog.counters) { k in
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(spacing: 5) {
                                Circle().fill(Tok.tone(k.tone)).frame(width: 4, height: 4)
                                Text(k.label).mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.dim(0.45))
                            }
                            Text(k.value).ui(20, .semibold, relativeTo: .title3).em(-0.03, of: 20).monospacedDigit().foregroundStyle(Tok.ink)
                        }
                        .padding(.horizontal, 13).padding(.vertical, 11)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glassCard(20, .tile)
                        .accessibilityElement(children: .combine)
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    Toggle(isOn: $store.killSwitch.animation(.smooth)) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(store.killSwitch ? "ARMED" : "DISARMED").mono(9, .semibold).em(0.16, of: 9)
                                .foregroundStyle(store.killSwitch ? Tok.ok : Tok.threat)
                            Text("Kill switch").ui(19, .semibold, relativeTo: .title3).em(-0.02, of: 19).foregroundStyle(Tok.ink)
                        }
                    }
                    .toggleStyle(GlassSwitchStyle())
                    .sensoryFeedback(.impact(weight: .medium), trigger: store.killSwitch)
                    Text(store.killSwitch
                         ? "All traffic is blocked if the tunnel drops. Enforced by workspace policy."
                         : "Traffic can leak during reconnects. Your admin has been notified.")
                        .ui(13, relativeTo: .footnote).lineSpacing(3).foregroundStyle(Tok.dim(0.55))
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, 16).padding(.vertical, 14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .glassCard(26)

                VStack(spacing: 0) {
                    ForEach(Array(Catalog.alerts.enumerated()), id: \.element.id) { i, al in
                        HStack(spacing: 12) {
                            GlowDot(color: Tok.tone(al.tone), glow: 10).frame(width: 8)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(al.title).ui(14, .medium).foregroundStyle(Tok.ink)
                                Text(al.meta).mono(10, .regular).foregroundStyle(Tok.dim(0.45)).lineLimit(1)
                            }
                            Spacer(minLength: 8)
                            Text(al.age).mono(10, .regular).foregroundStyle(Tok.dim(0.45))
                        }
                        .padding(.vertical, 10)
                        .overlay(alignment: .top) { if i > 0 { Hairline() } }
                        .accessibilityElement(children: .combine)
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 2)
                .glassCard(26, .tile)
            }
        }
        .onAppear { store.unreadAlerts = false }
        .toolbar(.hidden, for: .navigationBar)
    }
}
