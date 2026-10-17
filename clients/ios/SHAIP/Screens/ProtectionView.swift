import SwiftUI
import SHAIPCore

/// Protection: what is protecting this iPhone right now — derived only from
/// real state (`SHAIPCore.Protection`) — and, always next to it, what this VPN
/// does not do. Nothing here is a promise the code doesn't keep.
struct ProtectionView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let items = Protection.items(connected: store.connected, snapshot: store.snapshot,
                                     killSwitch: store.killSwitch, onDemand: store.onDemand)
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.ok, size: 420, x: -60, y: -200, opacity: 0.08)]) {
            VStack(spacing: 10) {
                LargeTitle(title: "Protection") {
                    Text(store.stateLabel).mono(10, .medium).em(0.14, of: 10)
                        .foregroundStyle(store.connected ? Tok.ok : Tok.ink2)
                }
                section("RIGHT NOW", items)
                section("WHAT THIS VPN DOESN'T DO", Protection.limits, limits: true)
                Text("SHAIP runs SHAIP VPN, pre-release software. Its code is open; it has not yet had an independent security audit.")
                    .ui(12, relativeTo: .footnote).foregroundStyle(Tok.dim(0.45))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 8).padding(.top, 4)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .toolbar(.hidden, for: .navigationBar)
    }

    private func section(_ title: String, _ rows: [ProtectionItem], limits: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Eyebrow(title, tracking: 0.16, color: Tok.ink3).padding(.horizontal, 8).padding(.top, 6)
            VStack(spacing: 0) {
                ForEach(Array(rows.enumerated()), id: \.element.id) { i, item in
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        icon(item, limits: limits).frame(width: 18)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(item.title).ui(15, .semibold).foregroundStyle(Tok.ink)
                            Text(item.detail).ui(12, relativeTo: .footnote).lineSpacing(2).foregroundStyle(Tok.dim(0.55))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(.vertical, 11)
                    .overlay(alignment: .top) { if i > 0 { Hairline() } }
                    .accessibilityElement(children: .combine)
                    .accessibilityValue(limits ? "" : item.status == .on ? "On" : "Off")
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 2)
            .glassCard(26, .tile)
        }
    }

    @ViewBuilder
    private func icon(_ item: ProtectionItem, limits: Bool) -> some View {
        if limits {
            Image(systemName: "info.circle").font(.system(size: 13, weight: .semibold)).foregroundStyle(Tok.steel)
        } else if item.status == .on {
            Image(systemName: "checkmark.circle.fill").font(.system(size: 13, weight: .semibold)).foregroundStyle(Tok.ok)
        } else {
            Image(systemName: "minus.circle").font(.system(size: 13, weight: .semibold)).foregroundStyle(Tok.ink2)
        }
    }
}
