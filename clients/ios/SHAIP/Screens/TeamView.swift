import SwiftUI
import SHAIPCore

/// 09 Team & plan: profile, plan with the seat meter, who is on the mesh, and this user's devices.
struct TeamView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let plan = Catalog.plan
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.signal, size: 460, x: -35, y: -260, opacity: 0.14)]) {
            VStack(spacing: 10) {
                HStack(spacing: 14) {
                    Text("MC").ui(21, .semibold).foregroundStyle(Tok.ink)
                        .frame(width: 60, height: 60)
                        .background(Circle().fill(LinearGradient(colors: [.white.opacity(0.14), .white.opacity(0.04)], startPoint: .top, endPoint: .bottom)
                            .shadow(.inner(color: .white.opacity(0.4), radius: 0, x: 0, y: 0.5))))
                        .overlay(Circle().strokeBorder(Color.white.opacity(0.22), lineWidth: 0.5))
                        .overlay(Circle().inset(by: -4).strokeBorder(Tok.signal.opacity(0.1), lineWidth: 4))
                        .shadow(color: .black.opacity(0.8), radius: 12, x: 0, y: 12)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Maya Chen").ui(22, .bold, relativeTo: .title2).em(-0.025, of: 22).foregroundStyle(Tok.ink)
                        Eyebrow("SECURITY ADMIN · ACME CORP", tracking: 0.12, color: Tok.ink2)
                    }
                    Spacer()
                }
                .padding(.horizontal, 8).padding(.bottom, 6)
                .accessibilityElement(children: .combine)

                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text(plan.name).ui(17, .semibold).em(-0.01, of: 17).foregroundStyle(Tok.ink)
                        Spacer()
                        Chip(text: "ACTIVE", size: 9, ink: Tok.ok, fill: Tok.ok.opacity(0.12), stroke: .clear, radius: 7, tracking: 0.14, hPad: 7, vPad: 4)
                    }
                    SeatMeter(used: plan.seatsUsed, total: plan.seatsTotal)
                    HStack {
                        stat("SEATS", "\(plan.seatsUsed)/\(plan.seatsTotal)")
                        Spacer()
                        stat("DEVICES", "\(plan.devices)")
                        Spacer()
                        stat("RENEWS", plan.renews)
                    }
                }
                .padding(.horizontal, 18).padding(.vertical, 16)
                .glassCard(28)

                HStack {
                    Eyebrow("TEAM · ON MESH", tracking: 0.16)
                    Spacer()
                    Eyebrow("\(Catalog.teamOnline) ONLINE", tracking: 0.16, color: Tok.ok)
                }
                .padding(.horizontal, 8).padding(.top, 6)

                VStack(spacing: 0) {
                    ForEach(Array(Catalog.team(connected: store.connected, node: store.node).enumerated()), id: \.element.id) { i, m in
                        HStack(spacing: 12) {
                            Text(m.initials).ui(12, .semibold).foregroundStyle(Tok.ink)
                                .frame(width: 36, height: 36)
                                .background(Circle().fill(Color.white.opacity(0.08)))
                                .overlay(Circle().strokeBorder(Color.white.opacity(0.14), lineWidth: 0.5))
                                .overlay(alignment: .bottomTrailing) {
                                    Circle().fill(Tok.tone(m.presence)).frame(width: 10, height: 10)
                                        .overlay(Circle().stroke(Tok.dotRing, lineWidth: 2))
                                        .offset(x: 1, y: 1)
                                }
                            VStack(alignment: .leading, spacing: 2) {
                                Text(m.name).ui(15, .medium).foregroundStyle(Tok.ink)
                                Text(m.role).ui(12).foregroundStyle(Tok.dim(0.48))
                            }
                            Spacer()
                            Text(m.location).mono(10, .medium).em(0.06, of: 10).foregroundStyle(Tok.dim(0.6))
                        }
                        .padding(.vertical, 10)
                        .overlay(alignment: .top) { if i > 0 { Hairline() } }
                        .accessibilityElement(children: .combine)
                    }
                }
                .padding(.horizontal, 16)
                .glassCard(24, .tile)

                VStack(spacing: 0) {
                    ForEach(Array(Catalog.devices(connected: store.connected).enumerated()), id: \.element.id) { i, d in
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(d.name).ui(15, .medium).foregroundStyle(Tok.ink)
                                Text(d.meta).mono(10, .regular).foregroundStyle(Tok.dim(0.45))
                            }
                            Spacer()
                            Text(d.state).mono(9, .semibold).em(0.12, of: 9).foregroundStyle(Tok.tone(d.tone))
                        }
                        .padding(.vertical, 11)
                        .overlay(alignment: .top) { if i > 0 { Hairline() } }
                        .accessibilityElement(children: .combine)
                    }
                }
                .padding(.horizontal, 16)
                .glassCard(24, .tile)
            }
        }
        .animation(.easeInOut(duration: 0.55), value: store.connected)
        .pushedScreenChrome()
    }

    private func stat(_ k: String, _ v: String) -> some View {
        HStack(spacing: 4) {
            Text(k).foregroundStyle(Tok.ink2)
            Text(v).foregroundStyle(Tok.ink)
        }
        .mono(10, .medium).em(0.1, of: 10)
        .accessibilityElement(children: .combine)
    }
}

/// 148 used (signal → steel with glow) and 52 free (hatched), as one 14 pt segmented bar.
private struct SeatMeter: View {
    let used: Int
    let total: Int

    var body: some View {
        GeometryReader { g in
            let w = g.size.width - 2, usedW = w * CGFloat(used) / CGFloat(total)
            HStack(spacing: 2) {
                UnevenRoundedRectangle(topLeadingRadius: 3, bottomLeadingRadius: 3, style: .continuous)
                    .fill(LinearGradient(colors: [Tok.signal, Tok.steel], startPoint: .leading, endPoint: .trailing))
                    .frame(width: usedW)
                    .shadow(color: Tok.signal.opacity(0.4), radius: 5)
                Canvas { ctx, size in
                    var x = 0.0
                    while x < size.width {
                        ctx.fill(Path(CGRect(x: x, y: 0, width: 2, height: size.height)), with: .color(.white.opacity(0.12)))
                        x += 5
                    }
                }
                .clipShape(UnevenRoundedRectangle(bottomTrailingRadius: 3, topTrailingRadius: 3, style: .continuous))
            }
        }
        .frame(height: 14)
        .accessibilityElement()
        .accessibilityLabel("Seats")
        .accessibilityValue("\(used) of \(total) used")
    }
}
