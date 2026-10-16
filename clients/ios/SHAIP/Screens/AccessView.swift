import SwiftUI
import LocalAuthentication
import SHAIPCore

/// 06 Access (zero trust): device posture, resource filter and per-resource access. Tapping an
/// MFA resource performs step-up authentication (Face ID / passcode) through LAContext.
struct AccessView: View {
    @Environment(TunnelStore.self) private var store
    @State private var stepUpFailed: String?

    var body: some View {
        @Bindable var store = store
        let rows = store.resources.filter(store.accessFilter.includes)
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.ok, size: 420, x: -60, y: -200, opacity: 0.1)]) {
            VStack(spacing: 12) {
                LargeTitle(title: "Access") { Eyebrow("POLICY · ACME-STRICT", color: Tok.dim(0.45)) }
                PostureCard(enforced: store.postureEnforced)
                GlassSegmented(options: AccessFilter.allCases.map { f in
                    (value: f, label: "\(["All", "Granted", "Pending"][f.rawValue]) · \(Catalog.accessTotals[f] ?? 0)")
                }, selection: $store.accessFilter)
                VStack(spacing: 0) {
                    ForEach(Array(rows.enumerated()), id: \.element.id) { i, r in
                        ResourceRow(resource: r) { stepUp(r) }
                            .overlay(alignment: .top) { if i > 0 { Hairline() } }
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 30, style: .continuous))
                .glassCard(30, .list)
                .animation(.smooth(duration: 0.3), value: store.accessFilter)
                if let stepUpFailed {
                    Text(stepUpFailed).ui(12).foregroundStyle(Tok.warn).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 8)
                }
            }
        }
        .toolbar(.hidden, for: .navigationBar)
    }

    private func stepUp(_ r: AccessResource) {
        guard r.state == .mfa else { return }
        Task {
            let ctx = LAContext()
            do {
                let ok = try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Verify to access \(r.host)")
                if ok, let i = store.resources.firstIndex(where: { $0.id == r.id }) {
                    withAnimation(.smooth) { store.resources[i].state = .granted }
                    stepUpFailed = nil
                }
            } catch {
                stepUpFailed = "Step-up for \(r.host) was not completed."
            }
        }
    }
}

/// Posture: an 84 pt trust ring (score arc in `ok` with glow, dotted outer ring), the compliance
/// line and check chips. "Patch age" turns warn when posture enforcement is off.
private struct PostureCard: View {
    let enforced: Bool

    var body: some View {
        HStack(spacing: 16) {
            TrustRing(score: Catalog.trustScore)
            VStack(alignment: .leading, spacing: 9) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Device posture: compliant").ui(16, .semibold).em(-0.01, of: 16).foregroundStyle(Tok.ink)
                    Text("LAST CHECK 00:42 AGO · CROWDSTRIKE").mono(10, .regular).foregroundStyle(Tok.dim(0.45)).lineLimit(1).minimumScaleFactor(0.8)
                }
                FlowLayout(spacing: 5) {
                    ForEach(Catalog.posture(enforced: enforced)) { p in
                        Chip(text: p.label, dot: p.ok ? Tok.ok : Tok.warn, ink: Tok.ink, fill: Color.white.opacity(0.05),
                             stroke: .white.opacity(0.1), radius: 8, hPad: 7, vPad: 4)
                    }
                }
            }
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(30)
        .accessibilityElement(children: .combine)
    }
}

private struct TrustRing: View {
    let score: Int

    var body: some View {
        ZStack {
            Circle().stroke(Color.white.opacity(0.18), style: StrokeStyle(lineWidth: 3, dash: [0.6, 3.38])).frame(width: 76, height: 76)
            Circle().stroke(Color.white.opacity(0.08), lineWidth: 5).frame(width: 62, height: 62)
            Circle().trim(from: 0, to: Double(score) / 100)
                .stroke(Tok.ok, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .frame(width: 62, height: 62)
                .shadow(color: Tok.ok.opacity(0.6), radius: 3)
            VStack(spacing: 0) {
                Text("\(score)").ui(24, .bold, relativeTo: .title2).em(-0.03, of: 24).foregroundStyle(Tok.ink).monospacedDigit()
                Text("TRUST").mono(8, .medium).em(0.14, of: 8).foregroundStyle(Tok.ink2)
            }
        }
        .frame(width: 84, height: 84)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Trust score \(score) of 100")
    }
}

private struct ResourceRow: View {
    let resource: AccessResource
    let onStepUp: () -> Void

    var body: some View {
        if resource.state == .mfa {
            Button(action: onStepUp) { content }
                .buttonStyle(.plain)
                .accessibilityElement(children: .combine)
                .accessibilityHint("Verify with Face ID to get access")
        } else {
            content.accessibilityElement(children: .combine)
        }
    }

    private var content: some View {
        let c = Tok.tone(resource.state.tone)
        return HStack(spacing: 12) {
            Text(resource.badge).mono(11, .semibold).foregroundStyle(Tok.ink)
                .frame(width: 40, height: 40)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(Color.white.opacity(0.06).shadow(.inner(color: .white.opacity(0.25), radius: 0, x: 0, y: 0.5))))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.white.opacity(0.12), lineWidth: 0.5))
            VStack(alignment: .leading, spacing: 3) {
                Text(resource.host).mono(14, .medium).em(-0.01, of: 14).foregroundStyle(Tok.ink).lineLimit(1)
                Text(resource.meta).ui(12).foregroundStyle(Tok.ink2).lineLimit(1)
            }
            Spacer(minLength: 8)
            Text(resource.state.rawValue).mono(9, .semibold).em(0.12, of: 9).foregroundStyle(c)
                .padding(.horizontal, 8).padding(.vertical, 5)
                .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(c.opacity(0.12)))
        }
        .padding(.horizontal, 14).padding(.vertical, 12)
        .contentShape(Rectangle())
    }
}
