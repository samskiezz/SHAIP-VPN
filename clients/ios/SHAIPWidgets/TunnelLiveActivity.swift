import ActivityKit
import AppIntents
import SwiftUI
import WidgetKit

/// Design screen 10: the lock-screen Live Activity and the Dynamic Island.
struct TunnelLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: TunnelActivityAttributes.self) { context in
            LockScreenTunnelView(state: context.state)
                .activityBackgroundTint(Color(hex: 0x0E1018, opacity: 0.72))
                .activitySystemActionForegroundColor(Tok.ink)
        } dynamicIsland: { context in
            let s = context.state
            return DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(s.connected ? s.city : "Not connected").font(.system(size: 15, weight: .semibold)).foregroundStyle(Tok.ink)
                        SessionClock(state: s).font(.system(size: 13, weight: .semibold, design: .monospaced))
                    }
                    .padding(.leading, 4)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(s.rttMs.map { "\($0) ms" } ?? "—").font(.system(size: 15, weight: .semibold, design: .monospaced))
                            .foregroundStyle(stateColor(s)).monospacedDigit()
                        Text(s.downMbps.map { "↓ \($0) Mbps" } ?? "OFFLINE").font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(Tok.dim(0.55))
                    }
                    .padding(.trailing, 4)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    TunnelActionButton(connected: s.connected).padding(.top, 4)
                }
            } compactLeading: {
                ShieldGlyph(connected: s.connected).font(.system(size: 14, weight: .semibold))
            } compactTrailing: {
                // The handoff rendered "—ms" while disconnected.
                Text(s.rttMs.map { "\($0)ms" } ?? "—").font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(stateColor(s)).monospacedDigit()
            } minimal: {
                ShieldGlyph(connected: s.connected).font(.system(size: 13, weight: .semibold))
            }
            .keylineTint(stateColor(s))
        }
    }
}

private func stateColor(_ s: TunnelActivityAttributes.ContentState) -> Color { s.connected ? Tok.ok : Tok.threat }

private struct ShieldGlyph: View {
    let connected: Bool
    var body: some View {
        Image(systemName: connected ? "checkmark.shield" : "shield.slash")
            .foregroundStyle(connected ? Tok.ok : Tok.threat)
            .accessibilityLabel(connected ? "Protected" : "Exposed")
    }
}

/// hh:mm:ss since the session started, ticking on its own; `--:--:--` with no session.
private struct SessionClock: View {
    let state: TunnelActivityAttributes.ContentState
    var body: some View {
        Group {
            if state.connected, let start = state.sessionStart {
                Text(timerInterval: start...Date.distantFuture, countsDown: false)
            } else {
                Text("--:--:--")
            }
        }
        .monospacedDigit()
        .foregroundStyle(stateColor(state))
    }
}

private struct TunnelActionButton: View {
    let connected: Bool
    var body: some View {
        Group {
            if connected {
                Button(intent: DisconnectTunnelIntent()) { label }
            } else {
                Button(intent: ConnectTunnelIntent()) { label }
            }
        }
        .buttonStyle(.plain)
    }

    private var label: some View {
        Text(connected ? "Tap to disconnect" : "Tap to connect")
            .font(.system(size: 14, weight: .semibold))
            .foregroundStyle(Tok.ink)
            .lineLimit(1)
            .minimumScaleFactor(0.8)
            .padding(.horizontal, 16)
            .frame(maxWidth: .infinity, minHeight: 40)
            .background(Capsule().fill(Color.white.opacity(0.12)))
            .overlay(Capsule().strokeBorder(Color.white.opacity(0.2), lineWidth: 0.5))
    }
}

/// The lock-screen card: app glyph, "Protected · Sydney", node · protocol, the session timer,
/// DOWN and RTT, and the connect/disconnect intent.
struct LockScreenTunnelView: View {
    let state: TunnelActivityAttributes.ContentState

    var body: some View {
        VStack(spacing: 14) {
            HStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(LinearGradient(colors: [Tok.signal, Color(hex: 0x3C7D9A)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 34, height: 34)
                    .overlay(Image(systemName: "shield").font(.system(size: 17, weight: .bold)).foregroundStyle(Color(hex: 0x03060C)))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text("\(state.connected ? "Protected" : "Exposed") · \(state.connected ? state.city : "Not connected")")
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(Tok.ink).lineLimit(1)
                    Text("\(state.node) · \(state.proto)").font(.system(size: 10, design: .monospaced)).foregroundStyle(Tok.dim(0.55))
                }
                Spacer(minLength: 8)
                SessionClock(state: state).font(.system(size: 15, weight: .semibold, design: .monospaced))
            }
            HStack(alignment: .center, spacing: 8) {
                metric("DOWN", state.downMbps.map(String.init) ?? "—", "Mbps")
                metric("RTT", state.rttMs.map(String.init) ?? "—", "ms")
                TunnelActionButton(connected: state.connected).fixedSize()
            }
        }
        .padding(.horizontal, 18).padding(.vertical, 16)
    }

    private func metric(_ k: String, _ v: String, _ unit: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(k).font(.system(size: 9, weight: .medium, design: .monospaced)).tracking(1.26).foregroundStyle(Tok.dim(0.45))
            HStack(alignment: .firstTextBaseline, spacing: 3) {
                Text(v).font(.system(size: 20, weight: .semibold)).monospacedDigit().foregroundStyle(Tok.ink)
                Text(unit).font(.system(size: 10, design: .monospaced)).foregroundStyle(Tok.dim(0.45))
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

#Preview("Lock screen", as: .content, using: TunnelActivityAttributes(workspace: "Acme")) {
    TunnelLiveActivity()
} contentStates: {
    TunnelActivityAttributes.ContentState(connected: true, city: "Sydney", node: "SYD-03", proto: "SHAIP MESH",
                                          sessionStart: Date().addingTimeInterval(-5025), downMbps: 141, rttMs: 14)
    TunnelActivityAttributes.ContentState(connected: false, city: "Sydney", node: "SYD-03", proto: "SHAIP MESH",
                                          sessionStart: nil, downMbps: nil, rttMs: nil)
}

#Preview("Island", as: .dynamicIsland(.expanded), using: TunnelActivityAttributes(workspace: "Acme")) {
    TunnelLiveActivity()
} contentStates: {
    TunnelActivityAttributes.ContentState(connected: true, city: "Sydney", node: "SYD-03", proto: "SHAIP MESH",
                                          sessionStart: Date().addingTimeInterval(-5025), downMbps: 141, rttMs: 14)
}
