import ActivityKit
import AppIntents
import SwiftUI
import WidgetKit

/// The lock-screen Live Activity and the Dynamic Island. Every value comes
/// from the running tunnel (via the app); unknown values show a dash.
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
                        Text(stateTitle(s)).font(.system(size: 15, weight: .semibold)).foregroundStyle(Tok.ink).lineLimit(1)
                        SessionClock(state: s).font(.system(size: 13, weight: .semibold, design: .monospaced))
                    }
                    .padding(.leading, 4)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text(s.rttMs.map { "\($0) ms" } ?? "—").font(.system(size: 15, weight: .semibold, design: .monospaced))
                            .foregroundStyle(stateColor(s)).monospacedDigit()
                        Text(s.downMbps.map { "↓ \(mbps($0)) Mbps" } ?? stateWord(s)).font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(Tok.dim(0.55))
                    }
                    .padding(.trailing, 4)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    TunnelActionButton(on: s.connected || s.reconnecting).padding(.top, 4)
                }
            } compactLeading: {
                StateGlyph(state: s).font(.system(size: 14, weight: .semibold))
            } compactTrailing: {
                Text(s.rttMs.map { "\($0)ms" } ?? "—").font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundStyle(stateColor(s)).monospacedDigit()
            } minimal: {
                StateGlyph(state: s).font(.system(size: 13, weight: .semibold))
            }
            .keylineTint(stateColor(s))
        }
    }
}

private func stateColor(_ s: TunnelActivityAttributes.ContentState) -> Color {
    s.connected ? Tok.ok : s.reconnecting ? Tok.warn : Tok.ink2
}

private func stateTitle(_ s: TunnelActivityAttributes.ContentState) -> String {
    s.connected ? "Protected" : s.reconnecting ? "Reconnecting" : "VPN off"
}

private func stateWord(_ s: TunnelActivityAttributes.ContentState) -> String {
    s.connected ? "CONNECTED" : s.reconnecting ? "RECONNECTING" : "OFF"
}

private func mbps(_ v: Double) -> String {
    v < 1 ? String(format: "%.2f", v) : v < 100 ? String(format: "%.1f", v) : String(format: "%.0f", v)
}

private struct StateGlyph: View {
    let state: TunnelActivityAttributes.ContentState
    var body: some View {
        Image(systemName: state.connected ? "lock.fill" : state.reconnecting ? "arrow.triangle.2.circlepath" : "lock.open")
            .foregroundStyle(stateColor(state))
            .accessibilityLabel(state.connected ? "VPN connected" : state.reconnecting ? "VPN reconnecting" : "VPN off")
    }
}

/// hh:mm:ss since the session started, ticking on its own; `--:--:--` with no session.
private struct SessionClock: View {
    let state: TunnelActivityAttributes.ContentState
    var body: some View {
        Group {
            if let start = state.sessionStart, state.connected || state.reconnecting {
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
    let on: Bool
    var body: some View {
        Group {
            if on {
                Button(intent: DisconnectTunnelIntent()) { label }
            } else {
                Button(intent: ConnectTunnelIntent()) { label }
            }
        }
        .buttonStyle(.plain)
    }

    private var label: some View {
        Text(on ? "Disconnect" : "Connect")
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

/// The lock-screen card: the state, the session timer, measured DOWN and RTT,
/// and the connect/disconnect intent. No server, address or tunnel address:
/// anyone can read a lock screen.
struct LockScreenTunnelView: View {
    let state: TunnelActivityAttributes.ContentState

    var body: some View {
        VStack(spacing: 14) {
            HStack(spacing: 10) {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(LinearGradient(colors: [Tok.signal, Color(hex: 0x3C7D9A)], startPoint: .topLeading, endPoint: .bottomTrailing))
                    .frame(width: 34, height: 34)
                    .overlay(Image(systemName: "lock").font(.system(size: 16, weight: .bold)).foregroundStyle(Color(hex: 0x03060C)))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 1) {
                    Text(stateTitle(state))
                        .font(.system(size: 15, weight: .semibold)).foregroundStyle(Tok.ink).lineLimit(1)
                    Text("SHAIP · PQANON/1").font(.system(size: 10, design: .monospaced)).foregroundStyle(Tok.dim(0.55))
                }
                Spacer(minLength: 8)
                SessionClock(state: state).font(.system(size: 15, weight: .semibold, design: .monospaced))
            }
            HStack(alignment: .center, spacing: 8) {
                metric("DOWN", state.downMbps.map(mbps) ?? "—", "Mbps")
                metric("RTT", state.rttMs.map(String.init) ?? "—", "ms")
                TunnelActionButton(on: state.connected || state.reconnecting).fixedSize()
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

#Preview("Lock screen", as: .content, using: TunnelActivityAttributes()) {
    TunnelLiveActivity()
} contentStates: {
    TunnelActivityAttributes.ContentState(connected: true, reconnecting: false,
                                          sessionStart: Date().addingTimeInterval(-5025), downMbps: 41.2, rttMs: 23)
    TunnelActivityAttributes.ContentState(connected: false, reconnecting: false, sessionStart: nil, downMbps: nil, rttMs: nil)
}
