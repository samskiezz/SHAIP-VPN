import ActivityKit
import Foundation

/// Starts, updates and ends the tunnel Live Activity. Updates are throttled to
/// one per 15 s unless the state changed (connect, reconnect, disconnect).
@MainActor
final class LiveActivityController {
    private var activity: Activity<TunnelActivityAttributes>?
    private var lastState: TunnelActivityAttributes.ContentState?
    private var lastUpdate = Date.distantPast

    func sync(_ state: TunnelActivityAttributes.ContentState, force: Bool) {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        if activity == nil { activity = Activity<TunnelActivityAttributes>.activities.first }
        let content = ActivityContent(state: state, staleDate: nil)

        guard let activity else {
            // Start with a session; with the VPN off there is nothing to show.
            guard state.connected || state.reconnecting else { return }
            self.activity = try? Activity.request(attributes: TunnelActivityAttributes(),
                                                  content: content, pushType: nil)
            lastState = state
            lastUpdate = Date()
            return
        }
        guard state != lastState else { return }
        let changed = state.connected != lastState?.connected || state.reconnecting != lastState?.reconnecting
        guard force || changed || Date().timeIntervalSince(lastUpdate) >= 15 else { return }
        lastState = state
        lastUpdate = Date()
        if !state.connected && !state.reconnecting {
            // The VPN is off: end the activity rather than leave stale data up.
            Task { await activity.end(content, dismissalPolicy: .immediate) }
            self.activity = nil
            return
        }
        Task { await activity.update(content) }
    }
}
