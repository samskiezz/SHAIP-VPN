import ActivityKit
import Foundation

/// Starts, updates and ends the tunnel Live Activity. Updates are throttled to one per 15 s (the
/// handoff's budget) unless something the user did changed it.
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
            // Start with the session; a disconnected app has nothing to put on the lock screen.
            guard state.connected else { return }
            self.activity = try? Activity.request(attributes: TunnelActivityAttributes(workspace: "Acme"),
                                                  content: content, pushType: nil)
            lastState = state
            lastUpdate = Date()
            return
        }
        guard state != lastState, force || Date().timeIntervalSince(lastUpdate) >= 15 else { return }
        lastState = state
        lastUpdate = Date()
        Task { await activity.update(content) }
    }
}
