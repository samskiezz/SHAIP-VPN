import SwiftUI
import Combine
import UIKit

/// The exact interaction state from the design, plus the tweakable props
/// (theme / accent / density) and the 1 Hz clock driving live stats.
@MainActor
final class AppState: ObservableObject {
    // state = { connected, proto, kill, split, dns, posture, always, seg, t, srv }
    @Published var connected = true
    @Published var proto = "mesh"
    @Published var kill = true
    @Published var split = false
    @Published var dns = true
    @Published var posture = true
    @Published var alwaysOn = true          // design key `always`
    @Published var seg = 0
    @Published var srv = 0
    @Published var t = 0

    // Tweakable props.
    @Published var theme: AppTheme = .dark
    @Published var accent: Accent = .aurora
    @Published var density: Double = 120

    private var timer: Timer?

    func startClock() {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.t += 1 }
        }
    }
    func stopClock() { timer?.invalidate(); timer = nil }

    var tokens: Tokens { .make(theme, accent) }
    var server: Server { SERVERS[min(srv, SERVERS.count - 1)] }
    var protoName: String { PROTOS.first { $0.k == proto }?.name ?? "" }

    // Haptics on connect toggles and the kill switch (per the handoff).
    func haptic() {
        let gen = UIImpactFeedbackGenerator(style: .medium)
        gen.impactOccurred()
    }
}
