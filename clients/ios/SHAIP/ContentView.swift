import SwiftUI

/// App shell. The eight screens are paged in the design's order and share one
/// state object, so — exactly like the reference — every screen updates
/// together (toggle the orb, pick a node, switch protocol, arm the kill switch).
/// The custom floating tab bar jumps between Connect / Network / Traffic /
/// Settings; swiping reaches Onboarding, Nodes, Account and Security.
///
/// Navigation wiring is the only part not fixed by the design (it specifies the
/// screens and the 4-item bar, not the graph); each screen itself is an exact
/// port. The system draws the real status bar, Dynamic Island and home
/// indicator (per the handoff), and the UI follows system light/dark using the
/// design's two token sets.
struct ContentView: View {
    @StateObject private var state = AppState()
    @State private var page = 1   // start on Connect
    @Environment(\.colorScheme) private var scheme

    var body: some View {
        TabView(selection: $page) {
            OnboardingView(page: $page).tag(0)
            ConnectView(page: $page).tag(1)
            NetworkView(page: $page).tag(2)
            NodesView(page: $page).tag(3)
            TrafficView(page: $page).tag(4)
            ProtocolView(page: $page).tag(5)
            AccountView(page: $page).tag(6)
            SecurityView(page: $page).tag(7)
        }
        .tabViewStyle(.page(indexDisplayMode: .never))
        .ignoresSafeArea()
        .environmentObject(state)
        .onAppear {
            state.theme = scheme == .dark ? .dark : .light
            state.startClock()
        }
        .onChange(of: scheme) { _, newValue in
            state.theme = newValue == .dark ? .dark : .light
        }
    }
}

#Preview {
    ContentView()
}
