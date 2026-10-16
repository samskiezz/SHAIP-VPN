import SwiftUI

@main
struct SHAIPApp: App {
    @State private var store = TunnelStore.shared
    @State private var router = Router()

    init() {
        // Live Activity intents (lock screen / Dynamic Island) run in this process.
        TunnelIntentBridge.handler = { action in
            TunnelStore.shared.connected = action == .connect
        }
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
                .environment(router)
                .preferredColorScheme(.dark)
                // Dynamic Type scales all non-mono text; capped where the fixed-geometry rows still fit.
                .dynamicTypeSize(...DynamicTypeSize.accessibility2)
                .onAppear { store.start() }
        }
    }
}

enum AppTab: Hashable {
    case connect, network, access, security, settings
}

@MainActor
@Observable
final class Router {
    var tab: AppTab = .connect
}

/// Five tabs in the native (floating, Liquid Glass) tab bar. Traffic is pushed from the Connect
/// status card, Nodes from the Network node chip, Team & plan from the Settings avatar.
struct RootView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(Router.self) private var router
    @AppStorage("shaip.signedIn") private var signedIn = false

    var body: some View {
        @Bindable var router = router
        TabView(selection: $router.tab) {
            Tab("Connect", systemImage: "checkmark.shield", value: AppTab.connect) {
                NavigationStack { ConnectView() }
            }
            Tab("Network", systemImage: "globe", value: AppTab.network) {
                NavigationStack { NetworkView() }
            }
            Tab("Access", systemImage: "qrcode", value: AppTab.access) {
                NavigationStack { AccessView() }
            }
            Tab("Security", systemImage: "scope", value: AppTab.security) {
                NavigationStack { SecurityView() }
            }
            Tab("Settings", systemImage: "slider.horizontal.3", value: AppTab.settings) {
                NavigationStack { ProtocolView() }
            }
        }
        .tint(Tok.signal)
        .sensoryFeedback(.selection, trigger: router.tab)
        .fullScreenCover(isPresented: Binding(get: { !signedIn }, set: { signedIn = !$0 })) {
            OnboardingView { signedIn = true }
                .environment(store)
        }
    }
}
