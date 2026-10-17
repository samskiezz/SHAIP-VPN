import SwiftUI

@main
struct SHAIPApp: App {
    @State private var store = TunnelStore.shared
    @State private var router = Router()

    init() {
        // Live Activity intents (lock screen / Dynamic Island) run in this process.
        TunnelIntentBridge.handler = { action in
            switch action {
            case .connect: TunnelStore.shared.connect()
            case .disconnect: TunnelStore.shared.disconnect()
            }
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
                .task { await store.load() }
                // shaip://enroll?t=… links (from the control plane's web page or a QR code).
                .onOpenURL { url in router.pendingEnrollLink = url.absoluteString }
        }
    }
}

enum AppTab: Hashable {
    case connect, traffic, protection, server, settings
}

@MainActor
@Observable
final class Router {
    var tab: AppTab = .connect
    /// An enrollment link opened from outside the app, waiting for the user.
    var pendingEnrollLink: String?
}

struct RootView: View {
    @Environment(TunnelStore.self) private var store
    @Environment(Router.self) private var router

    var body: some View {
        @Bindable var router = router
        TabView(selection: $router.tab) {
            Tab("Connect", systemImage: "power", value: AppTab.connect) {
                NavigationStack { ConnectView() }
            }
            Tab("Traffic", systemImage: "chart.xyaxis.line", value: AppTab.traffic) {
                NavigationStack { TrafficView() }
            }
            Tab("Protection", systemImage: "lock.shield", value: AppTab.protection) {
                NavigationStack { ProtectionView() }
            }
            Tab("Server", systemImage: "server.rack", value: AppTab.server) {
                NavigationStack { ServerView() }
            }
            Tab("Settings", systemImage: "slider.horizontal.3", value: AppTab.settings) {
                NavigationStack { SettingsView() }
            }
        }
        .tint(Tok.signal)
        .sensoryFeedback(.selection, trigger: router.tab)
        .privacyCover()
        // No server yet: set one up first. Nothing in the app pretends to
        // work without one.
        .fullScreenCover(isPresented: Binding(get: { store.loaded && store.config == nil }, set: { _ in })) {
            SetupView()
                .environment(store)
                .environment(router)
                .privacyCover()
        }
        .sheet(isPresented: Binding(get: { router.pendingEnrollLink != nil && store.config != nil },
                                    set: { if !$0 { router.pendingEnrollLink = nil } })) {
            EnrollSheet(link: router.pendingEnrollLink ?? "")
                .environment(store)
                .privacyCover()
        }
    }
}
