import SwiftUI

/// Hides the app's contents whenever it isn't the active app. iOS saves a
/// snapshot of the screen for the app switcher as the app leaves the
/// foreground, and shows it to anyone who opens the switcher; without this it
/// would hold whatever was on screen (the server, its fingerprint, the tunnel
/// address). Applied to the root view and to every sheet, since a sheet is
/// drawn above the root's overlay.
struct PrivacyCover: ViewModifier {
    @Environment(\.scenePhase) private var phase

    func body(content: Content) -> some View {
        content.overlay {
            if phase != .active {
                ZStack {
                    LinearGradient(colors: [Tok.bgTop, Tok.bgMid, Tok.bgBottom], startPoint: .top, endPoint: .bottom)
                    Image(systemName: "lock.fill")
                        .font(.system(size: 34, weight: .semibold))
                        .foregroundStyle(Tok.dim(0.5))
                        .accessibilityLabel("SHAIP")
                }
                .ignoresSafeArea()
                .transition(.identity)
            }
        }
    }
}

extension View {
    /// See ``PrivacyCover``.
    func privacyCover() -> some View { modifier(PrivacyCover()) }
}
