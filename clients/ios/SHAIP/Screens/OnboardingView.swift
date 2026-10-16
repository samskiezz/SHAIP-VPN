import SwiftUI
import SHAIPCore

/// 01 Onboarding: full-bleed mesh, gradient hero, SSO and passkey sign-in.
///
/// Sign-in is wired as a seam: production runs OIDC/SAML through `ASWebAuthenticationSession`
/// against the workspace IdP, and passkeys through `ASAuthorizationPlatformPublicKeyCredentialProvider`;
/// enrolment then goes through the control plane's `/api/enroll` (docs/enrollment.md). This build has
/// no IdP configured, so both buttons complete sign-in directly.
struct OnboardingView: View {
    let onSignIn: () -> Void
    @Environment(TunnelStore.self) private var store

    var body: some View {
        ZStack(alignment: .bottom) {
            ScreenBackground()
            GeometryReader { geo in
                SceneView(.net, layout: SceneLayout(cy: 0.5, r: 0.4), options: store.meshOptions)
                    .frame(width: geo.size.width, height: 540)
                    .offset(y: 30)
                HStack {
                    Text("SHAIP/OS 4.2")
                    Spacer()
                    Text("MESH · 0x3F9A")
                }
                .mono(9, .medium).em(0.18, of: 9).foregroundStyle(Tok.ink3)
                .padding(.horizontal, 24)
                .offset(y: max(66, geo.safeAreaInsets.top + 8))
                .accessibilityHidden(true)
                LinearGradient(stops: [.init(color: Tok.bgBottom.opacity(0), location: 0), .init(color: Color(hex: 0x03040A), location: 0.8)],
                               startPoint: .top, endPoint: .bottom)
                    .frame(height: 240)
                    .offset(y: 400)
                    .allowsHitTesting(false)
                Color(hex: 0x03040A).frame(height: max(0, geo.size.height - 640)).offset(y: 640)
            }
            .ignoresSafeArea()

            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 8) {
                    GlowDot(color: Tok.signal, glow: 10)
                    Text("\(Catalog.edgeNodes) EDGE NODES ONLINE").mono(10, .medium).em(0.16, of: 10).foregroundStyle(Tok.signal)
                }
                Text("Zero-trust access for every device on your team.")
                    .ui(40, .semibold, relativeTo: .largeTitle).em(-0.045, of: 40)
                    .foregroundStyle(LinearGradient(stops: [.init(color: .white, location: 0.3), .init(color: Color(hex: 0xA9B4D6), location: 1)],
                                                    startPoint: .top, endPoint: .bottom))
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                Text("Encrypted tunnels, identity-aware routing and posture checks, managed from one workspace.")
                    .ui(15).lineSpacing(4).foregroundStyle(Tok.dim(0.56))
                    .fixedSize(horizontal: false, vertical: true)
                VStack(spacing: 10) {
                    Button(action: onSignIn) {
                        Label("Continue with SSO", systemImage: "key")
                            .ui(17, .semibold).em(-0.01, of: 17)
                            .foregroundStyle(Color(hex: 0x05060A))
                            .frame(maxWidth: .infinity, minHeight: 56)
                            .background {
                                Capsule(style: .continuous)
                                    .fill(LinearGradient(colors: [.white, Color(hex: 0xDCE3F2)], startPoint: .top, endPoint: .bottom)
                                        .shadow(.inner(color: .black.opacity(0.15), radius: 0, x: 0, y: -1)))
                                    .shadow(color: Tok.signal.opacity(0.45), radius: 17, x: 0, y: 14)
                            }
                    }
                    .buttonStyle(PressScaleStyle())
                    Button(action: onSignIn) {
                        Label("Sign in with passkey", systemImage: "person.badge.key")
                            .ui(17, .medium)
                            .foregroundStyle(Tok.ink)
                            .frame(maxWidth: .infinity, minHeight: 56)
                            .contentShape(Capsule())
                    }
                    .buttonStyle(PressScaleStyle())
                    .liquidGlass(in: Capsule(style: .continuous))
                }
                .padding(.top, 4)
                HStack(spacing: 14) {
                    Text("SOC 2 TYPE II"); Text("ISO 27001"); Text("FIPS 140-3")
                }
                .mono(9, .medium).em(0.16, of: 9).foregroundStyle(Tok.dim(0.38))
                .frame(maxWidth: .infinity)
                .accessibilityElement(children: .combine)
                .accessibilityLabel("SOC 2 Type II, ISO 27001, FIPS 140-3")
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 8)
        }
        .preferredColorScheme(.dark)
    }
}

/// Subtle press feedback for full-width buttons.
struct PressScaleStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.97 : 1)
            .opacity(configuration.isPressed ? 0.9 : 1)
            .animation(.smooth(duration: 0.2), value: configuration.isPressed)
    }
}
