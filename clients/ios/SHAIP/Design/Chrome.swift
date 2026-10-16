import SwiftUI

/// An ambient light blob behind the glass (blur ~110 pt, opacity 0.10–0.16), placed relative to the
/// screen's top-leading corner in design points; trailing-anchored blobs use a negative `x` offset
/// from the trailing edge.
struct AmbientBlob {
    enum Edge { case leading, trailing }
    var color: Color
    var size: CGFloat
    var x: CGFloat
    var y: CGFloat
    var edge: Edge = .leading
    var opacity: Double
}

/// Screen background: radial gradient (120% × 70% ellipse, centred top) #0B1020 → #04050A (55%) →
/// #020306, plus the screen's ambient blobs.
struct ScreenBackground: View {
    var blobs: [AmbientBlob] = []

    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width, h = geo.size.height
            ZStack(alignment: .topLeading) {
                Tok.bgBottom
                // A circle of radius 0.7h stretched horizontally to 1.2w gives the CSS ellipse.
                RadialGradient(stops: [.init(color: Tok.bgTop, location: 0), .init(color: Tok.bgMid, location: 0.55),
                                       .init(color: Tok.bgBottom, location: 1)],
                               center: .top, startRadius: 0, endRadius: h * 0.7)
                    .scaleEffect(x: max(1, (1.2 * w) / (0.7 * h)), y: 1, anchor: .top)
                ForEach(blobs.indices, id: \.self) { i in
                    let b = blobs[i]
                    Circle().fill(b.color)
                        .frame(width: b.size, height: b.size)
                        .blur(radius: 110)
                        .opacity(b.opacity)
                        .offset(x: b.edge == .leading ? b.x : w - b.size - b.x, y: b.y)
                }
            }
            .frame(width: w, height: h, alignment: .topLeading)
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// The 130 pt scrim behind the floating tab bar: clear → rgba(2,3,6,.92).
struct BottomScrim: View {
    var body: some View {
        LinearGradient(colors: [Tok.bgBottom.opacity(0), Tok.bgBottom.opacity(0.92)], startPoint: .top, endPoint: .bottom)
            .frame(height: 130)
            .frame(maxHeight: .infinity, alignment: .bottom)
            .ignoresSafeArea()
            .allowsHitTesting(false)
            .accessibilityHidden(true)
    }
}

/// A tab screen: scrolling content inset 16 pt (titles add 8 more, i.e. 24), the background and
/// blobs behind, and the bottom scrim in front. Scrolling keeps every row reachable above the tab
/// bar on any device — the handoff's fixed 390×844 layouts hid the last Security alert under it.
struct ScreenScaffold<Content: View>: View {
    var blobs: [AmbientBlob] = []
    var topPadding: CGFloat = 4
    @ViewBuilder var content: Content

    var body: some View {
        ScrollView {
            content
                .padding(.horizontal, 16)
                .padding(.top, topPadding)
                .padding(.bottom, 28)
        }
        .scrollIndicators(.hidden)
        .background { ScreenBackground(blobs: blobs) }
        .overlay { BottomScrim() }
    }
}

extension View {
    /// Pushed screens keep the system back button (and swipe-back) over a transparent bar.
    func pushedScreenChrome() -> some View {
        navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.hidden, for: .navigationBar)
    }
}
