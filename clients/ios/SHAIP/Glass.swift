import SwiftUI

// MARK: - Absolute placement (CSS top/left/right → SwiftUI)

extension View {
    /// Place inside a 390-pt-wide ZStack(alignment: .topLeading), anchoring the
    /// element's top-left at (left, top) — the design uses absolute positioning.
    func place(top: CGFloat, left: CGFloat, width: CGFloat? = nil, height: CGFloat? = nil) -> some View {
        self
            .frame(width: width, height: height, alignment: .topLeading)
            .offset(x: left, y: top)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
}

// MARK: - Liquid Glass surface
//
// Recipe from the handoff: background `glass` + backdrop blur/saturate + 1pt
// `stroke` border + inset-top highlight + soft drop shadow. On iOS 26 this uses
// the real `.glassEffect`; it falls back to `.ultraThinMaterial` otherwise.

struct GlassSurface: View {
    let t: Tokens
    var radius: CGFloat = 28
    var high: Bool = false      // glassHi (tab bar) vs glass (cards)
    var shadow: Bool = false

    var body: some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        shape
            .fill(high ? t.glassHi : t.glass)
            .background {
                if #available(iOS 26.0, *) {
                    shape.fill(.clear).glassEffect(.regular, in: shape)
                } else {
                    shape.fill(.ultraThinMaterial)
                }
            }
            .overlay(shape.strokeBorder(t.stroke, lineWidth: 1))
            // inset top highlight
            .overlay(alignment: .top) {
                shape.strokeBorder(
                    LinearGradient(
                        colors: [t.dark ? Color.white.opacity(0.12) : Color.white.opacity(0.9), .clear],
                        startPoint: .top, endPoint: .center),
                    lineWidth: 1)
            }
            .compositingGroup()
            .shadow(color: shadow ? t.shadowColor : .clear,
                    radius: shadow ? 20 : 0, x: 0, y: shadow ? 14 : 0)
    }
}

extension View {
    /// Apply a glass surface as this view's background.
    func glass(_ t: Tokens, radius: CGFloat = 28, high: Bool = false, shadow: Bool = false) -> some View {
        background(GlassSurface(t: t, radius: radius, high: high, shadow: shadow))
    }
}

// MARK: - iOS switch (51×31, on = `good`)

struct IOSSwitch: View {
    let on: Bool
    let onColor: Color
    let track: Color
    var body: some View {
        ZStack(alignment: on ? .trailing : .leading) {
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(on ? onColor : track)
            Circle()
                .fill(.white)
                .frame(width: 27, height: 27)
                .shadow(color: .black.opacity(0.25), radius: 3, y: 2)
                .padding(2)
        }
        .frame(width: 51, height: 31)
        .animation(.spring(response: 0.3, dampingFraction: 0.7), value: on)
    }
}
