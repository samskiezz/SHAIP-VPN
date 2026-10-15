import SwiftUI

// MARK: - Colour blob (soft field behind the glass, blur 100, opacity `blob`)

struct Blob: View {
    let color: Color
    let size: CGFloat
    let opacity: Double
    var blur: CGFloat = 100
    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .blur(radius: blur)
            .opacity(opacity)
    }
}

// MARK: - Device scaler
//
// The design is authored at 390×844 (iPhone 16/17 base). This renders that fixed
// canvas and scales it to the device width, anchored top-left — the handoff's
// "recreate at 390×844, scaling with safe areas". The system draws the real
// status bar / Dynamic Island / home indicator (per the handoff, we don't).

struct Screen<Content: View>: View {
    let t: Tokens
    @ViewBuilder var content: Content
    var body: some View {
        GeometryReader { geo in
            let scale = geo.size.width / 390
            ZStack(alignment: .topLeading) { content }
                .frame(width: 390, height: 844, alignment: .topLeading)
                .scaleEffect(scale, anchor: .topLeading)
                .frame(width: geo.size.width, height: 844 * scale, alignment: .topLeading)
                .clipped()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(t.bg.ignoresSafeArea())
    }
}

// MARK: - Floating tab bar (inset 20, 28 from bottom, height 66, radius 33)

struct FloatingTabBar: View {
    let t: Tokens
    let active: Int
    var onSelect: (Int) -> Void = { _ in }

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(TABS.enumerated()), id: \.offset) { i, tab in
                let isOn = i == active
                VStack(spacing: 3) {
                    Image(systemName: tab.symbol)
                        .font(.system(size: 22, weight: .regular))
                    Text(tab.label).font(.ui(10, .medium))
                }
                .foregroundStyle(isOn ? t.c1 : t.sub)
                .padding(.vertical, 7)
                .padding(.horizontal, 14)
                .background(
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .fill(isOn
                              ? (t.dark ? Color.white.opacity(0.12) : Color(hex: "#0B0D14", opacity: 0.07))
                              : Color.clear)
                )
                .frame(maxWidth: .infinity)
                .contentShape(Rectangle())
                .onTapGesture { onSelect(i) }
            }
        }
        .padding(.horizontal, 6)
        .frame(width: 350, height: 66)
        .glass(t, radius: 33, high: true, shadow: true)
        .place(top: 750, left: 20)   // bottom 28 → 844-28-66
    }
}

// MARK: - Small reusable bits

/// Mono "eyebrow" label (letter-spaced uppercase data label).
struct Eyebrow: View {
    let text: String
    let size: CGFloat
    let color: Color
    var tracking: CGFloat = 0.12 * 12
    var body: some View {
        Text(text).font(.mono(size, .medium)).tracking(tracking).foregroundStyle(color)
    }
}
