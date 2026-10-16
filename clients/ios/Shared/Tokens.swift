import SwiftUI
import SHAIPCore

// Design tokens from design/HANDOFF.md ("Design tokens"). Dark only: the app is dark-first.
// Shared by the app and the Live Activity widget.

extension Color {
    /// `#RRGGBB` as a 24-bit literal.
    init(hex: UInt32, opacity: Double = 1) {
        self.init(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255, opacity: opacity)
    }

    init(_ c: RGB, opacity: Double = 1) {
        self.init(.sRGB, red: Double(c.r) / 255, green: Double(c.g) / 255, blue: Double(c.b) / 255, opacity: opacity)
    }
}

enum Tok {
    // Screen background: radial gradient, 120% × 70% ellipse centred at the top.
    static let bgTop = Color(hex: 0x0B1020)
    static let bgMid = Color(hex: 0x04050A)
    static let bgBottom = Color(hex: 0x020306)

    static let ink = Color(hex: 0xF5F7FC)
    /// `rgba(220,228,255,a)` — the design's secondary/tertiary inks are this colour at 0.38…0.75.
    static func dim(_ a: Double) -> Color { Color(.sRGB, red: 220 / 255, green: 228 / 255, blue: 1, opacity: a) }
    static let ink2 = dim(0.5)    // ink.secondary
    static let ink3 = dim(0.42)   // ink.tertiary: mono eyebrows and labels

    static let signal = Color(hex: 0x5CF2FF)
    static let steel = Color(hex: 0x8A9BB8)
    static let ok = Color(hex: 0x62F5A8)
    static let warn = Color(hex: 0xFFB547)
    static let threat = Color(hex: 0xFF5C7A)
    /// Tag chips and the upload readout.
    static let steelInk = Color(hex: 0xB4C2DA)
    static let hairline = Color.white.opacity(0.08)
    /// The dark ring around presence and badge dots.
    static let dotRing = Color(hex: 0x0A0D18)

    static func tone(_ t: Tone) -> Color {
        switch t {
        case .signal: signal
        case .steel: steel
        case .ok: ok
        case .warn: warn
        case .threat: threat
        case .secondary: ink2
        }
    }
}

extension View {
    /// A design-size system font that scales with Dynamic Type (non-mono text, per the handoff).
    func ui(_ size: CGFloat, _ weight: Font.Weight = .regular, relativeTo style: Font.TextStyle = .body) -> some View {
        modifier(ScaledSystemFont(size: size, weight: weight, design: .default, style: style))
    }

    /// SF Mono for eyebrows, data and IDs. Fixed size (allowed by the handoff; all sizes are ≥ 9 pt).
    func mono(_ size: CGFloat, _ weight: Font.Weight = .medium) -> some View {
        font(.system(size: size, weight: weight, design: .monospaced))
    }

    /// Letter-spacing as a fraction of the font size, as the design specifies it (e.g. 0.14em).
    func em(_ fraction: CGFloat, of size: CGFloat) -> some View { tracking(fraction * size) }
}

private struct ScaledSystemFont: ViewModifier {
    @ScaledMetric private var points: CGFloat
    let weight: Font.Weight
    let design: Font.Design

    init(size: CGFloat, weight: Font.Weight, design: Font.Design, style: Font.TextStyle) {
        _points = ScaledMetric(wrappedValue: size, relativeTo: style)
        self.weight = weight
        self.design = design
    }

    // Tabular digits everywhere ("every number uses .monospacedDigit()"); letters are unaffected.
    func body(content: Content) -> some View {
        content.font(.system(size: points, weight: weight, design: design).monospacedDigit())
    }
}
