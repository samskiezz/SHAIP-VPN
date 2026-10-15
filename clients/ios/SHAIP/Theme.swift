import SwiftUI

// MARK: - Props (the design's tweakable props: theme, accent, density)

enum AppTheme: String, CaseIterable, Identifiable { case dark = "Dark", light = "Light"; var id: String { rawValue } }
enum Accent: String, CaseIterable, Identifiable { case aurora = "Aurora", mint = "Mint", ember = "Ember"; var id: String { rawValue } }

// ACC = { Aurora:['#5EE7FF','#8B7CFF','#0E9BBF','#6450E8'], Mint:[...], Ember:[...] }
let ACC: [Accent: [String]] = [
    .aurora: ["#5EE7FF", "#8B7CFF", "#0E9BBF", "#6450E8"],
    .mint:   ["#7CFFB2", "#3EC6FF", "#0F9A62", "#1A86CC"],
    .ember:  ["#FFB35E", "#FF5E9A", "#C9690B", "#D42A66"],
]

// MARK: - Color helpers

extension Color {
    /// `#RRGGBB` (+ optional alpha). Mirrors the design's `rgba(hex, a)` helper.
    init(hex: String, opacity: Double = 1) {
        var s = hex
        if s.hasPrefix("#") { s.removeFirst() }
        let v = UInt64(s, radix: 16) ?? 0
        self.init(.sRGB,
                  red: Double((v >> 16) & 0xff) / 255,
                  green: Double((v >> 8) & 0xff) / 255,
                  blue: Double(v & 0xff) / 255,
                  opacity: opacity)
    }
}

/// `rgba(h, a)` from the design — a hex colour at a given alpha.
func rgba(_ hex: String, _ a: Double) -> Color { Color(hex: hex, opacity: a) }

// MARK: - Tokens (exact values from renderVals())

struct Tokens {
    let dark: Bool
    // theme tokens `t`
    let page, bg, ink, sub, glass, glassHi, stroke, track, div, bezel: Color
    let blob: Double
    // shadow (inset highlight + soft drop); SwiftUI approximates inset as a top stroke
    let shadowColor: Color
    let shadowRadius: CGFloat
    let shadowY: CGFloat
    // accent `a`
    let a1, a2, c1, c2, soft: Color
    let good, warn, bad: Color
    // raw hex the Canvas renderers need (they recompute c1/c2 with the on/off greys)
    let accentHex: [String]
    let c1Hex, c2Hex: String

    static func make(_ theme: AppTheme, _ accent: Accent) -> Tokens {
        let dark = theme == .dark
        let A = ACC[accent] ?? ACC[.aurora]!
        let c1Hex = dark ? A[0] : A[2]
        let c2Hex = dark ? A[1] : A[3]
        if dark {
            return Tokens(
                dark: true,
                page: Color(hex: "#06070B"),
                bg: Color(hex: "#07080D"),
                ink: Color(hex: "#F4F6FB"),
                sub: Color(.sRGB, red: 232/255, green: 238/255, blue: 255/255, opacity: 0.60),
                glass: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.06),
                glassHi: Color(.sRGB, red: 30/255, green: 32/255, blue: 42/255, opacity: 0.55),
                stroke: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.12),
                track: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.12),
                div: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.08),
                bezel: Color(hex: "#1B1C22"),
                blob: 0.32,
                shadowColor: Color(.sRGB, red: 0, green: 0, blue: 0, opacity: 0.35),
                shadowRadius: 40, shadowY: 20,
                a1: Color(hex: A[0]), a2: Color(hex: A[1]),
                c1: Color(hex: c1Hex), c2: Color(hex: c2Hex),
                soft: rgba(c1Hex, 0.14),
                good: Color(hex: "#5EF0A8"), warn: Color(hex: "#FFC65E"), bad: Color(hex: "#FF6B8A"),
                accentHex: A, c1Hex: c1Hex, c2Hex: c2Hex
            )
        } else {
            return Tokens(
                dark: false,
                page: Color(hex: "#DCE1EA"),
                bg: Color(hex: "#EEF1F7"),
                ink: Color(hex: "#0B0D14"),
                sub: Color(.sRGB, red: 11/255, green: 13/255, blue: 20/255, opacity: 0.60),
                glass: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.50),
                glassHi: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.62),
                stroke: Color(.sRGB, red: 1, green: 1, blue: 1, opacity: 0.85),
                track: Color(.sRGB, red: 11/255, green: 13/255, blue: 20/255, opacity: 0.10),
                div: Color(.sRGB, red: 11/255, green: 13/255, blue: 20/255, opacity: 0.07),
                bezel: Color(hex: "#1B1C22"),
                blob: 0.45,
                shadowColor: Color(.sRGB, red: 40/255, green: 50/255, blue: 80/255, opacity: 0.12),
                shadowRadius: 40, shadowY: 20,
                a1: Color(hex: A[0]), a2: Color(hex: A[1]),
                c1: Color(hex: c1Hex), c2: Color(hex: c2Hex),
                soft: rgba(c1Hex, 0.12),
                good: Color(hex: "#0E9A5E"), warn: Color(hex: "#B86E00"), bad: Color(hex: "#D02A50"),
                accentHex: A, c1Hex: c1Hex, c2Hex: c2Hex
            )
        }
    }
}

// MARK: - Fonts (Geist / Geist Mono; SF Pro / SF Mono substitutes per the handoff)

extension Font {
    /// UI font. Falls back to the system (SF Pro) when Geist isn't bundled.
    static func ui(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight)
    }
    /// Monospaced font for labels, data and IDs (Geist Mono → SF Mono).
    static func mono(_ size: CGFloat, _ weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}
