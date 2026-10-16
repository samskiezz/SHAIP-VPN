import Foundation

/// An sRGB colour with 8-bit channels — the design's `#RRGGBB` tokens.
public struct RGB: Hashable, Sendable {
    public var r: Int
    public var g: Int
    public var b: Int

    public init(_ r: Int, _ g: Int, _ b: Int) {
        self.r = r; self.g = g; self.b = b
    }

    /// `#RRGGBB`, as the engine's `rgb()` parses it.
    public init(hex: String) {
        let n = Int(hex.hasPrefix("#") ? String(hex.dropFirst()) : hex, radix: 16) ?? 0
        self.init(n >> 16, (n >> 8) & 255, n & 255)
    }

    public var hex: String {
        let digits = Array("0123456789ABCDEF")
        return "#" + String([r >> 4, r & 15, g >> 4, g & 15, b >> 4, b & 15].map { digits[$0] })
    }

    /// The engine's `mixHex`: per-channel linear mix towards `other`, rounded half up.
    public func mixed(to other: RGB, _ t: Double) -> RGB {
        func ch(_ a: Int, _ b: Int) -> Int {
            Int((Double(a) + Double(b - a) * t).rounded(.toNearestOrAwayFromZero))
        }
        return RGB(ch(r, other.r), ch(g, other.g), ch(b, other.b))
    }

    public static let white = RGB(255, 255, 255)
    /// `#F5F7FC`, HUD label ink.
    public static let ink = RGB(hex: "#F5F7FC")
}

/// A colour with straight (non-premultiplied) alpha.
public struct RGBA: Hashable, Sendable {
    public var rgb: RGB
    public var a: Double

    public init(_ rgb: RGB, _ a: Double) {
        self.rgb = rgb; self.a = a
    }
}

/// The engine's `rgba(h, a)`: alpha clamped to 0…1.
@inline(__always) func rgba(_ c: RGB, _ a: Double) -> RGBA {
    RGBA(c, a < 0 ? 0 : a > 1 ? 1 : a)
}

/// The renderer palette: `c1` (signal), `c2` (steel), and the two alert colours.
public struct Palette: Hashable, Sendable {
    public var c1: RGB
    public var c2: RGB
    public var bad: RGB
    public var warn: RGB

    public init(c1: RGB, c2: RGB, bad: RGB, warn: RGB) {
        self.c1 = c1; self.c2 = c2; self.bad = bad; self.warn = warn
    }

    /// signal `#5CF2FF`, steel `#8A9BB8`, threat `#FF5C7A`, warn `#FFB547`.
    public static let shaip = Palette(c1: RGB(hex: "#5CF2FF"), c2: RGB(hex: "#8A9BB8"),
                                      bad: RGB(hex: "#FF5C7A"), warn: RGB(hex: "#FFB547"))
    /// The desaturated mesh palette used while disconnected.
    public static let offC1 = RGB(hex: "#8A93A8")
    public static let offC2 = RGB(hex: "#3E4558")
}
