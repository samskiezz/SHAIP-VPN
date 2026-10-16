import Foundation

/// Compositing mode: Canvas2D `source-over` / `lighter` (additive).
public enum Blend: UInt8, Sendable {
    case normal = 0
    case additive = 1
}

public enum TextAlign: UInt8, Sendable {
    case left = 0
    case right = 1
}

public struct GradientStop: Hashable, Sendable {
    public var offset: Double
    public var color: RGBA
}

/// A Canvas2D radial gradient: from circle (x0, y0, r0) to circle (x1, y1, r1), colours beyond
/// either end extend (the `drawsBefore/AfterStartLocation` options in Core Graphics).
public struct RadialGradientSpec: Hashable, Sendable {
    public var x0: Double, y0: Double, r0: Double
    public var x1: Double, y1: Double, r1: Double
    public var stops: [GradientStop]
}

/// A Canvas2D conic gradient: starts at `angle` (radians, clockwise from +x in y-down space).
public struct ConicGradientSpec: Hashable, Sendable {
    public var angle: Double
    public var x: Double, y: Double
    public var stops: [GradientStop]
}

/// One draw call of a render frame. The engines emit these in the reference engine's exact order;
/// a painter maps them onto a graphics context (SceneView in the app, a recorder in the tests).
public enum DrawOp: Hashable, Sendable {
    /// Subsequent ops composite with this mode (emitted lazily, only when it changes).
    case blend(Blend)
    case line(x0: Double, y0: Double, x1: Double, y1: Double, color: RGBA, width: Double)
    case ring(x: Double, y: Double, r: Double, color: RGBA, width: Double)
    case disc(x: Double, y: Double, r: Double, color: RGBA)
    case rect(x: Double, y: Double, w: Double, h: Double, color: RGBA)
    /// A glow sprite centred at (x, y): white core, the colour at 10%, falling to 0 at the edge.
    case sprite(color: RGB, x: Double, y: Double, size: Double, alpha: Double)
    /// Mono 9 pt / 500 HUD text; (x, y) is the alphabetic baseline at the aligned edge.
    case text(String, x: Double, y: Double, align: TextAlign, color: RGBA)
    case gradientRect(x: Double, y: Double, w: Double, h: Double, gradient: RadialGradientSpec)
    case gradientDisc(x: Double, y: Double, r: Double, gradient: RadialGradientSpec)
    /// A circle of radius `r` at the origin of a space translated by (tx, ty) and scaled by
    /// (sx, sy); the gradient is in that same local space.
    case gradientEllipse(tx: Double, ty: Double, sx: Double, sy: Double, r: Double, gradient: RadialGradientSpec)
    case conicDisc(x: Double, y: Double, r: Double, gradient: ConicGradientSpec)
}

/// Collects a frame's ops, inserting `.blend` only when the requested mode actually changes
/// before the next draw — the same lazy semantics the vector recorder applies to the reference.
struct DrawList {
    private(set) var ops: [DrawOp] = []
    private var requested: Blend = .normal
    private var emitted: Blend = .normal

    init(capacity: Int) { ops.reserveCapacity(capacity) }

    mutating func setBlend(_ b: Blend) { requested = b }

    @inline(__always) mutating func emit(_ op: DrawOp) {
        if requested != emitted {
            ops.append(.blend(requested))
            emitted = requested
        }
        ops.append(op)
    }

    /// `glowAt` — Canvas2D ignores a globalAlpha outside 0…1; the engines never produce one.
    @inline(__always) mutating func glow(_ c: RGB, _ x: Double, _ y: Double, _ size: Double, _ alpha: Double) {
        emit(.sprite(color: c, x: x, y: y, size: size, alpha: max(0, min(1, alpha))))
    }
}

/// Text shown by a HUD reticle: a title line and a detail line.
public struct HUDText: Hashable, Sendable {
    public var title: String
    public var detail: String

    public init(_ title: String, _ detail: String) {
        self.title = title; self.detail = detail
    }
}

/// HUD label width model: SF Mono's advance is 0.6 em, so 9 pt glyphs are 5.4 pt wide. The
/// reference measures the same way (UTF-16 length × 9 × 0.6), keeping leader lines identical.
@inline(__always) func hudTextWidth(_ s: String) -> Double { Double(s.utf16.count) * 9 * 0.6 }

/// `hudLabel`: corner-bracket reticle, leader line and two text lines, flipped to stay on-screen.
func hudLabel(_ d: inout DrawList, c1: RGB, x: Double, y: Double, cx: Double, w: Double,
              _ l1: String, _ l2: String, al: Double) {
    d.setBlend(.normal)
    let tw = max(hudTextWidth(l1), hudTextWidth(l2))
    var side: Double = x > cx ? 1 : -1
    if x + side * (34 + tw) > w - 4 || x + side * (34 + tw) < 4 { side = -side }
    let b = 7.0, l = 3.0
    let bracket = rgba(c1, 0.85 * al)
    for (sx, sy) in [(-1.0, -1.0), (1.0, -1.0), (1.0, 1.0), (-1.0, 1.0)] {
        d.emit(.line(x0: x + sx * b, y0: y + sy * (b - l), x1: x + sx * b, y1: y + sy * b, color: bracket, width: 0.75))
        d.emit(.line(x0: x + sx * b, y0: y + sy * b, x1: x + sx * (b - l), y1: y + sy * b, color: bracket, width: 0.75))
    }
    let lx = x + side * 22, ly = y - 20
    let leader = rgba(.white, 0.32 * al)
    d.emit(.line(x0: x + side * b, y0: y - b, x1: lx, y1: ly, color: leader, width: 0.75))
    d.emit(.line(x0: lx, y0: ly, x1: lx + side * (tw + 8), y1: ly, color: leader, width: 0.75))
    let align: TextAlign = side > 0 ? .left : .right
    d.emit(.text(l1, x: lx + side * 4, y: ly - 5, align: align, color: rgba(.ink, 0.95 * al)))
    d.emit(.text(l2, x: lx + side * 4, y: ly + 11, align: align, color: rgba(c1, 0.75 * al)))
    d.setBlend(.additive)
}
