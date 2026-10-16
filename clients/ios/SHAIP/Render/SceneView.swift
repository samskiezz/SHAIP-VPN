import SwiftUI
import CoreGraphics
import SHAIPCore

/// A live 3-D scene (`net` mesh, `globe` or `radar`). SHAIPCore's SceneRenderer produces each
/// frame's draw ops — verified op-for-op against design/shaip-engine.js — and ScenePainter maps
/// them onto the Canvas. Rendering pauses when the view is offscreen or the app is not active, and
/// follows Reduce Motion (frozen rotation, static pulses, no packets).
struct SceneView: View {
    let mode: SceneMode
    let layout: SceneLayout
    let options: SceneOptions
    @State private var renderer: SceneRenderer
    @State private var onScreen = false
    @Environment(\.scenePhase) private var scenePhase
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(_ mode: SceneMode, layout: SceneLayout, options: SceneOptions) {
        self.mode = mode
        self.layout = layout
        self.options = options
        _renderer = State(initialValue: SceneRenderer(mode: mode))
    }

    var body: some View {
        // The phase is time-based, so motion speed is the same at any frame rate. 60 fps keeps a
        // ~2,000-op Canvas frame comfortably inside budget; a Metal port is the path to 120 fps.
        TimelineView(.animation(minimumInterval: reduceMotion ? 1.0 / 15 : 1.0 / 60,
                                paused: !onScreen || scenePhase != .active)) { timeline in
            Canvas { ctx, size in
                var o = options
                o.reduceMotion = o.reduceMotion || reduceMotion
                let ts = timeline.date.timeIntervalSinceReferenceDate * 1000
                let ops = renderer.frame(width: size.width, height: size.height, ts: ts, layout: layout, options: o)
                ScenePainter.paint(ops, in: &ctx)
            }
        }
        .onAppear { onScreen = true }
        .onDisappear { onScreen = false }
        .allowsHitTesting(false)
        .accessibilityHidden(true)   // the scene's data also appears as text elsewhere on screen
    }
}

/// Maps DrawOps onto a GraphicsContext with Canvas2D semantics: `.plusLighter` for additive runs,
/// radial-falloff glow sprites, alphabetic-baseline HUD text.
///
/// Lines, rects, discs and rings are batched by colour (alpha quantised to 1/64) and width (to
/// 1/20 pt) into a few dozen paths per frame instead of ~2,000 draw calls. Additive blending is
/// order-independent, so batches flush only when the blend mode changes; in normal mode they flush
/// before any unbatched op to preserve order.
enum ScenePainter {
    private struct Key: Hashable {
        var r: Int, g: Int, b: Int, a: Int, w: Int
    }

    private struct Batches {
        var lines: [Key: Path] = [:]
        var rects: [Key: Path] = [:]
        var discs: [Key: Path] = [:]
        var rings: [Key: Path] = [:]
        var isEmpty: Bool { lines.isEmpty && rects.isEmpty && discs.isEmpty && rings.isEmpty }

        mutating func flush(_ ctx: inout GraphicsContext) {
            for (k, p) in lines { ctx.stroke(p, with: .color(color(k)), lineWidth: Double(k.w) / 20) }
            for (k, p) in rects { ctx.fill(p, with: .color(color(k))) }
            for (k, p) in discs { ctx.fill(p, with: .color(color(k))) }
            for (k, p) in rings { ctx.stroke(p, with: .color(color(k)), lineWidth: Double(k.w) / 20) }
            self = Batches()
        }

        private func color(_ k: Key) -> Color {
            Color(.sRGB, red: Double(k.r) / 255, green: Double(k.g) / 255, blue: Double(k.b) / 255, opacity: Double(k.a) / 64)
        }
    }

    @inline(__always) private static func key(_ c: RGBA, width: Double = 0) -> Key? {
        let a = Int((c.a * 64).rounded())
        guard a > 0 else { return nil }   // below 1/128: invisible
        return Key(r: c.rgb.r, g: c.rgb.g, b: c.rgb.b, a: min(64, a), w: Int((width * 20).rounded()))
    }

    static func paint(_ ops: [DrawOp], in ctx: inout GraphicsContext) {
        var batches = Batches()
        var additive = false
        var resolved: [RGB: GraphicsContext.ResolvedImage] = [:]
        ctx.blendMode = .normal

        for op in ops {
            switch op {
            case .blend(let b):
                batches.flush(&ctx)
                additive = b == .additive
                ctx.blendMode = additive ? .plusLighter : .normal

            case let .line(x0, y0, x1, y1, c, w):
                guard let k = key(c, width: w) else { continue }
                batches.lines[k, default: Path()].move(to: CGPoint(x: x0, y: y0))
                batches.lines[k]!.addLine(to: CGPoint(x: x1, y: y1))
            case let .rect(x, y, w, h, c):
                guard let k = key(c) else { continue }
                batches.rects[k, default: Path()].addRect(CGRect(x: x, y: y, width: w, height: h))
            case let .disc(x, y, r, c):
                guard let k = key(c) else { continue }
                batches.discs[k, default: Path()].addEllipse(in: CGRect(x: x - r, y: y - r, width: r * 2, height: r * 2))
            case let .ring(x, y, r, c, w):
                guard let k = key(c, width: w) else { continue }
                batches.rings[k, default: Path()].addEllipse(in: CGRect(x: x - r, y: y - r, width: r * 2, height: r * 2))

            case let .sprite(c, x, y, size, alpha):
                if !additive { batches.flush(&ctx) }
                guard alpha > 0, size > 0 else { continue }
                if resolved[c] == nil, let img = GlowSprites.image(c) {
                    resolved[c] = ctx.resolve(Image(decorative: img, scale: 1))
                }
                guard let img = resolved[c] else { continue }
                ctx.opacity = alpha
                ctx.draw(img, in: CGRect(x: x - size / 2, y: y - size / 2, width: size, height: size))
                ctx.opacity = 1

            case let .text(s, x, y, align, c):
                if !additive { batches.flush(&ctx) }
                let t = ctx.resolve(Text(s).font(.system(size: 9, weight: .medium, design: .monospaced)).foregroundStyle(swiftColor(c)))
                let size = t.measure(in: CGSize(width: 2000, height: 200))
                let baseline = t.firstBaseline(in: size)
                ctx.draw(t, in: CGRect(x: align == .left ? x : x - size.width, y: y - baseline, width: size.width, height: size.height))

            case let .gradientRect(x, y, w, h, g):
                if !additive { batches.flush(&ctx) }
                fill(&ctx, Path(CGRect(x: x, y: y, width: w, height: h)), g)
            case let .gradientDisc(x, y, r, g):
                if !additive { batches.flush(&ctx) }
                fill(&ctx, Path(ellipseIn: CGRect(x: x - r, y: y - r, width: r * 2, height: r * 2)), g)
            case let .gradientEllipse(tx, ty, sx, sy, r, g):
                if !additive { batches.flush(&ctx) }
                var local = ctx
                local.translateBy(x: tx, y: ty)
                local.scaleBy(x: sx, y: sy)
                fill(&local, Path(ellipseIn: CGRect(x: -r, y: -r, width: r * 2, height: r * 2)), g)
            case let .conicDisc(x, y, r, g):
                if !additive { batches.flush(&ctx) }
                ctx.fill(Path(ellipseIn: CGRect(x: x - r, y: y - r, width: r * 2, height: r * 2)),
                         with: .conicGradient(gradient(g.stops), center: CGPoint(x: g.x, y: g.y), angle: .radians(g.angle)))
            }
        }
        batches.flush(&ctx)
        ctx.blendMode = .normal
    }

    private static func swiftColor(_ c: RGBA) -> Color { Color(c.rgb, opacity: c.a) }

    private static func gradient(_ stops: [GradientStop]) -> Gradient {
        Gradient(stops: stops.map { Gradient.Stop(color: swiftColor($0.color), location: $0.offset) })
    }

    /// Canvas2D radial gradients are two-circle; SwiftUI's shading is concentric only, so the one
    /// eccentric gradient (the globe body's top-left highlight) is drawn with Core Graphics.
    private static func fill(_ ctx: inout GraphicsContext, _ path: Path, _ g: RadialGradientSpec) {
        if g.x0 == g.x1 && g.y0 == g.y1 {
            ctx.fill(path, with: .radialGradient(gradient(g.stops), center: CGPoint(x: g.x0, y: g.y0),
                                                 startRadius: g.r0, endRadius: g.r1))
            return
        }
        ctx.withCGContext { cg in
            guard let space = CGColorSpace(name: CGColorSpace.sRGB) else { return }
            let colors = g.stops.map {
                CGColor(srgbRed: Double($0.color.rgb.r) / 255, green: Double($0.color.rgb.g) / 255,
                        blue: Double($0.color.rgb.b) / 255, alpha: $0.color.a)
            }
            guard let grad = CGGradient(colorsSpace: space, colors: colors as CFArray, locations: g.stops.map { CGFloat($0.offset) }) else { return }
            cg.saveGState()
            cg.addPath(path.cgPath)
            cg.clip()
            cg.drawRadialGradient(grad, startCenter: CGPoint(x: g.x0, y: g.y0), startRadius: g.r0,
                                  endCenter: CGPoint(x: g.x1, y: g.y1), endRadius: g.r1,
                                  options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
            cg.restoreGState()
        }
    }
}

/// Pre-rendered 128 px glow sprites: white core, the colour at 10% (alpha 1), 24% (0.42),
/// 50% (0.08), transparent at the edge — the engine's `spr()`.
enum GlowSprites {
    // Only touched from Canvas renderers, which run on the main thread (rendersAsynchronously: false).
    nonisolated(unsafe) private static var cache: [RGB: CGImage] = [:]

    static func image(_ c: RGB) -> CGImage? {
        if let img = cache[c] { return img }
        let n = 128
        guard let space = CGColorSpace(name: CGColorSpace.sRGB),
              let cg = CGContext(data: nil, width: n, height: n, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                                 bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
        func col(_ a: Double) -> CGColor {
            CGColor(srgbRed: Double(c.r) / 255, green: Double(c.g) / 255, blue: Double(c.b) / 255, alpha: a)
        }
        let colors = [CGColor(srgbRed: 1, green: 1, blue: 1, alpha: 1), col(1), col(0.42), col(0.08), col(0)]
        guard let grad = CGGradient(colorsSpace: space, colors: colors as CFArray, locations: [0, 0.1, 0.24, 0.5, 1]) else { return nil }
        let mid = CGPoint(x: n / 2, y: n / 2)
        cg.drawRadialGradient(grad, startCenter: mid, startRadius: 0, endCenter: mid, endRadius: CGFloat(n / 2), options: [])
        let img = cg.makeImage()
        if cache.count > 256 { cache.removeAll() }   // palette cross-fades mint a bounded set; keep it bounded
        cache[c] = img
        return img
    }
}
