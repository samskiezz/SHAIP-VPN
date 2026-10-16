import Foundation

public enum SceneMode: String, Sendable {
    case net, globe, radar
}

/// Where a scene sits in its canvas: centre height (fraction of h), radius (fraction of
/// min(w, h)), and a centre radius in points that mesh HUD labels keep clear of (the orb).
public struct SceneLayout: Hashable, Sendable {
    public var cy: Double
    public var r: Double
    public var hudClear: Double

    public init(cy: Double = 0.5, r: Double, hudClear: Double = 0) {
        self.cy = cy; self.r = r; self.hudClear = hudClear
    }
}

/// Live inputs for a frame: connection state, rendering props and the HUD copy.
public struct SceneOptions: Hashable, Sendable {
    public var connected = true
    /// Mesh node count (the design's tweakable 60…260).
    public var density = 210
    public var hud = true
    public var floor = true
    /// Freeze rotation, keep pulses static, hide packets and streaks.
    public var reduceMotion = false
    public var palette = Palette.shaip
    /// Mesh: labels for the first four outer hubs.
    public var labels: [HUDText] = []
    /// Globe: hub index of the selected node, and labels per hub index.
    public var activeHub = 0
    public var hubLabels: [Int: HUDText] = [:]
    /// Radar: label n is shown on threat blip n.
    public var radarLabels: [HUDText] = []

    public init() {}
}

/// One canvas's renderer: holds the generated geometry, the accumulated phase and the eased
/// connection state, and turns (size, timestamp, options) into a frame's draw ops — exactly as
/// `draw()` in design/shaip-engine.js does for one `<canvas data-gfx>`.
public final class SceneRenderer {
    public let mode: SceneMode
    private var net: NetGeometry?
    private var globe: GlobeGeometry?
    private var radar: RadarGeometry?
    private var density = -1
    private var last = 0.0
    private var u = 1.0
    public private(set) var phase = 0.0
    private var started = false

    public init(mode: SceneMode) { self.mode = mode }

    /// The eased connection value of the last frame (1 connected … 0 disconnected).
    public private(set) var link = 1.0

    /// Draw a frame. `ts` is a monotonic timestamp in milliseconds.
    public func frame(width w: Double, height h: Double, ts: Double, layout: SceneLayout, options o: SceneOptions) -> [DrawOp] {
        let regenerate: Bool
        switch mode {
        case .net: regenerate = net == nil || density != o.density
        case .globe: regenerate = globe == nil
        case .radar: regenerate = radar == nil
        }
        if regenerate {
            switch mode {
            case .net: net = genNet(o.density)
            case .globe: globe = genGlobe()
            case .radar: radar = genRadar()
            }
            density = o.density
            last = ts
            if !started { u = o.connected ? 1 : 0; started = true }
        }
        let dt = min(50, max(0, ts - last))
        last = ts
        u = max(0, min(1, u + (o.connected ? dt : -dt) / 550))
        link = ease(u)
        let mix = mode == .net ? link : 1
        if !o.reduceMotion { phase += dt * (0.25 + 0.75 * mix) }
        let C = Palette(c1: Palette.offC1.mixed(to: o.palette.c1, mix), c2: Palette.offC2.mixed(to: o.palette.c2, mix),
                        bad: o.palette.bad, warn: o.palette.warn)
        let p = SceneParams(mix: mix, link: link, cyF: layout.cy, rF: layout.r, hudClear: layout.hudClear,
                            hud: o.hud, floor: o.floor, reduceMotion: o.reduceMotion, labels: o.labels,
                            active: o.activeHub, hubLabels: o.hubLabels, radarLabels: o.radarLabels)
        let t = o.reduceMotion ? 0 : ts
        switch mode {
        case .net:
            var d = DrawList(capacity: 2048)
            drawNet(&d, w: w, h: h, G: net!, o: p, ph: phase, ts: t, C: C)
            return d.ops
        case .globe:
            var d = DrawList(capacity: 2304)
            drawGlobe(&d, w: w, h: h, G: globe!, o: p, ph: phase, ts: t, C: C)
            return d.ops
        case .radar:
            var d = DrawList(capacity: 192)
            drawRadar(&d, w: w, h: h, G: radar!, o: p, ph: phase, ts: t, C: C)
            return d.ops
        }
    }

    /// Mark the canvas as not drawn this frame (offscreen or paused), so the next frame resumes
    /// without a jump — the reference updates `last` for offscreen canvases the same way.
    public func skip(ts: Double) { last = ts }
}

/// Cubic ease-in-out over the 550 ms connection transition.
@inline(__always) func ease(_ u: Double) -> Double {
    if u < 0.5 { return 4 * u * u * u }
    let v = -2 * u + 2
    return 1 - v * v * v / 2
}
