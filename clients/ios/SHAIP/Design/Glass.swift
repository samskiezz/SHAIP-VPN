import SwiftUI

// The handoff's glass recipe. Content surfaces (cards, tiles, lists) use a blurred material with the
// recipe's fill gradient, 0.5 pt border, inner specular line and soft drop shadows. Controls (orb,
// header pills, round buttons, quick toggles) use native Liquid Glass (`.glassEffect`) with the same
// border and specular, as Apple recommends glass for the control layer; the tab bar is the system's.

struct GlassRecipe {
    var top: Double
    var bottom: Double
    var border: Double
    var specular: Double
    var shadow: Bool

    /// Primary cards: fill .085 → .025, border .15, specular .32, shadow 0 1 1 + 0 24 48 −18.
    static let card = GlassRecipe(top: 0.085, bottom: 0.025, border: 0.15, specular: 0.32, shadow: true)
    /// List cards: .075 → .02, border .15, specular .30.
    static let list = GlassRecipe(top: 0.075, bottom: 0.02, border: 0.15, specular: 0.30, shadow: true)
    /// Secondary glass (tiles): .07 → .02, border .13, specular .25.
    static let tile = GlassRecipe(top: 0.07, bottom: 0.02, border: 0.13, specular: 0.25, shadow: false)
    /// Buttons and pills: .09 → .03, border .16, specular .30.
    static let control = GlassRecipe(top: 0.09, bottom: 0.03, border: 0.16, specular: 0.30, shadow: false)
}

private struct GlassBackground<S: InsettableShape>: ViewModifier {
    let shape: S
    let recipe: GlassRecipe
    var border: Color?

    func body(content: Content) -> some View {
        content
            .background {
                shape
                    .fill(LinearGradient(colors: [.white.opacity(recipe.top), .white.opacity(recipe.bottom)],
                                         startPoint: .top, endPoint: .bottom)
                        .shadow(.inner(color: .white.opacity(recipe.specular), radius: 0, x: 0, y: 0.5)))
                    .background(.ultraThinMaterial, in: shape)
                    .shadow(color: .black.opacity(recipe.shadow ? 0.6 : 0), radius: 0.5, x: 0, y: 1)
                    .shadow(color: .black.opacity(recipe.shadow ? 0.55 : 0), radius: 18, x: 0, y: 18)
            }
            .overlay { shape.strokeBorder(border ?? .white.opacity(recipe.border), lineWidth: 0.5) }
    }
}

private struct LiquidGlassBackground<S: Shape>: ViewModifier {
    let shape: S
    var tint: Color?
    var interactive: Bool
    var border: Color

    func body(content: Content) -> some View {
        content
            .background {
                shape.fill(LinearGradient(colors: [.white.opacity(0.09), .white.opacity(0.03)], startPoint: .top, endPoint: .bottom)
                    .shadow(.inner(color: .white.opacity(0.3), radius: 0, x: 0, y: 0.5)))
            }
            .glassEffect(glass, in: shape)
            .overlay { shape.stroke(border, lineWidth: 0.5) }
    }

    private var glass: Glass {
        var g = Glass.regular
        if let tint { g = g.tint(tint) }
        return interactive ? g.interactive() : g
    }
}

extension View {
    /// A content surface (card, list or tile) with the handoff's glass recipe.
    func glassCard(_ radius: CGFloat, _ recipe: GlassRecipe = .card, border: Color? = nil) -> some View {
        modifier(GlassBackground(shape: RoundedRectangle(cornerRadius: radius, style: .continuous), recipe: recipe, border: border))
    }

    func glassCapsule(_ recipe: GlassRecipe = .control, border: Color? = nil) -> some View {
        modifier(GlassBackground(shape: Capsule(style: .continuous), recipe: recipe, border: border))
    }

    /// Native Liquid Glass for controls, with the recipe's border and specular line.
    func liquidGlass<S: Shape>(in shape: S, tint: Color? = nil, interactive: Bool = true,
                               border: Color = .white.opacity(0.16)) -> some View {
        modifier(LiquidGlassBackground(shape: shape, tint: tint, interactive: interactive, border: border))
    }
}
