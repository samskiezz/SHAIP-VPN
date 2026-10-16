import Foundation

/// Semantic colour roles; the app maps them to the design tokens.
public enum Tone: String, Sendable, CaseIterable {
    case signal, steel, ok, warn, threat, secondary
}
