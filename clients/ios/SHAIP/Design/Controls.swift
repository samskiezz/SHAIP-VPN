import SwiftUI

// Shared controls from the handoff's "Controls" and component specs.

/// Mono eyebrow: SF Mono 9–11 / 500, tracking +14–18%, uppercase.
struct Eyebrow: View {
    let text: String
    var size: CGFloat = 10
    var tracking: CGFloat = 0.14
    var color: Color = Tok.ink3
    var weight: Font.Weight = .medium

    init(_ text: String, size: CGFloat = 10, tracking: CGFloat = 0.14, color: Color = Tok.ink3, weight: Font.Weight = .medium) {
        self.text = text; self.size = size; self.tracking = tracking; self.color = color; self.weight = weight
    }

    var body: some View {
        Text(text.uppercased()).mono(size, weight).em(tracking, of: size).foregroundStyle(color)
    }
}

/// A status dot with the design's same-colour glow (`0 0 8–12`).
struct GlowDot: View {
    let color: Color
    var size: CGFloat = 6
    var glow: CGFloat = 8

    var body: some View {
        Circle().fill(color).frame(width: size, height: size).shadow(color: color, radius: glow / 2)
    }
}

/// Status pill: 24 pt capsule, state colour at 12%, glowing dot, mono 10 / 600 label.
struct StatusPill: View {
    let text: String
    let color: Color

    var body: some View {
        HStack(spacing: 7) {
            GlowDot(color: color)
            Text(text).mono(10, .semibold).em(0.14, of: 10).foregroundStyle(color)
        }
        .padding(.horizontal, 10)
        .frame(height: 24)
        .background(Capsule().fill(color.opacity(0.12)))
        .accessibilityElement(children: .combine)
    }
}

/// Small mono chip (spec chips, posture chips, tag badges).
struct Chip: View {
    let text: String
    var dot: Color? = nil
    var size: CGFloat = 9
    var ink: Color = Tok.dim(0.75)
    var fill: Color = .clear
    var stroke: Color = .white.opacity(0.14)
    var radius: CGFloat = 6
    var tracking: CGFloat = 0.06
    var hPad: CGFloat = 6
    var vPad: CGFloat = 3

    var body: some View {
        HStack(spacing: 4) {
            if let dot { Circle().fill(dot).frame(width: 4, height: 4) }
            Text(text).mono(size, .medium).em(tracking, of: size).foregroundStyle(ink).lineLimit(1)
        }
        .padding(.horizontal, hPad)
        .padding(.vertical, vPad)
        .background(RoundedRectangle(cornerRadius: radius, style: .continuous).fill(fill))
        .overlay(RoundedRectangle(cornerRadius: radius, style: .continuous).strokeBorder(stroke, lineWidth: 0.5))
    }
}

/// 0.5 pt row divider.
struct Hairline: View {
    var color: Color = Tok.hairline
    var body: some View { Rectangle().fill(color).frame(height: 0.5) }
}

/// The design's switch: 58×32 track, 36×28 capsule thumb (Liquid Glass style), on = ok,
/// off = white 14%. A real Toggle, so it reads as a switch to VoiceOver.
struct GlassSwitchStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button {
            configuration.isOn.toggle()
        } label: {
            HStack(spacing: 12) {
                configuration.label
                Spacer(minLength: 0)
                ZStack(alignment: configuration.isOn ? .trailing : .leading) {
                    Capsule(style: .continuous)
                        .fill((configuration.isOn ? Tok.ok : Color.white.opacity(0.14))
                            .shadow(.inner(color: .black.opacity(0.3), radius: 1, x: 0, y: 1)))
                    Capsule(style: .continuous)
                        .fill(LinearGradient(colors: [.white, Color(hex: 0xE4E8F0)], startPoint: .top, endPoint: .bottom)
                            .shadow(.inner(color: .black.opacity(0.08), radius: 0, x: 0, y: -1)))
                        .frame(width: 36, height: 28)
                        .shadow(color: .black.opacity(0.35), radius: 3, x: 0, y: 2)
                        .padding(2)
                }
                .frame(width: 58, height: 32)
                .animation(.smooth(duration: 0.3), value: configuration.isOn)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isToggle)
        .accessibilityValue(configuration.isOn ? "On" : "Off")
    }
}

/// Segmented control: 3 pt-padded track (white 5%, 0.5 pt border white 10%); the selected segment is
/// white 14% with a specular line and shadow, sliding with `.smooth`.
struct GlassSegmented<Value: Hashable>: View {
    let options: [(value: Value, label: String)]
    @Binding var selection: Value
    @Namespace private var ns

    var body: some View {
        HStack(spacing: 0) {
            ForEach(options.indices, id: \.self) { i in
                let opt = options[i]
                let on = opt.value == selection
                Button {
                    withAnimation(.smooth(duration: 0.3)) { selection = opt.value }
                } label: {
                    Text(opt.label)
                        .ui(13, .semibold, relativeTo: .subheadline)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                        .foregroundStyle(on ? Tok.ink : Tok.ink2)
                        .frame(maxWidth: .infinity)
                        .frame(height: 32)
                        .background {
                            if on {
                                Capsule(style: .continuous)
                                    .fill(Color.white.opacity(0.14).shadow(.inner(color: .white.opacity(0.3), radius: 0, x: 0, y: 0.5)))
                                    .shadow(color: .black.opacity(0.4), radius: 5, x: 0, y: 4)
                                    .matchedGeometryEffect(id: "seg", in: ns)
                            }
                        }
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(on ? .isSelected : [])
            }
        }
        .padding(3)
        .background(Capsule(style: .continuous).fill(Color.white.opacity(0.05)))
        .overlay(Capsule(style: .continuous).strokeBorder(Color.white.opacity(0.1), lineWidth: 0.5))
        .sensoryFeedback(.selection, trigger: selection)
    }
}

/// A 44 pt round Liquid Glass button.
struct RoundGlassButton<Label: View>: View {
    var size: CGFloat = 44
    let action: () -> Void
    @ViewBuilder var label: Label

    var body: some View {
        Button(action: action) {
            label.frame(width: size, height: size).contentShape(Circle())
        }
        .buttonStyle(.plain)
        .liquidGlass(in: Circle())
    }
}

/// A large title row: 34 / 700, tracking −3%, with an optional trailing accessory.
struct LargeTitle<Trailing: View>: View {
    let title: String
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(title).ui(34, .bold, relativeTo: .largeTitle).em(-0.03, of: 34).foregroundStyle(Tok.ink)
                .accessibilityAddTraits(.isHeader)
            Spacer(minLength: 8)
            trailing
        }
        .padding(.horizontal, 8)
    }
}

extension LargeTitle where Trailing == EmptyView {
    init(_ title: String) { self.init(title: title) { EmptyView() } }
}

/// Wrapping layout for chips.
struct FlowLayout: Layout {
    var spacing: CGFloat = 5

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(subviews, width: proposal.width ?? .infinity)
        return CGSize(width: proposal.width ?? rows.map(\.width).max() ?? 0, height: rows.last.map { $0.y + $0.height } ?? 0)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for row in arrange(subviews, width: bounds.width) {
            var x = bounds.minX
            for i in row.items {
                let s = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: bounds.minY + row.y), proposal: ProposedViewSize(s))
                x += s.width + spacing
            }
        }
    }

    private struct Row { var items: [Int] = []; var y: CGFloat = 0; var width: CGFloat = 0; var height: CGFloat = 0 }

    private func arrange(_ subviews: Subviews, width: CGFloat) -> [Row] {
        var rows: [Row] = [Row()]
        for (i, v) in subviews.enumerated() {
            let s = v.sizeThatFits(.unspecified)
            var row = rows[rows.count - 1]
            if !row.items.isEmpty && row.width + spacing + s.width > width {
                let y = row.y + row.height + spacing
                rows.append(Row(y: y))
                row = rows[rows.count - 1]
            }
            row.width += (row.items.isEmpty ? 0 : spacing) + s.width
            row.height = max(row.height, s.height)
            row.items.append(i)
            rows[rows.count - 1] = row
        }
        return rows
    }
}
