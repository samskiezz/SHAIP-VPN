import SwiftUI
import SHAIPCore

/// 04 Nodes: search, All / Recommended / Dedicated, and the node list (sorted by RTT). Tapping a
/// row selects the node and connects.
struct NodesView: View {
    @Environment(TunnelStore.self) private var store
    @State private var query = ""

    private var rows: [(index: Int, node: Node)] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return Catalog.nodes.enumerated().compactMap { i, n in
            guard store.nodeFilter.includes(n) else { return nil }
            guard q.isEmpty || [n.city, n.region, n.id, n.code, n.dc].contains(where: { $0.lowercased().contains(q) }) else { return nil }
            return (i, n)
        }
    }

    var body: some View {
        @Bindable var store = store
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.signal, size: 420, x: -200, y: -120, edge: .trailing, opacity: 0.12)]) {
            VStack(spacing: 12) {
                LargeTitle(title: "Nodes") { Eyebrow("SORT · RTT ASC", color: Tok.dim(0.45)) }
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass").font(.system(size: 16, weight: .semibold))
                    TextField("", text: $query, prompt: Text("Region, city or node ID").foregroundStyle(Tok.dim(0.45)))
                        .ui(15, relativeTo: .body)
                        .foregroundStyle(Tok.ink)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.search)
                    Chip(text: "\(Catalog.edgeNodes)", size: 10, ink: Tok.dim(0.45), stroke: .white.opacity(0.18))
                        .accessibilityLabel("\(Catalog.edgeNodes) nodes")
                }
                .foregroundStyle(Tok.dim(0.45))
                .padding(.horizontal, 16)
                .frame(height: 44)
                .glassCapsule(.tile, border: .white.opacity(0.14))
                GlassSegmented(options: NodeFilter.allCases.map { (value: $0, label: $0.label) }, selection: $store.nodeFilter)
                VStack(spacing: 0) {
                    ForEach(Array(rows.enumerated()), id: \.element.node.id) { pos, row in
                        NodeRow(node: row.node, index: row.index, selected: row.index == store.selectedNode)
                            .overlay(alignment: .top) { if pos > 0 { Hairline() } }
                    }
                    if rows.isEmpty {
                        Text("No nodes match").ui(14).foregroundStyle(Tok.ink2).frame(maxWidth: .infinity).padding(.vertical, 22)
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 30, style: .continuous))
                .glassCard(30, .list)
                .animation(.smooth(duration: 0.3), value: store.nodeFilter)
            }
        }
        .pushedScreenChrome()
    }
}

private struct NodeRow: View {
    @Environment(TunnelStore.self) private var store
    let node: Node
    let index: Int
    let selected: Bool

    var body: some View {
        Button {
            store.connect(to: index)
        } label: {
            HStack(spacing: 12) {
                Text(node.code).mono(11, .semibold).foregroundStyle(selected ? Tok.bgMid : Tok.ink)
                    .frame(width: 42, height: 42)
                    .background {
                        let specular = ShadowStyle.inner(color: .white.opacity(0.3), radius: 0, x: 0, y: 0.5)
                        RoundedRectangle(cornerRadius: 13, style: .continuous)
                            .fill(selected
                                  ? AnyShapeStyle(LinearGradient(colors: [Tok.signal, Tok.steel], startPoint: .topLeading, endPoint: .bottomTrailing).shadow(specular))
                                  : AnyShapeStyle(Color.white.opacity(0.06).shadow(specular)))
                    }
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 6) {
                        Text(node.city).ui(15, .semibold).em(-0.01, of: 15).foregroundStyle(Tok.ink).lineLimit(1)
                        if let tag = node.tag {
                            Chip(text: tag.rawValue, size: 8, ink: Tok.steelInk, fill: Tok.steel.opacity(0.18), stroke: .clear,
                                 radius: 5, tracking: 0.12, hPad: 5, vPad: 2)
                        }
                    }
                    HStack(spacing: 8) {
                        Text("\(node.id) · \(node.region)").mono(10, .regular).foregroundStyle(Tok.dim(0.45)).lineLimit(1).fixedSize()
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.white.opacity(0.1))
                            Capsule().fill(Tok.signal).frame(width: 34 * CGFloat(node.load) / 100)
                        }
                        .frame(width: 34, height: 3)
                        .accessibilityLabel("Load \(node.load) percent")
                    }
                }
                Spacer(minLength: 0)
                HStack(alignment: .bottom, spacing: 1.5) {
                    ForEach(Array(MockTelemetry.sparkline(row: index, tick: store.tick).enumerated()), id: \.offset) { _, h in
                        RoundedRectangle(cornerRadius: 1).fill(selected ? Tok.signal : Tok.dim(0.35)).frame(width: 2, height: h)
                    }
                }
                .frame(height: 16, alignment: .bottom)
                .accessibilityHidden(true)
                VStack(alignment: .trailing, spacing: 0) {
                    Text("\(node.ms)").mono(14, .semibold).foregroundStyle(Tok.tone(node.rttTone))
                    Text("ms").mono(9, .regular).foregroundStyle(Tok.dim(0.4))
                }
                .frame(width: 34, alignment: .trailing)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 11)
            .background {
                if selected {
                    LinearGradient(colors: [Tok.signal.opacity(0.12), Tok.signal.opacity(0.02)], startPoint: .leading, endPoint: .trailing)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .sensoryFeedback(.selection, trigger: selected)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(node.city), \(node.id), \(node.ms) milliseconds")
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }
}
