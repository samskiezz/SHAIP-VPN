import SwiftUI
import Charts
import SHAIPCore

/// 05 Traffic: live throughput (48 samples at 1 Hz, 0–220 Mbps), session tiles and per-app usage.
struct TrafficView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let on = store.connected, t = store.telemetry
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.signal, size: 440, x: -200, y: 40, opacity: 0.14)]) {
            VStack(spacing: 10) {
                LargeTitle(title: "Traffic") {
                    HStack(spacing: 6) {
                        GlowDot(color: on ? Tok.ok : Tok.threat)
                        // The handoff said LIVE even while disconnected.
                        Text("\(on ? "LIVE" : "OFFLINE") · \(store.node.id)").mono(10, .medium).em(0.14, of: 10)
                            .foregroundStyle(on ? Tok.ok : Tok.threat)
                    }
                    .accessibilityElement(children: .combine)
                }
                .padding(.bottom, 4)

                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Eyebrow("THROUGHPUT ↓", size: 9, tracking: 0.16, color: Tok.dim(0.45))
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                Text(on ? Format.fixed(t.downMbps, 1) : "0.0").ui(52, .semibold, relativeTo: .largeTitle).em(-0.045, of: 52)
                                    .monospacedDigit().foregroundStyle(Tok.ink).contentTransition(.numericText())
                                Text("Mbps").mono(13, .medium).foregroundStyle(Tok.ink2)
                            }
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("Download \(on ? Format.fixed(t.downMbps, 1) : "0") megabits per second")
                        Spacer()
                        VStack(alignment: .trailing, spacing: 6) {
                            Text("↑ \(on ? Format.fixed(t.upMbps, 1) : "0.0")").mono(11, .medium).foregroundStyle(Tok.steelInk).monospacedDigit()
                            // The real window peak (the handoff hard-coded 212.4, above the curve's maximum).
                            Text("PK \(Format.fixed(store.history.peak, 1))").mono(11, .medium).foregroundStyle(Tok.dim(0.45)).monospacedDigit()
                        }
                        .padding(.top, 2)
                    }
                    ThroughputChart(history: store.history)
                        .frame(height: 150)
                    HStack {
                        Text("T-48s"); Spacer(); Text("T-24s"); Spacer(); Text("NOW")
                    }
                    .mono(9, .regular).em(0.1, of: 9).foregroundStyle(Tok.dim(0.38))
                    .accessibilityHidden(true)
                }
                .padding(.horizontal, 18).padding(.top, 18).padding(.bottom, 14)
                .glassCard(30)

                HStack(spacing: 8) {
                    tile("SESSION", on ? Format.fixed(t.sessionGB, 2) : "0.00", "GB")
                    tile("JITTER", on ? Format.fixed(t.jitterMs, 1) : "—", "ms")
                    tile("PACKETS", on ? Format.fixed(t.packetsM, 2) : "0.00", "M")
                }

                VStack(spacing: 0) {
                    ForEach(Array(Catalog.apps.enumerated()), id: \.element.id) { i, app in
                        VStack(alignment: .leading, spacing: 7) {
                            HStack(alignment: .firstTextBaseline) {
                                Text(app.name).ui(14, .semibold).foregroundStyle(Tok.ink)
                                Text(app.host).mono(10, .regular).foregroundStyle(Tok.dim(0.4)).lineLimit(1)
                                Spacer(minLength: 8)
                                Text(app.value).mono(12, .medium).foregroundStyle(Tok.ink)
                            }
                            GeometryReader { g in
                                ZStack(alignment: .leading) {
                                    Capsule().fill(Color.white.opacity(0.07))
                                    Capsule().fill(Tok.tone(app.tone)).frame(width: g.size.width * app.share)
                                        .shadow(color: Tok.tone(app.tone), radius: 4)
                                }
                            }
                            .frame(height: 3)
                        }
                        .padding(.vertical, 11)
                        .overlay(alignment: .top) { if i > 0 { Hairline() } }
                        .accessibilityElement(children: .combine)
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 4)
                .glassCard(26, .tile)
            }
        }
        .animation(.easeInOut(duration: 0.55), value: on)
        .pushedScreenChrome()
    }

    private func tile(_ label: String, _ value: String, _ unit: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).mono(9, .medium).em(0.14, of: 9).foregroundStyle(Tok.ink3)
            HStack(alignment: .firstTextBaseline, spacing: 3) {
                Text(value).ui(20, .semibold, relativeTo: .title3).em(-0.03, of: 20).monospacedDigit().foregroundStyle(Tok.ink)
                    .lineLimit(1).minimumScaleFactor(0.7)
                Text(unit).mono(10, .regular).foregroundStyle(Tok.dim(0.45))
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassCard(22, .tile)
        .accessibilityElement(children: .combine)
    }
}

/// The throughput chart, layered as the handoff specifies: dashed gridlines, an area fill (signal
/// 34% → 0), a 3 pt blurred glow line, the 1.6 pt line with a horizontal gradient (signal 15% →
/// signal → white at "now"), and the dashed steel upload line.
private struct ThroughputChart: View {
    let history: ThroughputHistory

    private struct Sample: Identifiable {
        let t: Double, down: Double, up: Double
        var id: Double { t }
    }

    private var samples: [Sample] {
        (0..<history.down.count).map { Sample(t: Double($0), down: history.down[$0], up: history.up[$0]) }
    }

    var body: some View {
        let data = samples
        ZStack {
            // Glow: the same line, thicker and blurred (σ 3), under the crisp layers.
            Chart(data) { s in
                LineMark(x: .value("t", s.t), y: .value("down", s.down))
                    .interpolationMethod(.monotone)
                    .lineStyle(StrokeStyle(lineWidth: 3))
                    .foregroundStyle(Tok.signal)
            }
            .chartXScale(domain: 0.0...47.0)
            .chartYScale(domain: 0.0...220.0)
            .chartXAxis(.hidden)
            .chartYAxis(.hidden)
            .chartLegend(.hidden)
            .blur(radius: 3)
            .opacity(0.5)

            Chart(data) { s in
                AreaMark(x: .value("t", s.t), y: .value("down", s.down))
                    .interpolationMethod(.monotone)
                    .foregroundStyle(LinearGradient(colors: [Tok.signal.opacity(0.34), Tok.signal.opacity(0)], startPoint: .top, endPoint: .bottom))
                LineMark(x: .value("t", s.t), y: .value("down", s.down), series: .value("series", "down"))
                    .interpolationMethod(.monotone)
                    .lineStyle(StrokeStyle(lineWidth: 1.6, lineCap: .round, lineJoin: .round))
                    .foregroundStyle(LinearGradient(stops: [.init(color: Tok.signal.opacity(0.15), location: 0),
                                                            .init(color: Tok.signal, location: 0.7),
                                                            .init(color: .white, location: 1)],
                                                    startPoint: .leading, endPoint: .trailing))
                LineMark(x: .value("t", s.t), y: .value("up", s.up), series: .value("series", "up"))
                    .interpolationMethod(.monotone)
                    .lineStyle(StrokeStyle(lineWidth: 1.2, dash: [2, 3]))
                    .foregroundStyle(Tok.steel)
            }
            .chartXScale(domain: 0.0...47.0)
            .chartYScale(domain: 0.0...220.0)
            .chartLegend(.hidden)
            .chartYAxis {
                AxisMarks(values: [55.0, 110.0, 165.0]) { _ in
                    AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5, dash: [2, 3])).foregroundStyle(Color.white.opacity(0.07))
                }
            }
            .chartXAxis {
                AxisMarks(values: (1...5).map { Double($0) * 47 / 6 }) { _ in
                    AxisGridLine(stroke: StrokeStyle(lineWidth: 0.5)).foregroundStyle(Color.white.opacity(0.04))
                }
            }
        }
        .accessibilityElement()
        .accessibilityLabel("Throughput, last 48 seconds")
        .accessibilityValue("Peak \(Format.fixed(history.peak, 1)) megabits per second")
    }
}
