import SwiftUI
import Charts
import SHAIPCore

/// Traffic: the measured throughput (48 samples at 1 Hz, from the tunnel's
/// byte counters), session totals, and the tunnel's own health counters.
struct TrafficView: View {
    @Environment(TunnelStore.self) private var store

    var body: some View {
        let on = store.connected, snap = store.snapshot
        ScreenScaffold(blobs: [AmbientBlob(color: Tok.signal, size: 440, x: -200, y: 40, opacity: 0.14)]) {
            VStack(spacing: 10) {
                LargeTitle(title: "Traffic") {
                    HStack(spacing: 6) {
                        GlowDot(color: on ? Tok.ok : Tok.ink2)
                        Text(on ? "LIVE · \(store.config?.label.uppercased() ?? "")" : store.stateLabel).mono(10, .medium).em(0.14, of: 10)
                            .foregroundStyle(on ? Tok.ok : Tok.ink2).lineLimit(1)
                    }
                    .accessibilityElement(children: .combine)
                }
                .padding(.bottom, 4)

                VStack(alignment: .leading, spacing: 8) {
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 4) {
                            Eyebrow("THROUGHPUT ↓", size: 9, tracking: 0.16, color: Tok.dim(0.45))
                            HStack(alignment: .firstTextBaseline, spacing: 6) {
                                Text(on ? Format.mbps(store.downMbps) : "0.00").ui(52, .semibold, relativeTo: .largeTitle).em(-0.045, of: 52)
                                    .monospacedDigit().foregroundStyle(Tok.ink).contentTransition(.numericText())
                                Text("Mbps").mono(13, .medium).foregroundStyle(Tok.ink2)
                            }
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel("Download \(on ? Format.mbps(store.downMbps) : "0") megabits per second")
                        Spacer()
                        VStack(alignment: .trailing, spacing: 6) {
                            Text("↑ \(on ? Format.mbps(store.upMbps) : "0.00")").mono(11, .medium).foregroundStyle(Tok.steelInk).monospacedDigit()
                            Text("PK \(Format.mbps(store.history.peak))").mono(11, .medium).foregroundStyle(Tok.dim(0.45)).monospacedDigit()
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
                    let sent = Format.bytes(snap?.bytesSent ?? 0), received = Format.bytes(snap?.bytesReceived ?? 0)
                    tile("SENT", snap == nil ? "—" : sent.value, sent.unit)
                    tile("RECEIVED", snap == nil ? "—" : received.value, received.unit)
                    tile("PACKETS", snap.map { Format.count($0.packetsSent + $0.packetsReceived) } ?? "—", "")
                }

                VStack(spacing: 0) {
                    row("Round-trip time", store.rttMs.map { "\($0) ms" } ?? "—", "Keepalive ping to the server and back", first: true)
                    row("Reconnects", snap.map { "\($0.reconnects)" } ?? "—", "Sessions re-established after a failure")
                    row("Rekeys", snap.map { "\($0.rekeys)" } ?? "—", "Sessions replaced by a fresh handshake")
                    row("Rejected packets", snap.map { Format.count($0.packetsRejected) } ?? "—",
                        "Arrived but failed authentication (replays, tampering, strays)")
                    row("Held while reconnecting", snap.map { Format.count($0.droppedOffline) } ?? "—",
                        "Dropped inside the tunnel, not sent around it")
                    row("IPv6 blocked", snap.map { Format.count($0.ipv6Dropped) } ?? "—", "The tunnel carries IPv4 only")
                }
                .padding(.horizontal, 16).padding(.vertical, 2)
                .glassCard(26, .tile)
            }
        }
        .animation(.easeInOut(duration: 0.55), value: on)
        .toolbar(.hidden, for: .navigationBar)
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

    private func row(_ title: String, _ value: String, _ detail: String, first: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).ui(14, .semibold).foregroundStyle(Tok.ink)
                Text(detail).ui(11).foregroundStyle(Tok.dim(0.45)).fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Text(value).mono(13, .medium).foregroundStyle(Tok.ink).monospacedDigit()
        }
        .padding(.vertical, 10)
        .overlay(alignment: .top) { if !first { Hairline() } }
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
        let top = history.scale
        ZStack {
            // Glow: the same line, thicker and blurred (σ 3), under the crisp layers.
            Chart(data) { s in
                LineMark(x: .value("t", s.t), y: .value("down", s.down))
                    .interpolationMethod(.monotone)
                    .lineStyle(StrokeStyle(lineWidth: 3))
                    .foregroundStyle(Tok.signal)
            }
            .chartXScale(domain: 0.0...47.0)
            .chartYScale(domain: 0.0...top)
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
            .chartYScale(domain: 0.0...top)
            .chartLegend(.hidden)
            .chartYAxis {
                AxisMarks(values: [top / 4, top / 2, top * 3 / 4]) { _ in
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
        .accessibilityValue("Peak \(Format.mbps(history.peak)) megabits per second")
    }
}
