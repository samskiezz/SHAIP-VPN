import SwiftUI

// Chart paths (318×120, 40 samples, y-scale 0–220 Mbps) from renderVals().
private func chartPath(_ fn: @escaping (Int) -> Double, _ t: Int) -> Path {
    var p = Path()
    for i in 0..<40 {
        let x = Double(i) * 318.0 / 39.0
        let y = 118.0 - fn(t - 39 + i) / 220.0 * 110.0
        if i == 0 { p.move(to: CGPoint(x: x, y: y)) } else { p.addLine(to: CGPoint(x: x, y: y)) }
    }
    return p
}
private func areaPath(_ fn: @escaping (Int) -> Double, _ t: Int) -> Path {
    var p = chartPath(fn, t)
    p.addLine(to: CGPoint(x: 318, y: 120))
    p.addLine(to: CGPoint(x: 0, y: 120))
    p.closeSubpath()
    return p
}
private let zeroFn: (Int) -> Double = { _ in 0 }

// MARK: - 05 Live traffic

struct TrafficView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        let on = state.connected
        let srv = state.server
        Screen(t: t) {
            Blob(color: t.a1, size: 420, opacity: t.blob).place(top: 60, left: -140)
            Blob(color: t.a2, size: 360, opacity: t.blob).place(top: 344, left: 170)

            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Traffic").font(.ui(34, .bold)).tracking(-1.02).foregroundStyle(t.ink)
                    Spacer()
                    Text("● LIVE · \(srv.nodeId.components(separatedBy: " ")[0])").font(.mono(12, .medium)).foregroundStyle(on ? t.good : t.bad)
                }
                .padding(.horizontal, 4)

                // chart card
                VStack(alignment: .leading, spacing: 6) {
                    Text("DOWNLOAD").font(.mono(11, .medium)).tracking(1.1).foregroundStyle(t.sub)
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text(on ? String(format: "%.1f", f(state.t)) : "0.0").font(.ui(44, .semibold)).tracking(-1.76).monospacedDigit().foregroundStyle(t.ink)
                        Text("Mbps").font(.mono(14, .medium)).foregroundStyle(t.sub)
                    }
                    ZStack(alignment: .topLeading) {
                        Path { p in for y in [30.0, 60, 90] { p.move(to: CGPoint(x: 0, y: y)); p.addLine(to: CGPoint(x: 318, y: y)) } }
                            .stroke(t.track, lineWidth: 1)
                        areaPath(on ? f : zeroFn, state.t).fill(t.soft)
                        chartPath(on ? f : zeroFn, state.t).stroke(t.c1, style: StrokeStyle(lineWidth: 2, lineJoin: .round))
                        chartPath(on ? g : zeroFn, state.t).stroke(t.c2, style: StrokeStyle(lineWidth: 1.6, dash: [3, 3]))
                    }
                    .frame(width: 318, height: 120)
                    .padding(.top, 4)
                    HStack(spacing: 16) {
                        Text("━ down").font(.mono(11)).foregroundStyle(t.c1)
                        Text("┅ up").font(.mono(11)).foregroundStyle(t.c2)
                        Spacer()
                        Text("last 40s").font(.mono(11)).foregroundStyle(t.sub)
                    }
                }
                .padding(.horizontal, 18).padding(.top, 18).padding(.bottom, 12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .glass(t, radius: 28, shadow: true)

                // 2×2 tiles
                let tiles: [(String, String, String)] = [
                    ("UPLOAD", on ? String(format: "%.1f", g(state.t)) : "0.0", "Mbps"),
                    ("LATENCY", on ? String(srv.ms + jitter(state.t)) : "—", "ms"),
                    ("PACKET LOSS", on ? "0.02" : "—", "%"),
                    ("SESSION", on ? String(format: "%.2f", 2.41 + Double(state.t) * 0.018) : "0.00", "GB"),
                ]
                let cols = [GridItem(.flexible(), spacing: 10), GridItem(.flexible(), spacing: 10)]
                LazyVGrid(columns: cols, spacing: 10) {
                    ForEach(Array(tiles.enumerated()), id: \.offset) { _, s in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(s.0).font(.mono(10, .medium)).tracking(1).foregroundStyle(t.sub)
                            HStack(alignment: .firstTextBaseline, spacing: 4) {
                                Text(s.1).font(.ui(22, .semibold)).tracking(-0.44).monospacedDigit().foregroundStyle(t.ink)
                                Text(s.2).font(.mono(11)).foregroundStyle(t.sub)
                            }
                        }
                        .padding(.horizontal, 16).padding(.vertical, 14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .glass(t, radius: 22)
                    }
                }

                // top destinations
                VStack(spacing: 0) {
                    ForEach(Array([("git.acme.internal", "1.2 GB"), ("rds.ap-southeast-2", "640 MB"), ("slack.com", "212 MB")].enumerated()), id: \.offset) { i, d in
                        HStack {
                            Text(d.0).font(.mono(13)).foregroundStyle(t.ink)
                            Spacer()
                            Text(d.1).font(.mono(13, .medium)).foregroundStyle(t.sub)
                        }
                        .padding(.vertical, 9)
                        .overlay(alignment: .top) { if i != 0 { Rectangle().fill(t.div).frame(height: 1) } }
                    }
                }
                .padding(.horizontal, 16).padding(.vertical, 6)
                .glass(t, radius: 24)
            }
            .padding(.horizontal, 20)
            .place(top: 66, left: 0, width: 390)

            FloatingTabBar(t: t, active: 2, onSelect: { page = TAB_TO_PAGE[$0] })
        }
    }
}

// MARK: - 06 Protocol

struct ProtocolView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        Screen(t: t) {
            Blob(color: t.a2, size: 420, opacity: t.blob).place(top: 100, left: 130)
            Blob(color: t.a1, size: 360, opacity: t.blob).place(top: 424, left: -160)

            VStack(alignment: .leading, spacing: 12) {
                Text("Protocol").font(.ui(34, .bold)).tracking(-1.02).foregroundStyle(t.ink).padding(.leading, 4)

                ForEach(PROTOS) { p in
                    let sel = p.k == state.proto
                    HStack(spacing: 12) {
                        VStack(alignment: .leading, spacing: 4) {
                            HStack(spacing: 8) {
                                Text(p.name).font(.ui(16, .semibold)).foregroundStyle(t.ink)
                                if !p.tag.isEmpty { Text(p.tag).font(.mono(10, .medium)).foregroundStyle(t.c1) }
                            }
                            Text(p.sub).font(.mono(12)).foregroundStyle(t.sub)
                        }
                        Spacer()
                        Circle().strokeBorder(sel ? t.c1 : t.track, lineWidth: 2)
                            .background(Circle().fill(sel ? t.c1 : .clear).frame(width: 10, height: 10))
                            .frame(width: 22, height: 22)
                    }
                    .padding(.horizontal, 18).padding(.vertical, 16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .glass(t, radius: 24)
                    .overlay(RoundedRectangle(cornerRadius: 24, style: .continuous).strokeBorder(sel ? t.c1 : t.stroke, lineWidth: 1))
                    .overlay {
                        if sel {
                            RoundedRectangle(cornerRadius: 24, style: .continuous)
                                .strokeBorder(rgba(t.c1Hex, 0.14), lineWidth: 4).padding(-2)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { state.proto = p.k }
                }

                Text("TUNNEL").font(.mono(11, .medium)).tracking(1.32).foregroundStyle(t.sub).padding(.horizontal, 6).padding(.top, 8)

                VStack(spacing: 0) {
                    toggleRow(t, "Split tunneling", "Route only corporate subnets", on: state.split, first: true) { state.split.toggle() }
                    toggleRow(t, "Private DNS", "Encrypted resolver, blocks trackers", on: state.dns, first: false) { state.dns.toggle() }
                    toggleRow(t, "Device posture checks", "OS version, disk encryption", on: state.posture, first: false) { state.posture.toggle() }
                    toggleRow(t, "Always-on", "Reconnect on network change", on: state.alwaysOn, first: false) { state.alwaysOn.toggle() }
                }
                .padding(.horizontal, 18).padding(.vertical, 2)
                .glass(t, radius: 24)
            }
            .padding(.horizontal, 20)
            .place(top: 66, left: 0, width: 390)

            FloatingTabBar(t: t, active: 3, onSelect: { page = TAB_TO_PAGE[$0] })
        }
    }

    private func toggleRow(_ t: Tokens, _ label: String, _ sub: String, on: Bool, first: Bool, tap: @escaping () -> Void) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.ui(15, .medium)).foregroundStyle(t.ink)
                Text(sub).font(.ui(12)).foregroundStyle(t.sub)
            }
            Spacer()
            IOSSwitch(on: on, onColor: t.good, track: t.track).onTapGesture(perform: tap)
        }
        .padding(.vertical, 12)
        .overlay(alignment: .top) { if !first { Rectangle().fill(t.div).frame(height: 1) } }
    }
}

// MARK: - 07 Account & plan

struct AccountView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        let on = state.connected
        Screen(t: t) {
            Blob(color: t.a1, size: 460, opacity: t.blob).place(top: -180, left: -35)
            Blob(color: t.a2, size: 360, opacity: t.blob).place(top: 384, left: 190)

            VStack(alignment: .leading, spacing: 14) {
                VStack(spacing: 8) {
                    Text("MC").font(.ui(28, .semibold)).foregroundStyle(t.ink)
                        .frame(width: 84, height: 84).glass(t, radius: 42)
                        .overlay(Circle().strokeBorder(t.soft, lineWidth: 6).frame(width: 96, height: 96))
                    Text("Maya Chen").font(.ui(22, .semibold)).tracking(-0.44).foregroundStyle(t.ink)
                    Text("SECURITY ADMIN · ACME CORP").font(.mono(12)).foregroundStyle(t.sub)
                }
                .frame(maxWidth: .infinity).padding(.bottom, 6)

                VStack(spacing: 12) {
                    HStack {
                        Text("Business · Annual").font(.ui(17, .semibold)).foregroundStyle(t.ink)
                        Spacer()
                        Text("ACTIVE").font(.mono(11, .medium)).foregroundStyle(t.c1)
                    }
                    HStack { Text("SEATS").font(.mono(12)).foregroundStyle(t.sub); Spacer(); Text("148 / 200").font(.mono(12)).foregroundStyle(t.ink) }
                    ZStack(alignment: .leading) {
                        Capsule().fill(t.track).frame(height: 6)
                        GeometryReader { g in Capsule().fill(t.c1).frame(width: g.size.width * 0.74, height: 6) }.frame(height: 6)
                    }
                    HStack { Text("RENEWS").font(.mono(12)).foregroundStyle(t.sub); Spacer(); Text("14 MAR 2027").font(.mono(12)).foregroundStyle(t.ink) }
                }
                .padding(.horizontal, 20).padding(.vertical, 18)
                .glass(t, radius: 28, shadow: true)

                Text("YOUR DEVICES").font(.mono(11, .medium)).tracking(1.32).foregroundStyle(t.sub).padding(.horizontal, 6).padding(.top, 4)

                VStack(spacing: 0) {
                    deviceRow(t, "iPhone 17 Pro", "iOS 26.1 · this device", on ? "CONNECTED" : "IDLE", on ? t.good : t.sub, first: true)
                    deviceRow(t, "MacBook Pro 14\"", "macOS 26 · Sydney", "CONNECTED", t.good, first: false)
                    deviceRow(t, "iPad Air", "iPadOS 26 · last seen 3d", "IDLE", t.sub, first: false)
                }
                .padding(.horizontal, 18).padding(.vertical, 2)
                .glass(t, radius: 24)

                Text("Manage workspace").font(.ui(16, .semibold)).foregroundStyle(t.bg)
                    .frame(maxWidth: .infinity).frame(height: 52)
                    .background(RoundedRectangle(cornerRadius: 26, style: .continuous).fill(t.ink))
            }
            .padding(.horizontal, 20)
            .place(top: 76, left: 0, width: 390)

            FloatingTabBar(t: t, active: 3, onSelect: { page = TAB_TO_PAGE[$0] })
        }
    }

    private func deviceRow(_ t: Tokens, _ name: String, _ meta: String, _ stateText: String, _ color: Color, first: Bool) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.ui(15, .medium)).foregroundStyle(t.ink)
                Text(meta).font(.mono(11)).foregroundStyle(t.sub)
            }
            Spacer()
            Text(stateText).font(.mono(11, .medium)).foregroundStyle(color)
        }
        .padding(.vertical, 13)
        .overlay(alignment: .top) { if !first { Rectangle().fill(t.div).frame(height: 1) } }
    }
}

// MARK: - 08 Kill switch & alerts

struct SecurityView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        let armed = state.kill
        Screen(t: t) {
            Blob(color: armed ? t.a1 : Color(hex: "#FF5E7A"), size: 440, opacity: t.blob)
                .place(top: 20, left: -140).animation(.easeInOut(duration: 0.5), value: armed)
            Blob(color: t.a2, size: 360, opacity: t.blob).place(top: 364, left: 190)

            VStack(alignment: .leading, spacing: 12) {
                Text("Security").font(.ui(34, .bold)).tracking(-1.02).foregroundStyle(t.ink).padding(.leading, 4)

                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(armed ? "ARMED" : "DISARMED").font(.mono(11, .semibold)).tracking(1.32).foregroundStyle(armed ? t.good : t.bad)
                            Text("Kill switch").font(.ui(24, .semibold)).tracking(-0.48).foregroundStyle(t.ink)
                        }
                        Spacer()
                        IOSSwitch(on: armed, onColor: t.good, track: t.track)
                            .onTapGesture { state.kill.toggle(); state.haptic() }
                    }
                    Text(armed
                         ? "All traffic is blocked if the tunnel drops. Enforced by workspace policy; local network stays reachable."
                         : "Traffic can leak outside the tunnel during reconnects. Your admin will be notified.")
                        .font(.ui(14)).lineSpacing(6).foregroundStyle(t.sub)
                    HStack(spacing: 8) {
                        chip(t, "POLICY · ACME-STRICT")
                        chip(t, "LAN ALLOWED")
                    }
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
                .glass(t, radius: 28, shadow: true)

                HStack(alignment: .firstTextBaseline) {
                    Text("ALERTS · LAST 24H").font(.mono(11, .medium)).tracking(1.32).foregroundStyle(t.sub)
                    Spacer()
                    Text("5").font(.mono(12, .medium)).foregroundStyle(t.c1)
                }
                .padding(.horizontal, 6).padding(.top, 8)

                VStack(spacing: 0) {
                    let alerts: [(String, String, String, Color)] = [
                        ("Tunnel renegotiated", "SYD-03 → SYD-04 · 0 packets lost", "2m", t.c1),
                        ("Untrusted Wi-Fi joined", "Cafe_Guest · auto-protected", "41m", t.warn),
                        ("Posture check passed", "iOS 26.1 · disk encrypted", "1h", t.good),
                        ("3 tracker domains blocked", "Private DNS", "3h", t.c2),
                        ("DNS leak test passed", "Resolver 10.84.0.53", "6h", t.good),
                    ]
                    ForEach(Array(alerts.enumerated()), id: \.offset) { i, al in
                        HStack(alignment: .top, spacing: 12) {
                            Circle().fill(al.3).frame(width: 8, height: 8).shadow(color: al.3, radius: 5).padding(.top, 6)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(al.0).font(.ui(14, .medium)).foregroundStyle(t.ink)
                                Text(al.1).font(.mono(11)).foregroundStyle(t.sub)
                            }
                            Spacer()
                            Text(al.2).font(.mono(11)).foregroundStyle(t.sub)
                        }
                        .padding(.vertical, 12)
                        .overlay(alignment: .top) { if i != 0 { Rectangle().fill(t.div).frame(height: 1) } }
                    }
                }
                .padding(.horizontal, 18).padding(.vertical, 2)
                .glass(t, radius: 24)
            }
            .padding(.horizontal, 20)
            .place(top: 66, left: 0, width: 390)

            FloatingTabBar(t: t, active: 3, onSelect: { page = TAB_TO_PAGE[$0] })
        }
    }

    private func chip(_ t: Tokens, _ text: String) -> some View {
        Text(text).font(.mono(11, .medium)).foregroundStyle(t.ink)
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(t.glass))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(t.stroke, lineWidth: 1))
    }
}
