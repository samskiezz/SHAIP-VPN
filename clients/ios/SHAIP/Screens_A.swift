import SwiftUI

// Tab tap (0…3) → page index in the paged app shell.
let TAB_TO_PAGE = [1, 2, 4, 5]   // Connect, Network, Traffic, Settings(Protocol)

// MARK: - 01 Onboarding

struct OnboardingView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        Screen(t: t) {
            Blob(color: t.a1, size: 440, opacity: t.blob).place(top: -60, left: -140)
            Blob(color: t.a2, size: 400, opacity: t.blob).place(top: 260, left: 150)
            SceneCanvas(mode: "net", connected: state.connected, tokens: t, density: Int(state.density))
                .place(top: 70, left: 0, width: 390, height: 440)

            VStack(spacing: 0) {
                Spacer(minLength: 0)
                VStack(alignment: .leading, spacing: 22) {
                    Text("SHAIP / SECURE MESH ACCESS").font(.mono(12, .medium)).tracking(1.68).foregroundStyle(t.c1)
                    Text("Zero-trust access for every device on your team.")
                        .font(.ui(38, .semibold)).tracking(-1.33).lineSpacing(2).foregroundStyle(t.ink)
                    Text("Encrypted tunnels, identity-aware routing and posture checks, managed from one workspace.")
                        .font(.ui(15)).lineSpacing(7).foregroundStyle(t.sub)
                    VStack(spacing: 10) {
                        Text("Continue with SSO").font(.ui(17, .semibold)).foregroundStyle(t.bg)
                            .frame(maxWidth: .infinity).frame(height: 56)
                            .background(RoundedRectangle(cornerRadius: 28, style: .continuous).fill(t.ink))
                            .onTapGesture { page = 1 }
                        Text("Enter workspace URL").font(.ui(17, .medium)).foregroundStyle(t.ink)
                            .frame(maxWidth: .infinity).frame(height: 56)
                            .glass(t, radius: 28)
                    }
                    .padding(.top, 6)
                    HStack(spacing: 6) {
                        Capsule().fill(t.ink).frame(width: 20, height: 6)
                        Capsule().fill(t.track).frame(width: 6, height: 6)
                        Capsule().fill(t.track).frame(width: 6, height: 6)
                    }
                    .frame(maxWidth: .infinity)
                }
                .padding(.horizontal, 28)
                .padding(.bottom, 44)
            }
            .frame(width: 390, height: 844)
        }
    }
}

// MARK: - 02 Connect

struct ConnectView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        let on = state.connected
        let srv = state.server
        let dot = on ? t.good : t.bad
        Screen(t: t) {
            Blob(color: on ? t.a1 : Color(hex: "#6B7080"), size: 440, opacity: t.blob)
                .place(top: 40, left: -120).animation(.easeInOut(duration: 0.6), value: on)
            Blob(color: on ? t.a2 : Color(hex: "#4A4F5C"), size: 380, opacity: t.blob)
                .place(top: 344, left: 160).animation(.easeInOut(duration: 0.6), value: on)

            // header
            HStack {
                HStack(spacing: 10) {
                    Text("A").font(.ui(13, .bold)).foregroundStyle(t.bg)
                        .frame(width: 32, height: 32)
                        .background(Circle().fill(t.ink))
                    Text("Acme Corp").font(.ui(15, .semibold)).foregroundStyle(t.ink)
                    Text("PROD").font(.mono(12, .medium)).foregroundStyle(t.sub)
                }
                .padding(.leading, 6).padding(.trailing, 16).frame(height: 44)
                .glass(t, radius: 22)
                Spacer()
                Image(systemName: "bell").font(.system(size: 20)).foregroundStyle(t.ink)
                    .frame(width: 44, height: 44).glass(t, radius: 22)
            }
            .place(top: 62, left: 20, width: 350)

            SceneCanvas(mode: "net", connected: on, tokens: t, density: Int(state.density))
                .place(top: 110, left: 0, width: 390, height: 330)

            // connect orb
            Button {
                state.connected.toggle(); state.haptic()
            } label: {
                VStack(spacing: 4) {
                    Image(systemName: "power").font(.system(size: 30, weight: .bold))
                        .foregroundStyle(on ? t.c1 : t.sub)
                    Text(on ? "TAP TO STOP" : "TAP TO START").font(.mono(11, .medium)).tracking(0.88).foregroundStyle(t.sub)
                }
                .frame(width: 128, height: 128)
                .glass(t, radius: 64)
                .overlay(
                    Circle().strokeBorder(on ? rgba(t.c1Hex, 0.12) : Color(hex: "#808080", opacity: 0.08), lineWidth: 10)
                        .frame(width: 148, height: 148)
                )
                .animation(.easeInOut(duration: 0.4), value: on)
            }
            .buttonStyle(.plain)
            .place(top: 211, left: 131)

            // status card
            VStack(spacing: 14) {
                HStack {
                    HStack(spacing: 8) {
                        Circle().fill(dot).frame(width: 7, height: 7)
                        Text(on ? "PROTECTED" : "NOT PROTECTED").font(.mono(11, .semibold)).tracking(1.1).foregroundStyle(dot)
                    }
                    .padding(.horizontal, 10).frame(height: 26)
                    .background(Capsule().fill(dot.opacity(0.14)))
                    Spacer()
                    Text(sessionTimer(on, state.t)).font(.mono(15)).monospacedDigit().foregroundStyle(t.ink)
                }
                HStack(alignment: .bottom) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(on ? srv.city : "Disconnected").font(.ui(24, .semibold)).tracking(-0.48).foregroundStyle(t.ink)
                        Text("\(srv.nodeId.components(separatedBy: " ")[0]) · \(state.protoName)").font(.mono(12)).foregroundStyle(t.sub)
                    }
                    Spacer()
                    VStack(alignment: .trailing, spacing: 4) {
                        Text("EXIT IP").font(.mono(11)).foregroundStyle(t.sub)
                        Text(on ? srv.ip : "—").font(.mono(13, .medium)).foregroundStyle(t.ink)
                    }
                }
            }
            .padding(.horizontal, 20).padding(.vertical, 18)
            .frame(width: 350, alignment: .leading)
            .glass(t, radius: 28, shadow: true)
            .place(top: 450, left: 20)

            // stat tiles
            HStack(spacing: 10) {
                statTile(t, "DOWN", on ? String(Int(f(state.t))) : "—", "Mbps")
                statTile(t, "UP", on ? String(Int(g(state.t))) : "—", "Mbps")
                statTile(t, "LATENCY", on ? String(srv.ms + jitter(state.t)) : "—", "ms")
            }
            .frame(width: 350)
            .place(top: 610, left: 20)

            FloatingTabBar(t: t, active: 0, onSelect: { page = TAB_TO_PAGE[$0] })
        }
    }

    private func statTile(_ t: Tokens, _ label: String, _ value: String, _ unit: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.mono(10, .medium)).tracking(1).foregroundStyle(t.sub)
            Text(value).font(.ui(20, .semibold)).tracking(-0.4).monospacedDigit().foregroundStyle(t.ink)
            Text(unit).font(.mono(11)).foregroundStyle(t.sub)
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading)
        .glass(t, radius: 22)
    }
}

// MARK: - 03 Network globe

struct NetworkView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        let srv = state.server
        Screen(t: t) {
            Blob(color: t.a2, size: 460, opacity: t.blob, blur: 120).place(top: 120, left: -35)

            VStack(alignment: .leading, spacing: 4) {
                Text("Network").font(.ui(34, .bold)).tracking(-1.02).foregroundStyle(t.ink)
                Text("42 EDGE NODES · 18 REGIONS · 12 ACTIVE ROUTES").font(.mono(12)).foregroundStyle(t.sub)
            }
            .place(top: 66, left: 24, width: 342)

            SceneCanvas(mode: "globe", connected: state.connected, tokens: t, density: Int(state.density))
                .place(top: 140, left: 0, width: 390, height: 400)

            // floating chip (right 20)
            HStack {
                Spacer()
                HStack(spacing: 8) {
                    Circle().fill(state.connected ? t.good : t.bad).frame(width: 7, height: 7)
                    Text("\(srv.nodeId.components(separatedBy: " ")[0]) · \(srv.ms + jitter(state.t)) ms").font(.mono(12)).foregroundStyle(t.ink)
                }
                .padding(.horizontal, 12).frame(height: 34)
                .glass(t, radius: 17)
            }
            .place(top: 176, left: 20, width: 350)

            // active route card
            VStack(spacing: 14) {
                HStack {
                    Text("Active route").font(.ui(17, .semibold)).foregroundStyle(t.ink)
                    Spacer()
                    Text("MULTI-HOP").font(.mono(11, .medium)).foregroundStyle(t.c1)
                }
                VStack(spacing: 10) {
                    routeRow(t, "iPhone 17 Pro", "10.84.12.7", filled: true)
                    routeRow(t, "\(srv.city) edge", "\(srv.code) · \(srv.ms) ms", filled: true)
                    routeRow(t, "Singapore relay", "SIN-01 · +41 ms", filled: false)
                    routeRow(t, "Acme VPC", "ap-southeast-2", filled: false)
                }
            }
            .padding(.horizontal, 20).padding(.vertical, 18)
            .frame(width: 350, alignment: .leading)
            .glass(t, radius: 28, shadow: true)
            .place(top: 548, left: 20)

            FloatingTabBar(t: t, active: 1, onSelect: { page = TAB_TO_PAGE[$0] })
        }
    }

    private func routeRow(_ t: Tokens, _ name: String, _ meta: String, filled: Bool) -> some View {
        HStack(spacing: 12) {
            Circle().strokeBorder(t.c1, lineWidth: 2).background(Circle().fill(filled ? t.c1 : .clear))
                .frame(width: 10, height: 10)
            Text(name).font(.ui(14)).foregroundStyle(t.ink)
            Spacer()
            Text(meta).font(.mono(12)).foregroundStyle(t.sub)
        }
    }
}

// MARK: - 04 Nodes

struct NodesView: View {
    @EnvironmentObject var state: AppState
    @Binding var page: Int

    var body: some View {
        let t = state.tokens
        Screen(t: t) {
            Blob(color: t.a1, size: 420, opacity: t.blob).place(top: -80, left: 150)
            Blob(color: t.a2, size: 380, opacity: t.blob).place(top: 424, left: -180)

            VStack(alignment: .leading, spacing: 14) {
                Text("Nodes").font(.ui(34, .bold)).tracking(-1.02).foregroundStyle(t.ink).padding(.leading, 4)

                // search
                HStack(spacing: 10) {
                    Image(systemName: "magnifyingglass").font(.system(size: 16)).foregroundStyle(t.sub)
                    Text("Search region, city or node ID").font(.ui(15)).foregroundStyle(t.sub)
                    Spacer()
                }
                .padding(.horizontal, 16).frame(height: 44).glass(t, radius: 22)

                // segmented
                HStack(spacing: 0) {
                    ForEach(Array(["Recommended", "Regions", "Dedicated"].enumerated()), id: \.offset) { i, label in
                        let sel = i == state.seg
                        Text(label).font(.ui(13, .semibold))
                            .foregroundStyle(sel ? t.ink : t.sub)
                            .frame(maxWidth: .infinity).frame(height: 34)
                            .background(
                                RoundedRectangle(cornerRadius: 17, style: .continuous)
                                    .fill(sel ? (t.dark ? Color.white.opacity(0.14) : Color.white) : .clear)
                                    .shadow(color: sel ? .black.opacity(0.12) : .clear, radius: 4, y: 2)
                            )
                            .contentShape(Rectangle())
                            .onTapGesture { state.seg = i }
                    }
                }
                .padding(3).glass(t, radius: 20)

                // list card
                VStack(spacing: 0) {
                    ForEach(Array(SERVERS.enumerated()), id: \.offset) { i, s in
                        serverRow(t, i, s)
                    }
                }
                .glass(t, radius: 28, shadow: true)
                .clipShape(RoundedRectangle(cornerRadius: 28, style: .continuous))
            }
            .padding(.horizontal, 20)
            .place(top: 66, left: 0, width: 390)

            FloatingTabBar(t: t, active: 1, onSelect: { page = TAB_TO_PAGE[$0] })
        }
    }

    private func serverRow(_ t: Tokens, _ i: Int, _ s: Server) -> some View {
        let sel = i == state.srv
        let msColor = s.ms < 50 ? t.good : (s.ms < 150 ? t.warn : t.bad)
        return HStack(spacing: 12) {
            Text(s.code).font(.mono(12, .semibold)).foregroundStyle(sel ? Color(hex: "#05060A") : t.ink)
                .frame(width: 44, height: 44)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(sel ? t.c1 : t.glass))
            VStack(alignment: .leading, spacing: 5) {
                Text(s.city).font(.ui(15, .semibold)).foregroundStyle(t.ink)
                HStack(spacing: 8) {
                    Text(s.nodeId).font(.mono(11)).foregroundStyle(t.sub).lineLimit(1)
                    ZStack(alignment: .leading) {
                        Capsule().fill(t.track).frame(width: 40, height: 4)
                        Capsule().fill(t.ink.opacity(0.7)).frame(width: 40 * CGFloat(s.load) / 100, height: 4)
                    }
                }
            }
            Spacer()
            Text("\(s.ms) ms").font(.mono(13, .medium)).foregroundStyle(msColor)
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .background(sel ? rgba(t.c1Hex, 0.1) : Color.clear)
        .overlay(alignment: .top) { if i != 0 { Rectangle().fill(t.div).frame(height: 1) } }
        .contentShape(Rectangle())
        .onTapGesture { state.srv = i; state.connected = true; state.haptic() }
    }
}
