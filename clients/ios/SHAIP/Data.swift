import Foundation

// MARK: - Exact data from SHAIP iOS.dc.html

struct Server: Identifiable {
    let code: String
    let city: String
    let nodeId: String   // the design's `id` field
    let ms: Int
    let load: Int
    let ip: String
    var id: String { code }
}

// SERVERS
let SERVERS: [Server] = [
    Server(code: "SYD", city: "Sydney",      nodeId: "SYD-03 · EQX SY4",  ms: 14,  load: 42, ip: "203.0.113.42"),
    Server(code: "MEL", city: "Melbourne",   nodeId: "MEL-01 · NXT M2",   ms: 22,  load: 31, ip: "203.0.113.87"),
    Server(code: "AKL", city: "Auckland",    nodeId: "AKL-02",            ms: 38,  load: 18, ip: "198.51.100.9"),
    Server(code: "SIN", city: "Singapore",   nodeId: "SIN-01 · RELAY",    ms: 92,  load: 64, ip: "198.51.100.140"),
    Server(code: "TYO", city: "Tokyo",       nodeId: "TYO-04",            ms: 118, load: 57, ip: "192.0.2.61"),
    Server(code: "LAX", city: "Los Angeles", nodeId: "LAX-02",            ms: 146, load: 49, ip: "192.0.2.200"),
    Server(code: "FRA", city: "Frankfurt",   nodeId: "FRA-01 · DEDICATED", ms: 268, load: 22, ip: "192.0.2.18"),
]

struct Proto: Identifiable {
    let k: String
    let name: String
    let tag: String
    let sub: String
    var id: String { k }
}

// PROTOS
let PROTOS: [Proto] = [
    Proto(k: "mesh", name: "SHAIP Mesh",    tag: "RECOMMENDED", sub: "WireGuard core · multi-hop · PQ handshake"),
    Proto(k: "wg",   name: "WireGuard",     tag: "",            sub: "UDP 51820 · ChaCha20-Poly1305"),
    Proto(k: "ike",  name: "IKEv2 / IPsec", tag: "",            sub: "AES-256-GCM · native iOS fallback"),
]

// CITIES (lat, lon) — 12 globe hubs: SYD, SIN, TYO, FRA, LON, NYC, SFO, GRU, BOM, AKL, YYZ, DXB
let CITIES: [(Double, Double)] = [
    (-33.9, 151.2), (1.3, 103.8), (35.7, 139.7), (50.1, 8.7), (51.5, -0.1), (40.7, -74),
    (37.8, -122.4), (-23.5, -46.6), (19, 72.8), (-36.8, 174.7), (43.7, -79.4), (25.2, 55.3),
]

// ARCS between hubs
let ARCS: [(Int, Int)] = [
    (0, 1), (0, 2), (1, 3), (3, 4), (4, 5), (5, 6), (0, 9), (1, 8), (8, 11), (11, 3), (6, 2), (5, 7),
]

// Tab bar — the design's 4 items. Icons map to SF Symbols per the handoff README's Assets section
// (shield, globe, waveform.path.ecg, slider.horizontal.3).
let TABS: [(label: String, symbol: String)] = [
    ("Connect", "shield"),
    ("Network", "globe"),
    ("Traffic", "waveform.path.ecg"),
    ("Settings", "slider.horizontal.3"),
]
