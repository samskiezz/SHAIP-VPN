// SHAIP iPhone app preview: the app's screens (clients/ios/SHAIP/Screens) rebuilt for a web
// page, over the design's own render engine (clients/ios/design/shaip-engine.js, inlined ahead
// of this file by build.sh, which provides `draw`). Copy, layout and logic follow the Swift
// views; where a Swift type is ported (ServerConfig, Format, Protection) it keeps its rules.
//
// A web page can't open a VPN tunnel, so connecting here runs a simulated session in this page.
// Nothing is stored or sent anywhere.

/* global draw, SAMPLE_CONFIG */

// ---------- Tokens (Shared/Tokens.swift) ----------
const T = {
  signal: '#5CF2FF', steel: '#8A9BB8', ok: '#62F5A8', warn: '#FFB547', threat: '#FF5C7A',
  ink: '#F5F7FC', ink2: 'rgba(220,228,255,0.5)', steelInk: '#B4C2DA',
};
const dim = a => `rgba(220,228,255,${a})`;
const alpha = (hex, a) => {
  if (!hex.startsWith('#')) return hex.replace(/[\d.]+\)$/, m => `${(parseFloat(m) * a).toFixed(3)})`);
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
};
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- Icons (SF Symbols the app uses, drawn as strokes) ----------
const ICON = {
  power: '<path d="M12 3v8M6.3 6.8a8 8 0 1011.4 0"/>',
  chart: '<path d="M4 4v16h16"/><path d="M7.5 15l3.5-4.5 3 2.5 4.5-6"/>',
  shield: '<path d="M12 3l7 2.8v5.4c0 4.4-2.9 8.2-7 9.8-4.1-1.6-7-5.4-7-9.8V5.8L12 3z"/><rect x="9.25" y="11.25" width="5.5" height="4.5" rx="1"/><path d="M10.5 11.25v-1.2a1.5 1.5 0 013 0v1.2"/>',
  server: '<rect x="4" y="4.5" width="16" height="6" rx="1.8"/><rect x="4" y="13.5" width="16" height="6" rx="1.8"/><path d="M7.5 7.5h.01M7.5 16.5h.01M11 7.5h5M11 16.5h5"/>',
  sliders: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  lock: '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 018 0v2.5"/>',
  lockOpen: '<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 017.6-1.7"/>',
  cycle: '<path d="M19.5 10.5A7.5 7.5 0 006 7.2M4.5 13.5A7.5 7.5 0 0018 16.8"/><path d="M5.5 3.5v4h4M18.5 20.5v-4h-4"/>',
  network: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.3 2.5 3.5 5.3 3.5 8.5s-1.2 6-3.5 8.5c-2.3-2.5-3.5-5.3-3.5-8.5s1.2-6 3.5-8.5z"/>',
  checkFill: '<circle cx="12" cy="12" r="9" fill="currentColor" stroke="none"/><path d="M8 12.3l2.6 2.6L16 9.5" stroke="#04050A" stroke-width="2.2"/>',
  minus: '<circle cx="12" cy="12" r="8.5"/><path d="M8 12h8"/>',
  info: '<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5.5"/><path d="M12 7.7v.1" stroke-width="2.4"/>',
  docPlus: '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z"/><path d="M14 3v5h5M12 11.5v6M9 14.5h6"/>',
  clipboard: '<rect x="8.5" y="3" width="7" height="3.5" rx="1"/><path d="M8.5 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-1.5"/>',
  download: '<path d="M12 3.5v10.5M8 10l4 4 4-4M5 14.5V19a2 2 0 002 2h10a2 2 0 002-2v-4.5"/>',
  trash: '<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l.9 12.6A1.5 1.5 0 008.9 21h6.2a1.5 1.5 0 001.5-1.4L17.5 7M10 11v6M14 11v6"/>',
  folder: '<path d="M3.5 7.5a2 2 0 012-2h4l2 2h7a2 2 0 012 2v8a2 2 0 01-2 2h-13a2 2 0 01-2-2z"/>',
};
const icon = (name, size = 22, color = 'currentColor', width = 1.7) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[name]}</svg>`;

// ---------- Format (SHAIPCore/Telemetry.swift) ----------
const Format = {
  clock(s) {
    if (s == null || s < 0) return '--:--:--';
    const two = v => String(v).padStart(2, '0');
    return `${two(Math.floor(s / 3600))}:${two(Math.floor(s / 60) % 60)}:${two(s % 60)}`;
  },
  mbps: v => (v < 1 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : v.toFixed(0)),
  bytes(n) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = n, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return { value: i === 0 ? String(Math.round(n)) : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0), unit: units[i] };
  },
  count: n => (n < 1000 ? String(n) : n < 1e6 ? (n / 1000).toFixed(1) + 'K' : (n / 1e6).toFixed(2) + 'M'),
  orbArc: s => (s == null ? 0 : (300 + (s % 30) * 10) / 629),
  fingerprint(hex, groups = 4) {
    if (!hex) return '—';
    return hex.slice(0, groups * 4).match(/.{1,4}/g).join(' ');
  },
};

// ---------- ServerConfig (SHAIPCore/ServerConfig.swift) ----------
const ML_DSA_PUB_BYTES = 1952, ED_PUB_BYTES = 32;
function hostOf(address) {
  if (address.startsWith('[')) {
    const end = address.indexOf(']');
    if (end < 0) return null;
    return address.slice(1, end) || null;
  }
  const parts = address.split(':');
  return parts.length === 2 && parts[0] ? parts[0] : null;
}
const isHex = (s, bytes) => s.length === bytes * 2 && /^[0-9a-fA-F]*$/.test(s);
function tables(text) {
  const out = {};
  let table = '';
  for (const raw of text.split(/\r?\n|\r/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('[') && line.endsWith(']')) { table = line.slice(1, -1).trim(); continue; }
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    const q = value[0];
    const close = (q === '"' || q === "'") ? value.indexOf(q, 1) : -1;
    if (close > 0) value = value.slice(1, close);
    else if (value.includes('#')) value = value.slice(0, value.indexOf('#')).trim();
    (out[table] ??= {})[key] = value;
  }
  return out;
}
function parseConfig(text) {
  const t = tables(text), server = t.server ?? {}, enroll = t.enroll ?? {};
  if (server.address == null) throw new Error('The config has no [server] address.');
  if (server.server_ml_dsa_pub == null) throw new Error('The config has no [server] server_ml_dsa_pub.');
  if (server.server_ed_pub == null) throw new Error('The config has no [server] server_ed_pub.');
  const address = server.address.trim();
  const c = {
    address,
    label: server.label ?? hostOf(address) ?? address,
    mlDsaPub: server.server_ml_dsa_pub.trim().toLowerCase(),
    edPub: server.server_ed_pub.trim().toLowerCase(),
    controlPlane: enroll.control_plane ?? null,
    enrollAuthorityPub: enroll.authority_key ?? null,
    deviceCAPub: enroll.ca_key ?? null,
  };
  const port = Number(address.split(':').pop());
  if (hostOf(address) == null || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`“${address}” is not a host:port address.`);
  if (!isHex(c.mlDsaPub, ML_DSA_PUB_BYTES)) throw new Error(`server_ml_dsa_pub must be ${ML_DSA_PUB_BYTES} bytes of hex (${ML_DSA_PUB_BYTES * 2} characters).`);
  if (!isHex(c.edPub, ED_PUB_BYTES)) throw new Error(`server_ed_pub must be ${ED_PUB_BYTES} bytes of hex (${ED_PUB_BYTES * 2} characters).`);
  c.canEnroll = c.controlPlane != null && c.enrollAuthorityPub != null && c.deviceCAPub != null;
  return c;
}
// identity_id = SHA-256(pq_pub || ed_pub)[0..16] (client/src/handshake.rs): the same value
// pqanond --print-public prints, so the fingerprint shown matches the operator's.
async function identityOf(c) {
  try {
    const hex = c.mlDsaPub + c.edPub, bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    const sum = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return Array.from(sum.slice(0, 16), b => b.toString(16).padStart(2, '0')).join('');
  } catch { return null; }
}

// ---------- State (SHAIP/Store/TunnelStore.swift) ----------
const HIST = 48;
const S = {
  config: null, identity: null,
  status: 'disconnected',            // disconnected | connecting | connected | disconnecting
  killSwitch: false, onDemand: false,
  enrolled: false,
  lastError: null,
  tab: 'connect',
  snapshot: null, connectedSince: null,
  down: 0, up: 0,
  history: { down: Array(HIST).fill(0), up: Array(HIST).fill(0) },
  layer: null,                       // paste | enroll | remove | about
  setupError: null, pasteError: null, enrollMsg: null,
  lock: false,
};
const connected = () => S.status === 'connected';
const connecting = () => S.status === 'connecting';
const isOn = () => S.status === 'connected' || S.status === 'connecting';
const sessionSeconds = () => (isOn() && S.connectedSince ? Math.max(0, Math.floor((Date.now() - S.connectedSince) / 1000)) : null);
const rttMs = () => (connected() && S.snapshot ? Math.round(S.snapshot.rttMs) : null);
const stateLabel = () => ({ connected: 'CONNECTED', connecting: 'CONNECTING', disconnecting: 'DISCONNECTING' }[S.status] ?? 'NOT CONNECTED');
const peak = () => Math.max(...S.history.down);
function chartScale() {
  const top = Math.max(...S.history.down, ...S.history.up);
  if (top <= 1) return 1;
  const mag = Math.pow(10, Math.floor(Math.log10(top)));
  return Math.ceil(top / mag) * mag;
}

// ---------- The simulated session ----------
let pending = null, burst = 0, burstRate = 0, tickN = 0;
function connect() {
  if (!S.config || isOn()) return;
  S.status = 'connecting'; S.lastError = null;
  clearTimeout(pending);
  pending = setTimeout(() => {
    S.status = 'connected';
    S.connectedSince = Date.now();
    burst = 5; burstRate = 38 + Math.random() * 30;   // a few busy seconds as apps reconnect
    S.snapshot = {
      tunnelAddress: '10.77.0.2', serverAddress: S.config.address, dns: '10.77.0.1', mtu: 1370,
      serverIdentity: S.identity, rttMs: 22,
      bytesSent: 0, bytesReceived: 0, packetsSent: 0, packetsReceived: 0,
      reconnects: 0, rekeys: 0, packetsRejected: 0, droppedOffline: 0, ipv6Dropped: 0,
    };
    update();
  }, 1100);
  update();
}
function disconnect() {
  if (!isOn()) return;
  clearTimeout(pending);
  S.status = 'disconnecting';
  update();
  pending = setTimeout(() => {
    S.status = 'disconnected'; S.snapshot = null; S.connectedSince = null; S.down = 0; S.up = 0;
    update();
  }, 500);
}
const toggleConnection = () => (isOn() ? disconnect() : connect());

function sampleRates() {
  if (burst <= 0 && Math.random() < 0.1) { burst = 2 + Math.floor(Math.random() * 7); burstRate = 8 + Math.random() * 85; }
  let down = 0.18 + Math.random() * 1.1, up = 0.05 + Math.random() * 0.3;
  if (burst > 0) { burst--; down += burstRate * (0.65 + Math.random() * 0.5); up += burstRate * 0.05 * (0.5 + Math.random()); }
  return { down, up };
}
function tick() {
  tickN++;
  if (connected() && S.snapshot) {
    const { down, up } = sampleRates(), s = S.snapshot;
    S.down = down; S.up = up;
    const rx = down * 1e6 / 8, tx = up * 1e6 / 8;
    s.bytesReceived += rx; s.bytesSent += tx;
    s.packetsReceived += Math.round(rx / 1150); s.packetsSent += Math.round(tx / 420);
    s.rttMs = 21 + 4 * Math.sin(tickN / 9) + Math.random() * 3 + (down > 40 ? 6 : 0);
    if (Math.random() < 0.04) s.ipv6Dropped += 1 + Math.floor(Math.random() * 3);
    const secs = sessionSeconds();
    if (secs && secs % (20 * 60) === 0) s.rekeys++;
    S.history.down = [...S.history.down.slice(1), down];
    S.history.up = [...S.history.up.slice(1), up];
  } else {
    S.history.down = [...S.history.down.slice(1), 0];
    S.history.up = [...S.history.up.slice(1), 0];
  }
  update();
}

// ---------- Protection (SHAIPCore/Protection.swift) ----------
const REKEY_MINUTES = 20;
function protectionItems() {
  const live = connected() && S.snapshot, snap = S.snapshot, out = [];
  out.push(live
    ? { title: 'Encrypted tunnel', detail: 'Traffic between this iPhone and the server is encrypted with ChaCha20-Poly1305, under keys from a hybrid post-quantum handshake (ML-KEM-768 + X25519).', on: true }
    : { title: 'Encrypted tunnel', detail: 'Not connected. Your traffic is not going through the VPN.', on: false });
  if (live) {
    out.push({ title: 'Server verified', detail: `The server proved it holds the keys this app was given (ML-DSA-65 + Ed25519)${snap.serverIdentity ? `, identity ${Format.fingerprint(snap.serverIdentity)}` : ''}.`, on: true });
    out.push(snap.dns
      ? { title: 'DNS through the tunnel', detail: `Lookups go to ${snap.dns} inside the tunnel, not to your network's resolver.`, on: true }
      : { title: 'DNS through the tunnel', detail: "The server provided no resolver, so lookups use your network's resolver.", on: false });
    out.push({ title: 'IPv6 blocked', detail: 'This tunnel carries IPv4 only, so IPv6 traffic is stopped while connected instead of going around it.', on: true });
    out.push({ title: 'Fresh keys', detail: `A new handshake replaces the session keys every ${REKEY_MINUTES} minutes${snap.rekeys > 0 ? ` (${snap.rekeys} so far)` : ''}.`, on: true });
  }
  out.push(S.killSwitch
    ? { title: 'Kill switch', detail: 'iOS blocks traffic outside the tunnel while the VPN is on, including while it reconnects. Local network devices are blocked too.', on: true }
    : { title: 'Kill switch', detail: 'Off. If the tunnel drops, apps may reach the internet directly until it reconnects.', on: false });
  out.push({ title: 'Connect automatically', detail: S.onDemand ? 'iOS reconnects the VPN on any network.' : 'Off. The VPN connects only when you turn it on.', on: S.onDemand });
  return out;
}
const LIMITS = [
  ['The VPN server sees your destinations', 'This hides your traffic from your local network and internet provider, not from whoever runs the server.'],
  ['One hop, no mixnet', 'Traffic goes straight to one server. Someone who can watch both sides of it could match traffic by timing.'],
  ['It can still look like a VPN', "To your network every packet is random bytes, but their sizes and timing can still suggest an encrypted tunnel, and anyone with this server's config can recognize its handshakes."],
  ['Websites can still recognize you', 'Logins, cookies and browser fingerprinting work the same with or without a VPN.'],
  ['No content filtering', 'There is no ad, tracker or malware blocking.'],
  ['Not independently audited yet', "Don't rely on it where your safety depends on it."],
];

// ---------- DOM ----------
const $ = (sel, root = document) => root.querySelector(sel);
const cache = new WeakMap();
function setText(el, v) { if (el && cache.get(el) !== v) { cache.set(el, v); el.textContent = v; } }
function setHTML(el, v) { if (el && cache.get(el) !== v) { cache.set(el, v); el.innerHTML = v; } }

const TABS = [['connect', 'Connect', 'power'], ['traffic', 'Traffic', 'chart'], ['protection', 'Protection', 'shield'], ['server', 'Server', 'server'], ['settings', 'Settings', 'sliders']];
const blob = (color, size, pos, opacity) => `<div class="blob" style="width:${size}px;height:${size}px;${pos};background:${color};opacity:${opacity}"></div>`;
const statusPill = (text, color) => `<span class="pill" style="color:${color};background:${alpha(color, 0.12)}"><span class="dot"></span>${esc(text)}</span>`;

function build() {
  $('#app').innerHTML = `
  <section class="screen" data-screen="connect" aria-label="Connect">
    <div class="bg"></div>
    <div class="scroll"><div class="content" style="gap:0">
      <div class="server-pill glass-control" role="group">
        <span class="avatar">${icon('server', 15, 'currentColor', 2.2)}</span>
        <span class="name" id="c-name">No server</span>
        <span class="chip mono" id="c-chip">OPEN</span>
      </div>
      <div class="mesh-zone">
        <canvas data-gfx="net" data-cy="0.5" data-r="0.36" data-hud-clear="124" aria-hidden="true"></canvas>
        <div class="orb-wrap">
          <svg class="rings" width="244" height="244" viewBox="0 0 244 244" aria-hidden="true">
            <circle cx="122" cy="122" r="118" fill="none" stroke="rgba(255,255,255,0.2)" stroke-width="6" stroke-dasharray="0.7 5.48"></circle>
            <circle id="orb-track" cx="122" cy="122" r="100" fill="none" stroke-width="1"></circle>
            <circle id="orb-arc" class="arc" cx="122" cy="122" r="100" fill="none" stroke-width="2.5" stroke-linecap="round" stroke-dasharray="0 629" transform="rotate(-90 122 122)"></circle>
          </svg>
          <button class="orb" id="orb" type="button" aria-label="Connect VPN">
            <span id="orb-icon">${icon('power', 30, 'currentColor', 2)}</span>
            <span class="state" id="orb-state">OFF</span>
            <span class="sub" id="orb-sub">Tap to connect</span>
          </button>
        </div>
      </div>
      <button class="status-card glass-card" id="c-card" type="button" aria-describedby="c-card-hint">
        <span class="top"><span id="c-pill"></span><span class="timer tab" id="c-timer">--:--:--</span></span>
        <span class="mid">
          <span class="line"><span class="label" id="c-label">No server</span>
            <span class="tip"><span>TUNNEL IP</span><span id="c-tip">—</span></span></span>
          <span class="subtitle" id="c-sub"></span>
        </span>
        <span class="metrics" id="c-metrics"></span>
      </button>
      <span id="c-card-hint" hidden>Opens traffic</span>
      <div class="error-line" id="c-error" hidden></div>
      <div class="quick" style="margin-top:20px">
        <button class="qtile glass-control" id="q-kill" type="button" role="switch">
          <span class="h">${icon('lock', 15, 'currentColor', 2)}<span>Kill switch</span></span><span class="s" id="q-kill-s">OFF</span></button>
        <button class="qtile glass-control" id="q-auto" type="button" role="switch">
          <span class="h">${icon('cycle', 15, 'currentColor', 2)}<span>Auto-connect</span></span><span class="s" id="q-auto-s">OFF</span></button>
        <div class="qtile glass-control" id="q-dns" role="group" aria-label="DNS">
          <span class="h">${icon('network', 15, 'currentColor', 2)}<span>DNS</span></span><span class="s" id="q-dns-s">—</span></div>
      </div>
    </div></div>
  </section>

  <section class="screen" data-screen="traffic" aria-label="Traffic" hidden>
    <div class="bg">${blob(T.signal, 440, 'left:-200px;top:40px', 0.14)}</div>
    <div class="scroll"><div class="content">
      <div class="title-row" style="padding-bottom:4px"><h1 class="large-title">Traffic</h1>
        <span class="eyebrow" id="t-live" style="display:flex;align-items:center;gap:6px;letter-spacing:.14em"></span></div>
      <div class="hero-card glass-card">
        <div class="head">
          <div style="display:flex;flex-direction:column;gap:4px">
            <span class="eyebrow" style="font-size:9px;color:${dim(0.45)}">THROUGHPUT ↓</span>
            <div class="big"><b id="t-down">0.00</b><i>Mbps</i></div>
          </div>
          <div class="side"><span id="t-up" style="color:${T.steelInk}">↑ 0.00</span><span id="t-peak" style="color:${dim(0.45)}">PK 0.00</span></div>
        </div>
        <div class="chart" id="t-chart" role="img" aria-label="Throughput, last 48 seconds"></div>
        <div class="axis" aria-hidden="true"><span>T-48s</span><span>T-24s</span><span>NOW</span></div>
      </div>
      <div class="tiles" id="t-tiles"></div>
      <div class="list glass-tile" id="t-rows"></div>
    </div></div>
  </section>

  <section class="screen" data-screen="protection" aria-label="Protection" hidden>
    <div class="bg">${blob(T.ok, 420, 'left:-60px;top:-200px', 0.08)}</div>
    <div class="scroll"><div class="content">
      <div class="title-row"><h1 class="large-title">Protection</h1><span class="eyebrow" id="p-state" style="letter-spacing:.14em"></span></div>
      <div class="eyebrow section-eyebrow">RIGHT NOW</div>
      <div class="list glass-tile" id="p-now"></div>
      <div class="eyebrow section-eyebrow">WHAT THIS VPN DOESN'T DO</div>
      <div class="list glass-tile">${LIMITS.map(([t, d]) => `<div class="prow"><span class="ic">${icon('info', 14, T.steel, 2)}</span><span class="t"><b>${esc(t)}</b><span>${esc(d)}</span></span></div>`).join('')}</div>
      <div class="footnote">SHAIP runs SHAIP VPN, pre-release software. Its code is open; it has not yet had an independent security audit.</div>
    </div></div>
  </section>

  <section class="screen" data-screen="server" aria-label="Server" hidden>
    <div class="bg">${blob(T.signal, 420, 'right:-220px;top:80px', 0.1)}</div>
    <div class="scroll"><div class="content">
      <div class="title-row"><h1 class="large-title">Server</h1></div>
      <div class="card glass-card">
        <div class="row"><span id="s-pill"></span><span class="chip signal">PQANON/1</span></div>
        <div class="server-name" id="s-name"></div>
        <div class="kv"><span>ADDRESS</span><span id="s-addr"></span></div>
        <div class="kv"><span>CONNECTED TO</span><span id="s-to"></span></div>
        <div class="kv"><span>TUNNEL IP</span><span id="s-tip"></span></div>
        <div class="kv"><span>RESOLVER</span><span id="s-dns"></span></div>
      </div>
      <div class="card small glass-tile" id="s-identity"></div>
      <div class="card small glass-tile" id="s-device"></div>
      <div class="actions">
        <button class="glass-control" id="s-replace" type="button">${icon('download', 17)}Replace config</button>
        <button class="glass-control" id="s-remove" type="button" style="color:${T.threat}">${icon('trash', 17)}Remove</button>
      </div>
    </div></div>
  </section>

  <section class="screen" data-screen="settings" aria-label="Settings" hidden>
    <div class="bg">${blob(T.signal, 420, 'right:-220px;top:80px', 0.1)}</div>
    <div class="scroll"><div class="content">
      <div class="title-row"><h1 class="large-title">Settings</h1></div>
      <div class="proto glass-card">
        <div class="h"><b>PQANON/1</b><span class="chip signal" style="font-size:8px;letter-spacing:.14em">THE ONLY PROTOCOL</span></div>
        <p>Hybrid post-quantum handshake: the session key comes from both ML-KEM-768 and X25519, so breaking one is not enough. Both sides sign with ML-DSA-65 and Ed25519. Traffic is sealed with ChaCha20-Poly1305 and padded to common packet sizes.</p>
        <div class="chips">${['UDP', 'ML-KEM-768 + X25519', 'ML-DSA-65 + Ed25519', 'ChaCha20-Poly1305'].map(c => `<span class="chip">${c}</span>`).join('')}</div>
      </div>
      <div class="eyebrow section-eyebrow">VPN</div>
      <div class="switches glass-tile">
        <button class="srow" id="set-kill" type="button" role="switch"><span class="t"><b>Kill switch</b><span id="set-kill-sub"></span></span><span class="switch"><i></i></span></button>
        <button class="srow" id="set-auto" type="button" role="switch"><span class="t"><b>Connect automatically</b><span>iOS keeps the VPN connected on any network.</span></span><span class="switch"><i></i></span></button>
      </div>
      <div class="eyebrow section-eyebrow">TUNNEL</div>
      <div class="facts" id="set-facts"></div>
      <div class="version"><span>SHAIP 2.0 · core 0.1.0</span><span class="footnote" style="padding:0">Pre-release software. SHAIP VPN has not yet had an independent security audit.</span></div>
    </div></div>
  </section>

  <div class="scrim"></div>
  <nav class="tabbar" role="tablist" aria-label="Tabs">${TABS.map(([k, label, ic]) =>
    `<button type="button" role="tab" data-tab="${k}" aria-selected="false">${icon(ic, 22)}<span>${label}</span></button>`).join('')}</nav>

  <div class="setup" id="setup" hidden>
    <canvas data-gfx="net" data-cy="0.5" data-r="0.4" data-art="1" aria-hidden="true"></canvas>
    <div class="fade"></div><div class="floor"></div>
    <div class="stack">
      <div class="live"><span class="dot" style="box-shadow:0 0 10px currentColor"></span>PQANON/1 · POST-QUANTUM VPN</div>
      <h2>Your traffic, encrypted to a server you choose.</h2>
      <p>Import the config your server's operator gave you. Traffic and DNS lookups between this iPhone and that server are encrypted. The operator can still see where your traffic goes.</p>
      <div class="warn-text" id="setup-error" hidden></div>
      <div class="buttons">
        <button class="btn-primary" id="setup-import" type="button">${icon('docPlus', 19, 'currentColor', 2)}Import config file</button>
        <button class="btn-glass glass-control" id="setup-paste" type="button">${icon('clipboard', 19, 'currentColor', 1.8)}Paste config</button>
        <button class="sample" id="setup-sample" type="button"><span class="chip">PREVIEW</span>Use a sample server</button>
      </div>
      <div class="fine">PRE-RELEASE · NOT YET INDEPENDENTLY AUDITED</div>
    </div>
  </div>

  <div id="layer"></div>

  <div class="lock" id="lock" hidden>
    <canvas data-gfx="net" data-cy="0.46" data-r="0.4" data-art="1" aria-hidden="true"></canvas>
    <div class="clock"><span class="date" id="lock-date"></span><span class="time" id="lock-time"></span></div>
    <div class="la" id="lock-la" role="group" aria-label="SHAIP Live Activity"></div>
    <div class="unlock" id="lock-hint" style="bottom:calc(98px + var(--bottom-chrome))" hidden>No Live Activity while the VPN is off.</div>
    <button class="unlock" id="lock-close" type="button">Tap to unlock</button>
  </div>`;

  // Wiring
  document.querySelectorAll('.tabbar button').forEach(b => b.addEventListener('click', () => { S.tab = b.dataset.tab; update(); }));
  $('#orb').addEventListener('click', toggleConnection);
  $('#c-card').addEventListener('click', () => { S.tab = 'traffic'; update(); });
  const toggleKill = () => { S.killSwitch = !S.killSwitch; update(); };
  const toggleAuto = () => { S.onDemand = !S.onDemand; update(); };
  $('#q-kill').addEventListener('click', toggleKill);
  $('#q-auto').addEventListener('click', toggleAuto);
  $('#set-kill').addEventListener('click', toggleKill);
  $('#set-auto').addEventListener('click', toggleAuto);
  $('#s-replace').addEventListener('click', () => openLayer('paste'));
  $('#s-remove').addEventListener('click', () => openLayer('remove'));
  $('#setup-import').addEventListener('click', () => pickFile(text => adopt(text, 'setup')));
  $('#setup-paste').addEventListener('click', () => openLayer('paste'));
  $('#setup-sample').addEventListener('click', () => adopt(SAMPLE_CONFIG, 'setup'));
  $('#lock-close').addEventListener('click', () => { S.lock = false; update(); });
  $('#lock').addEventListener('click', e => { if (e.target === $('#lock') || e.target.tagName === 'CANVAS') { S.lock = false; update(); } });
}

// ---------- Config import ----------
const fileInput = document.getElementById('file');
let onFile = null;
fileInput.addEventListener('change', () => {
  const f = fileInput.files && fileInput.files[0];
  fileInput.value = '';
  if (!f || !onFile) return;
  const cb = onFile; onFile = null;
  f.text().then(cb, () => cb(''));
});
function pickFile(cb) { onFile = cb; fileInput.click(); }

async function install(config) {
  if (isOn()) { clearTimeout(pending); S.status = 'disconnected'; S.snapshot = null; S.connectedSince = null; S.down = S.up = 0; }
  S.config = config; S.enrolled = false; S.lastError = null; S.identity = null;
  S.identity = await identityOf(config);
  if (config.canEnroll) openLayer('enroll'); else closeLayer();
  update();
}
async function adopt(text, where) {
  try {
    await install(parseConfig(text));
    S.setupError = null; S.pasteError = null;
  } catch (e) {
    if (where === 'setup') S.setupError = e.message; else S.pasteError = e.message;
  }
  update();
}
function removeConfiguration() {
  clearTimeout(pending);
  S.status = 'disconnected'; S.snapshot = null; S.connectedSince = null; S.down = S.up = 0;
  S.config = null; S.identity = null; S.enrolled = false; S.tab = 'connect';
  closeLayer();
}

// ---------- Sheets and dialogs ----------
function openLayer(kind) {
  S.layer = kind; S.pasteError = null; S.enrollMsg = null;
  const L = $('#layer');
  const sheet = (title, left, right, body) => `<div class="layer" data-kind="${kind}"><div class="sheet" role="dialog" aria-modal="true" aria-label="${esc(title)}">
      <div class="bar"><span style="display:flex;align-items:center;gap:14px">${left}</span><h3>${esc(title)}</h3>${right}</div>
      <div class="body">${body}</div></div></div>`;
  if (kind === 'paste') {
    L.innerHTML = sheet('Server config',
      `<button type="button" data-act="close">Cancel</button><button type="button" data-act="file" aria-label="Choose a file">${icon('folder', 21, 'currentColor', 1.8)}</button>`,
      `<button type="button" data-act="save" id="paste-save" disabled>Save</button>`,
      `<p>Paste the client config from your server's operator. It needs the [server] address, server_ml_dsa_pub and server_ed_pub (from pqanond --print-public).</p>
       <textarea id="paste-text" spellcheck="false" autocapitalize="off" autocomplete="off" aria-label="Client config" placeholder="[server]&#10;address = &quot;vpn.example.net:443&quot;&#10;server_ml_dsa_pub = &quot;…&quot;&#10;server_ed_pub = &quot;…&quot;"></textarea>
       <div class="warn-text" id="paste-error" hidden></div>`);
    const ta = $('#paste-text'), save = $('#paste-save');
    ta.addEventListener('input', () => { save.disabled = !ta.value; });
    ta.addEventListener('dragover', e => e.preventDefault());
    ta.addEventListener('drop', e => {
      const f = e.dataTransfer && e.dataTransfer.files[0];
      if (!f) return;
      e.preventDefault();
      f.text().then(t => { ta.value = t; save.disabled = !t; });
    });
    setTimeout(() => ta.focus(), 50);
  } else if (kind === 'enroll') {
    L.innerHTML = sheet('Enroll this device',
      `<button type="button" data-act="close" id="enroll-close">Not now</button>`,
      `<button type="button" data-act="enroll" id="enroll-go" disabled>Enroll</button>`,
      `<p>Servers that admit enrolled devices only need this once per device. Paste the enrollment link from your account page; this iPhone proves it holds its own key and receives a certificate.</p>
       <input type="text" id="enroll-link" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="pqanon://enroll?t=…" aria-label="Enrollment link">
       <div class="warn-text" id="enroll-msg" hidden></div>`);
    const input = $('#enroll-link');
    input.addEventListener('input', () => { $('#enroll-go').disabled = !input.value.trim(); });
  } else if (kind === 'remove') {
    L.innerHTML = `<div class="layer" data-kind="remove" data-act="close"><div class="dialog" role="alertdialog" aria-modal="true" aria-label="Remove this server">
      <div class="group"><div class="msg"><b>Remove this server from your iPhone?</b><span>The VPN configuration is deleted. This device's identity stays, so it can reconnect after you import the config again.</span></div>
      <button type="button" class="danger" data-act="remove">Remove</button></div>
      <button type="button" class="cancel" data-act="close">Cancel</button></div></div>`;
  } else if (kind === 'about') {
    L.innerHTML = sheet('About this preview', '<span></span>', `<button type="button" data-act="close">Done</button>`,
      `<p>This is the SHAIP iPhone app's own interface, running in your browser: the same screens, words, glass and live 3-D mesh as the iPhone build.</p>
       <p>A web page can't open a VPN tunnel. When you connect here, the session and its numbers are simulated inside this page, and nothing is sent anywhere. In the iPhone app, every number comes from the tunnel itself.</p>
       <p>Try the sample server, tap the orb, then open Traffic and Protection.</p>
       <div style="display:flex;flex-direction:column;gap:10px;margin-top:6px">
         <button type="button" class="btn-glass glass-control" data-act="lock">Show lock screen</button>
         <button type="button" class="btn-glass glass-control" data-act="reset">Start over</button></div>`);
  }
  update();
}
function closeLayer() { S.layer = null; $('#layer').innerHTML = ''; }
document.addEventListener('click', e => {
  const t = e.target.closest('[data-act]');
  if (!t || !t.closest('#layer')) return;
  if (t.classList.contains('layer') && e.target !== t) return;   // a click inside the dialog, not on the backdrop
  const act = t.dataset.act;
  if (act === 'close') { closeLayer(); update(); }
  else if (act === 'file') pickFile(text => { const ta = $('#paste-text'); if (ta) { ta.value = text; $('#paste-save').disabled = !text; } });
  else if (act === 'save') { const ta = $('#paste-text'); if (ta && ta.value) adopt(ta.value, 'paste'); }
  else if (act === 'enroll') {
    S.enrollMsg = 'Enrollment runs in the iPhone app, which holds this device\'s key and proves it to the control plane. This preview has no device key, so the link was not used.';
    update();
  }
  else if (act === 'remove') { removeConfiguration(); update(); }
  else if (act === 'lock') { closeLayer(); S.lock = true; update(); }
  else if (act === 'reset') { reset(); }
});
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (S.layer) { closeLayer(); update(); } else if (S.lock) { S.lock = false; update(); }
});
function reset() { removeConfiguration(); S.killSwitch = false; S.onDemand = false; S.lock = false; S.setupError = null; S.history = { down: Array(HIST).fill(0), up: Array(HIST).fill(0) }; update(); }

// ---------- Rendering ----------
let lastArcSeconds = null;
function update() {
  const on = connected(), pend = connecting(), snap = S.snapshot, cfg = S.config, secs = sessionSeconds();
  const tint = on ? T.signal : pend ? T.warn : dim(0.55);
  const pillColor = on ? T.ok : pend ? T.warn : T.ink2;

  // Tabs
  document.querySelectorAll('.screen').forEach(s => { s.hidden = s.dataset.screen !== S.tab; });
  document.querySelectorAll('.tabbar button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === S.tab)));

  // Connect
  setText($('#c-name'), cfg ? cfg.label : 'No server');
  setText($('#c-chip'), S.enrolled ? 'ENROLLED' : 'OPEN');
  const orb = $('#orb');
  orb.disabled = !cfg || S.status === 'disconnecting';
  orb.style.color = tint;
  orb.style.setProperty('--orb-glow', on ? 'rgba(92,242,255,0.28)' : 'transparent');
  orb.setAttribute('aria-label', isOn() ? 'Disconnect VPN' : 'Connect VPN');
  setText($('#orb-state'), S.status === 'connected' ? 'CONNECTED' : S.status === 'connecting' ? 'CONNECTING' : S.status === 'disconnecting' ? 'STOPPING' : 'OFF');
  setText($('#orb-sub'), isOn() ? 'Tap to disconnect' : 'Tap to connect');
  $('#orb-track').setAttribute('stroke', on ? 'rgba(92,242,255,0.18)' : 'rgba(255,255,255,0.08)');
  const arc = $('#orb-arc'), arcSecs = on ? secs : null;
  // Linear between ticks; no animation when the 30 s cycle wraps or the arc empties.
  arc.style.transition = arcSecs == null || arcSecs % 30 === 0 || lastArcSeconds == null ? 'stroke 0.55s ease-in-out' : '';
  arc.setAttribute('stroke', tint);
  arc.setAttribute('stroke-dasharray', `${(Format.orbArc(arcSecs) * 629).toFixed(1)} 629`);
  lastArcSeconds = arcSecs;

  setHTML($('#c-pill'), statusPill(stateLabel(), pillColor));
  setText($('#c-timer'), Format.clock(secs));
  setText($('#c-label'), cfg ? cfg.label : 'No server');
  setText($('#c-tip'), on && snap ? snap.tunnelAddress : '—');
  setText($('#c-sub'), on && snap ? `DNS ${snap.dns ?? 'unchanged'} · MTU ${snap.mtu} · PQANON/1` : cfg ? `${cfg.address} · PQANON/1` : 'Set up a server to connect');
  const total = snap ? snap.bytesSent + snap.bytesReceived : 0, data = Format.bytes(total), rtt = rttMs();
  setHTML($('#c-metrics'), [
    ['DOWN', on ? Format.mbps(S.down) : '—', 'Mbps'], ['UP', on ? Format.mbps(S.up) : '—', 'Mbps'],
    ['RTT', rtt != null ? String(rtt) : '—', 'ms'], ['DATA', snap ? data.value : '—', data.unit],
  ].map(([k, v, u]) => `<span class="metric"><span class="k">${k}</span><span class="v"><b>${v}</b><i>${u}</i></span></span>`).join(''));
  const err = $('#c-error');
  err.hidden = !(S.lastError && !on);
  setText(err, S.lastError ?? '');

  const quick = (id, onState, color, label) => {
    const el = $(id);
    el.style.borderColor = onState ? alpha(color, 0.35) : 'rgba(255,255,255,0.14)';
    el.querySelector('svg').style.color = onState ? color : T.ink2;
    const s = el.querySelector('.s');
    s.style.color = onState ? color : T.ink2;
    setText(s, label);
    if (el.tagName === 'BUTTON') el.setAttribute('aria-checked', String(onState));
  };
  quick('#q-kill', S.killSwitch, T.ok, S.killSwitch ? 'ON' : 'OFF');
  quick('#q-auto', S.onDemand, T.signal, S.onDemand ? 'ON' : 'OFF');
  const dnsOn = !!(on && snap && snap.dns);
  quick('#q-dns', dnsOn, T.steel, !on ? '—' : snap && snap.dns ? 'VIA TUNNEL' : 'YOUR NETWORK');

  // Traffic
  setHTML($('#t-live'), `<span class="dot" style="color:${on ? T.ok : T.ink2}"></span><span style="color:${on ? T.ok : T.ink2};white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${on ? `LIVE · ${esc((cfg?.label ?? '').toUpperCase())}` : stateLabel()}</span>`);
  setText($('#t-down'), on ? Format.mbps(S.down) : '0.00');
  setText($('#t-up'), `↑ ${on ? Format.mbps(S.up) : '0.00'}`);
  setText($('#t-peak'), `PK ${Format.mbps(peak())}`);
  const sent = Format.bytes(snap?.bytesSent ?? 0), recv = Format.bytes(snap?.bytesReceived ?? 0);
  setHTML($('#t-tiles'), [
    ['SENT', snap ? sent.value : '—', sent.unit], ['RECEIVED', snap ? recv.value : '—', recv.unit],
    ['PACKETS', snap ? Format.count(snap.packetsSent + snap.packetsReceived) : '—', ''],
  ].map(([k, v, u]) => `<div class="tile glass-tile"><span class="k">${k}</span><span class="v"><b>${v}</b><i>${u}</i></span></div>`).join(''));
  setHTML($('#t-rows'), [
    ['Round-trip time', rtt != null ? `${rtt} ms` : '—', 'Keepalive ping to the server and back'],
    ['Reconnects', snap ? String(snap.reconnects) : '—', 'Sessions re-established after a failure'],
    ['Rekeys', snap ? String(snap.rekeys) : '—', 'Sessions replaced by a fresh handshake'],
    ['Rejected packets', snap ? Format.count(snap.packetsRejected) : '—', 'Arrived but failed authentication (replays, tampering, strays)'],
    ['Held while reconnecting', snap ? Format.count(snap.droppedOffline) : '—', 'Dropped inside the tunnel, not sent around it'],
    ['IPv6 blocked', snap ? Format.count(snap.ipv6Dropped) : '—', 'The tunnel carries IPv4 only'],
  ].map(([t, v, d]) => `<div class="lrow"><span class="t"><b>${t}</b><span>${d}</span></span><span class="val">${v}</span></div>`).join(''));
  if (S.tab === 'traffic') drawChart();

  // Protection
  setText($('#p-state'), stateLabel());
  $('#p-state').style.color = on ? T.ok : T.ink2;
  setHTML($('#p-now'), protectionItems().map(it =>
    `<div class="prow"><span class="ic">${it.on ? icon('checkFill', 15, T.ok, 2) : icon('minus', 14, T.ink2, 2)}</span><span class="t"><b>${esc(it.title)}</b><span>${esc(it.detail)}</span></span></div>`).join(''));

  // Server
  if (cfg) {
    setHTML($('#s-pill'), statusPill(stateLabel(), on ? T.ok : T.ink2));
    setText($('#s-name'), cfg.label);
    setText($('#s-addr'), cfg.address);
    setText($('#s-to'), on && snap ? snap.serverAddress : '—');
    setText($('#s-tip'), on && snap ? snap.tunnelAddress : '—');
    setText($('#s-dns'), on && snap ? (snap.dns ?? 'none pushed') : '—');
    setHTML($('#s-identity'), `<span class="eyebrow">SERVER IDENTITY</span>` + (on && snap && snap.serverIdentity
      ? `<div class="fp">${Format.fingerprint(snap.serverIdentity, 8)}</div><p>Proven by the handshake: the server signed it with the ML-DSA-65 and Ed25519 keys in your config. Compare it with the identity_id your operator published.</p>`
      : `<p style="font-size:13px;color:${dim(0.55)}">Connect to verify. The tunnel refuses any server that cannot prove it holds the pinned keys.</p>`));
    setHTML($('#s-device'), `<span class="eyebrow">THIS DEVICE</span><b style="font-size:15px;font-weight:600;color:${T.ink2}">Not enrolled</b>
      <p>${cfg.canEnroll ? 'If this server admits enrolled devices only, enroll with the link from your account page.' : "This server's config has no enrollment section; open servers don't need one."}</p>
      ${cfg.canEnroll ? '<button type="button" class="textbtn" id="s-enroll" style="align-self:flex-start;padding-top:2px">Enroll this device</button>' : ''}`);
    const enrollBtn = $('#s-enroll');
    if (enrollBtn && !enrollBtn.dataset.wired) { enrollBtn.dataset.wired = '1'; enrollBtn.addEventListener('click', () => openLayer('enroll')); }
  }

  // Settings
  const kill = $('#set-kill'), auto = $('#set-auto');
  kill.setAttribute('aria-checked', String(S.killSwitch));
  auto.setAttribute('aria-checked', String(S.onDemand));
  setText($('#set-kill-sub'), isOn() ? 'Blocks traffic outside the tunnel. Takes effect the next time the VPN connects.' : 'Blocks traffic outside the tunnel while the VPN is on, including local devices.');
  const port = cfg ? cfg.address.split(':').pop() : null;
  setHTML($('#set-facts'), [['PORT', port ? `UDP ${port}` : '—'], ['MTU', snap ? String(snap.mtu) : '1370'], ['KEEPALIVE', '10 s'], ['REKEY', `${REKEY_MINUTES} min`]]
    .map(([k, v]) => `<div class="fact"><span>${k}</span><span>${v}</span></div>`).join(''));

  // Setup cover, sheets, lock screen
  $('#setup').hidden = !!cfg;
  const se = $('#setup-error');
  se.hidden = !S.setupError; setText(se, S.setupError ?? '');
  const pe = $('#paste-error');
  if (pe) { pe.hidden = !S.pasteError; setText(pe, S.pasteError ?? ''); }
  const em = $('#enroll-msg');
  if (em) { em.hidden = !S.enrollMsg; setText(em, S.enrollMsg ?? ''); }
  updateLock();
  if (S.tab === 'connect') fitLabels(false);
}

function updateLock() {
  const lock = $('#lock');
  lock.hidden = !S.lock;
  if (!S.lock) return;
  const now = new Date(), on = connected();
  setText($('#lock-date'), now.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long' }));
  setText($('#lock-time'), clockText(now));
  // The Live Activity runs only while the tunnel is up (LiveActivityController).
  const live = on;
  $('#lock-la').hidden = !live;
  $('#lock-hint').hidden = live;
  if (!live) return;
  const rtt = rttMs();
  setHTML($('#lock-la'), `
    <div class="h"><span class="glyph">${icon('lock', 17, 'currentColor', 2.4)}</span>
      <span class="who"><b>Protected</b><span>SHAIP · PQANON/1</span></span>
      <span class="clk" style="color:${T.ok}">${Format.clock(sessionSeconds())}</span></div>
    <div class="m">
      <div><span class="k">DOWN</span><span class="v"><b>${Format.mbps(S.down)}</b><i>Mbps</i></span></div>
      <div><span class="k">RTT</span><span class="v"><b>${rtt != null ? rtt : '—'}</b><i>ms</i></span></div>
      <button type="button" id="lock-toggle">${isOn() ? 'Disconnect' : 'Connect'}</button></div>`);
  $('#lock-toggle').onclick = toggleConnection;
}
const clockText = d => d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' }).replace(/\s?[AP]\.?M\.?$/i, '');

// The throughput chart, layered as the handoff specifies: dashed gridlines, an area fill
// (signal 34% → 0), a 3 pt blurred glow line, the 1.6 pt line with a horizontal gradient
// (signal 15% → signal → white at "now"), and the dashed steel upload line.
function monotone(points) {
  const n = points.length, dx = [], m = [], t = [];
  for (let i = 0; i < n - 1; i++) { dx[i] = points[i + 1][0] - points[i][0]; m[i] = (points[i + 1][1] - points[i][1]) / dx[i]; }
  t[0] = m[0]; t[n - 1] = m[n - 2];
  for (let i = 1; i < n - 1; i++) {
    if (m[i - 1] * m[i] <= 0) t[i] = 0;
    else { const w1 = 2 * dx[i] + dx[i - 1], w2 = dx[i] + 2 * dx[i - 1]; t[i] = (w1 + w2) / (w1 / m[i - 1] + w2 / m[i]); }
  }
  let d = `M${points[0][0].toFixed(1)},${points[0][1].toFixed(1)}`;
  for (let i = 0; i < n - 1; i++) {
    const h = dx[i] / 3, [x0, y0] = points[i], [x1, y1] = points[i + 1];
    d += `C${(x0 + h).toFixed(1)},${(y0 + h * t[i]).toFixed(1)} ${(x1 - h).toFixed(1)},${(y1 - h * t[i + 1]).toFixed(1)} ${x1.toFixed(1)},${y1.toFixed(1)}`;
  }
  return d;
}
function drawChart() {
  const box = $('#t-chart'), W = box.clientWidth, H = 150;
  if (!W) return;
  const top = chartScale(), y = v => 2 + (H - 4) * (1 - Math.min(v, top) / top), x = i => i / (HIST - 1) * W;
  const down = monotone(S.history.down.map((v, i) => [x(i), y(v)]));
  const up = monotone(S.history.up.map((v, i) => [x(i), y(v)]));
  const grid = [top / 4, top / 2, top * 3 / 4].map(v => `<line x1="0" x2="${W}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}" stroke="rgba(255,255,255,0.07)" stroke-width="0.5" stroke-dasharray="2 3"/>`).join('')
    + [1, 2, 3, 4, 5].map(k => `<line y1="0" y2="${H}" x1="${(k * W / 6).toFixed(1)}" x2="${(k * W / 6).toFixed(1)}" stroke="rgba(255,255,255,0.04)" stroke-width="0.5"/>`).join('');
  box.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" aria-hidden="true" style="overflow:visible">
    <defs>
      <linearGradient id="t-area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${T.signal}" stop-opacity="0.34"/><stop offset="1" stop-color="${T.signal}" stop-opacity="0"/></linearGradient>
      <linearGradient id="t-line" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2="${W}" y2="0"><stop offset="0" stop-color="${T.signal}" stop-opacity="0.15"/><stop offset="0.7" stop-color="${T.signal}"/><stop offset="1" stop-color="#FFFFFF"/></linearGradient>
      <filter id="t-glow" x="-5%" y="-30%" width="110%" height="160%"><feGaussianBlur stdDeviation="3"/></filter>
    </defs>
    ${grid}
    <path d="${down}L${W},${H}L0,${H}Z" fill="url(#t-area)"/>
    <path d="${down}" fill="none" stroke="${T.signal}" stroke-width="3" opacity="0.5" filter="url(#t-glow)"/>
    <path d="${down}" fill="none" stroke="url(#t-line)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="${up}" fill="none" stroke="${T.steel}" stroke-width="1.2" stroke-dasharray="2 3"/>
  </svg>`;
  box.setAttribute('aria-label', `Throughput, last 48 seconds. Peak ${Format.mbps(peak())} megabits per second`);
}

// ---------- Render engine loop ----------
const reduceMotion = () => !!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches);
const framed = () => !!(window.matchMedia && matchMedia('(min-width: 820px) and (min-height: 560px)').matches);
function engineOptions(connectedState) {
  return {
    connected: connectedState, density: 210, hud: false, floor: true, quality: framed() ? 'Ultra' : 'Standard',
    reduceMotion: reduceMotion(), c1: T.signal, c2: T.steel, bad: T.threat, warn: T.warn,
    labels: [], active: 0, hubLabels: {}, radar: [],
  };
}
function frame(ts) {
  requestAnimationFrame(frame);
  const live = engineOptions(connected()), art = engineOptions(true);
  // Draw only the scenes on the top layer: nothing under the setup or lock screen.
  const top = S.lock ? $('#lock') : !S.config ? $('#setup') : $('#app');
  top.querySelectorAll('canvas[data-gfx]').forEach(c => {
    if (top.id === 'app' && c.closest('#setup, #lock')) return;
    draw(c, ts, c.dataset.art ? art : live);
  });
}

// ---------- Page chrome ----------
function layout() {
  const slot = document.getElementById('slot');
  slot.classList.add('with-strip');
  const s = Math.min(1, (window.innerHeight - 64) / 844);   // room for the 12 px bezel
  slot.style.setProperty('--scale', String(Math.max(0.55, s)));
  if (S.tab === 'traffic') drawChart();
  fitLabels(true);
}
// Quick-tile labels shrink before they truncate, like SwiftUI's minimumScaleFactor (0.8 there;
// a little more here, since fallback fonts off Apple devices run wider than SF Pro).
let fitWidth = 0;
function fitLabels(force) {
  const tiles = document.querySelectorAll('.qtile .h span');
  if (!tiles.length || !tiles[0].clientWidth) return;
  const w = tiles[0].closest('.qtile').clientWidth;
  if (!force && w === fitWidth) return;
  fitWidth = w;
  tiles.forEach(el => {
    let size = 13;
    el.style.fontSize = size + 'px';
    while (el.scrollWidth > el.clientWidth + 0.5 && size > 13 * 0.72) { size -= 0.25; el.style.fontSize = size + 'px'; }
  });
}
function clockTick() {
  setText(document.getElementById('sbar-time'), clockText(new Date()));
  if (S.lock) updateLock();
}

build();
document.getElementById('note-lock').addEventListener('click', () => { closeLayer(); S.lock = !S.lock; update(); });
document.getElementById('note-reset').addEventListener('click', reset);
document.getElementById('strip-more').addEventListener('click', () => openLayer('about'));
window.addEventListener('resize', layout);
layout();
update();
clockTick();
setInterval(tick, 1000);
setInterval(clockTick, 5000);
requestAnimationFrame(frame);
