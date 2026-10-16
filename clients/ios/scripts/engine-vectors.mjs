// Generates SHAIPCore's cross-language render vectors from the design reference engine.
//
//   node clients/ios/scripts/engine-vectors.mjs \
//     clients/ios/design/shaip-engine.js \
//     clients/ios/SHAIPCore/Tests/SHAIPCoreTests/Fixtures/engine-vectors.json [--dump DIR]
//
// It runs the engine's real draw() entry point against a recording 2D context, frame by frame,
// and canonicalises every draw call into the same op stream SHAIPCore's SceneRenderer emits:
// line, ring, disc, rect, sprite, text, radial-gradient rect/disc/ellipse, conic disc, and
// lazily-emitted blend changes. Each recorded frame is stored as per-type op counts, an FNV-1a 64
// hash of the canonical text (numbers quantised to 1e-4), and its first ops for diagnosis. The
// Swift test (EngineVectorTests) replays the same frame sequences and must reproduce every hash.
// With --dump, the full canonical text of each frame is written to DIR for diffing.
import fs from 'node:fs';
import path from 'node:path';

const [enginePath, outPath, ...rest] = process.argv.slice(2);
if (!enginePath || !outPath) { console.error('usage: engine-vectors.mjs <shaip-engine.js> <out.json> [--dump DIR]'); process.exit(2); }
const dumpDir = rest[0] === '--dump' ? rest[1] : null;

// Load the engine as a module, exposing its internals; sprites become tagged tokens.
let src = fs.readFileSync(enginePath, 'utf8');
if (!src.includes('function spr(col) {')) throw new Error('engine layout changed: spr() not found');
src = src.replace('function spr(col) {', 'function spr(col) { return { __spr: col };');
src += '\nexport { genNet, genGlobe, genRadar, rng, fib, CITIES, ARCS, LAND };\n';
const E = await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));

// ---- canonical form (mirrors SHAIPCore DrawOp.canonical) ----
const Q = v => { if (!Number.isFinite(v)) throw new Error('non-finite value ' + v); return String(Math.floor(v * 1e4 + 0.5)); };
const parseColor = s => {
  if (typeof s !== 'string') throw new Error('expected a colour string');
  if (s[0] === '#') { const n = parseInt(s.slice(1), 16); return [n >> 16, (n >> 8) & 255, n & 255, 1]; }
  const m = /^rgba\(([^,]+),([^,]+),([^,]+),([^)]+)\)$/.exec(s);
  if (!m) throw new Error('unparsed colour ' + s);
  return [+m[1], +m[2], +m[3], +m[4]];
};
const col = c => `${c[0]},${c[1]},${c[2]},${Q(c[3])}`;
const grad = g => [Q(g.x0), Q(g.y0), Q(g.r0), Q(g.x1), Q(g.y1), Q(g.r1), ...g.stops.map(s => `${Q(s[0])},${col(s[1])}`)].join(',');
const conic = g => [Q(g.a), Q(g.x), Q(g.y), ...g.stops.map(s => `${Q(s[0])},${col(s[1])}`)].join(',');

class Recorder {
  constructor() {
    this.ops = []; this.path = []; this.stack = []; this.emitted = 'source-over';
    this.st = { fillStyle: '#000000', strokeStyle: '#000000', lineWidth: 1, globalAlpha: 1, gco: 'source-over', textAlign: 'start', m: [1, 0, 0, 1, 0, 0] };
  }
  get fillStyle() { return this.st.fillStyle; } set fillStyle(v) { this.st.fillStyle = v; }
  get strokeStyle() { return this.st.strokeStyle; } set strokeStyle(v) { this.st.strokeStyle = v; }
  get lineWidth() { return this.st.lineWidth; } set lineWidth(v) { this.st.lineWidth = v; }
  get globalAlpha() { return this.st.globalAlpha; } set globalAlpha(v) { if (v >= 0 && v <= 1) this.st.globalAlpha = v; }
  get globalCompositeOperation() { return this.st.gco; } set globalCompositeOperation(v) { this.st.gco = v; }
  get textAlign() { return this.st.textAlign; } set textAlign(v) { this.st.textAlign = v; }
  set font(v) { if (!/\b9px\b/.test(v)) throw new Error('unexpected font ' + v); }
  setTransform() { this.st.m = [1, 0, 0, 1, 0, 0]; }   // device-pixel scale: record in CSS px
  clearRect() {}
  save() { this.stack.push({ ...this.st, m: [...this.st.m] }); }
  restore() { this.st = this.stack.pop(); }
  translate(x, y) { const m = this.st.m; m[4] += m[0] * x + m[2] * y; m[5] += m[1] * x + m[3] * y; }
  scale(sx, sy) { const m = this.st.m; m[0] *= sx; m[1] *= sx; m[2] *= sy; m[3] *= sy; }
  identity() { const m = this.st.m; return m[0] === 1 && m[1] === 0 && m[2] === 0 && m[3] === 1 && m[4] === 0 && m[5] === 0; }
  beginPath() { this.path = []; }
  moveTo(x, y) { this.path.push(['M', x, y]); }
  lineTo(x, y) { this.path.push(['L', x, y]); }
  arc(x, y, r, a0, a1) { if (a0 !== 0 || a1 < 6.2831853) throw new Error('partial arc'); this.path.push(['A', x, y, r]); }
  measureText(t) { return { width: t.length * 9 * 0.6 }; }
  createRadialGradient(x0, y0, r0, x1, y1, r1) { const g = { kind: 'radial', x0, y0, r0, x1, y1, r1, stops: [] }; g.addColorStop = (o, c) => g.stops.push([o, parseColor(c)]); return g; }
  createConicGradient(a, x, y) { const g = { kind: 'conic', a, x, y, stops: [] }; g.addColorStop = (o, c) => g.stops.push([o, parseColor(c)]); return g; }
  emit(s) { const mode = this.st.gco === 'lighter' ? 'lighter' : 'source-over'; if (this.st.gco !== 'lighter' && this.st.gco !== 'source-over') throw new Error('gco ' + this.st.gco); if (mode !== this.emitted) { this.ops.push(`B,${mode === 'lighter' ? 1 : 0}`); this.emitted = mode; } this.ops.push(s); }
  withAlpha(c) { return [c[0], c[1], c[2], c[3] * this.st.globalAlpha]; }
  stroke() {
    if (!this.identity()) throw new Error('stroke under transform');
    const c = this.withAlpha(parseColor(this.st.strokeStyle)), w = this.st.lineWidth;
    let px = null, py = null;
    for (const s of this.path) {
      if (s[0] === 'M') { px = s[1]; py = s[2]; }
      else if (s[0] === 'L') { this.emit(`L,${Q(px)},${Q(py)},${Q(s[1])},${Q(s[2])},${col(c)},${Q(w)}`); px = s[1]; py = s[2]; }
      else this.emit(`R,${Q(s[1])},${Q(s[2])},${Q(s[3])},${col(c)},${Q(w)}`);
    }
  }
  fill() {
    if (this.path.length !== 1 || this.path[0][0] !== 'A') throw new Error('fill of non-circle path');
    const [, x, y, r] = this.path[0], fs = this.st.fillStyle;
    if (typeof fs === 'string') { if (!this.identity()) throw new Error('solid fill under transform'); this.emit(`D,${Q(x)},${Q(y)},${Q(r)},${col(this.withAlpha(parseColor(fs)))}`); return; }
    if (this.st.globalAlpha !== 1) throw new Error('gradient under globalAlpha');
    if (fs.kind === 'conic') { if (!this.identity()) throw new Error('conic under transform'); this.emit(`GC,${Q(x)},${Q(y)},${Q(r)},${conic(fs)}`); return; }
    if (this.identity()) { this.emit(`GD,${Q(x)},${Q(y)},${Q(r)},${grad(fs)}`); return; }
    const m = this.st.m;
    if (m[1] !== 0 || m[2] !== 0 || x !== 0 || y !== 0) throw new Error('unsupported ellipse transform');
    this.emit(`GE,${Q(m[4])},${Q(m[5])},${Q(m[0])},${Q(m[3])},${Q(r)},${grad(fs)}`);
  }
  fillRect(x, y, w, h) {
    if (!this.identity()) throw new Error('fillRect under transform');
    const fs = this.st.fillStyle;
    if (typeof fs === 'string') this.emit(`Q,${Q(x)},${Q(y)},${Q(w)},${Q(h)},${col(this.withAlpha(parseColor(fs)))}`);
    else { if (fs.kind !== 'radial' || this.st.globalAlpha !== 1) throw new Error('unsupported rect fill'); this.emit(`GR,${Q(x)},${Q(y)},${Q(w)},${Q(h)},${grad(fs)}`); }
  }
  drawImage(img, x, y, w, h) {
    if (!img || !img.__spr) throw new Error('drawImage of a non-sprite');
    if (!this.identity()) throw new Error('drawImage under transform');
    const c = parseColor(img.__spr);
    this.emit(`S,${c[0]},${c[1]},${c[2]},${Q(x + w / 2)},${Q(y + h / 2)},${Q(w)},${Q(this.st.globalAlpha)}`);
  }
  fillText(t, x, y) {
    if (!this.identity()) throw new Error('text under transform');
    const align = this.st.textAlign === 'left' ? 0 : this.st.textAlign === 'right' ? 1 : -1;
    if (align < 0) throw new Error('textAlign ' + this.st.textAlign);
    this.emit(`T,${t},${Q(x)},${Q(y)},${align},${col(this.withAlpha(parseColor(this.st.fillStyle)))}`);
  }
}

// ---- FNV-1a 64 over UTF-8 ----
const FNV_OFF = 0xcbf29ce484222325n, FNV_PRIME = 0x100000001b3n, M64 = (1n << 64n) - 1n;
const fnv = s => { let h = FNV_OFF; for (const b of Buffer.from(s, 'utf8')) { h ^= BigInt(b); h = (h * FNV_PRIME) & M64; } return h.toString(16).padStart(16, '0'); };

// ---- a mock canvas element driven through the engine's own draw() ----
globalThis.innerWidth = 4000; globalThis.innerHeight = 4000; globalThis.devicePixelRatio = 3;
const mkCanvas = (gfx, w, h, data) => {
  const c = { width: 0, height: 0, clientWidth: w, clientHeight: h, dataset: { gfx, ...data }, rec: null };
  c.getBoundingClientRect = () => ({ width: w, height: h, top: 0, left: 0, right: w, bottom: h });
  c.getContext = () => c.rec;
  return c;
};

const CY = '#5CF2FF', VI = '#8A9BB8', OK = '#62F5A8', WA = '#FFB547', BA = '#FF5C7A';
const base = { density: 210, hud: true, floor: true, quality: 'Ultra', reduceMotion: false, c1: CY, c2: VI, bad: BA, warn: WA,
  labels: [['SYD-03', 'ACTIVE · 15ms'], ['SIN-01', 'RELAY · 92ms'], ['TYO-04', 'STANDBY · 118ms'], ['FRA-01', 'DEDICATED · 268ms']],
  active: 0, hubLabels: { 0: ['SYD-03', '15ms · ACTIVE'], 1: ['SIN-01', '92ms · RELAY'], 2: ['TYO-04', '118ms'], 9: ['AKL-02', '38ms'] },
  radar: [['C2 BEACON BLOCKED', '185.220.101.4'], ['PHISH DOMAIN', 'acme-sso.co']] };

// Each scenario is a timeline of (ts, option overrides); `rec` marks the frames that are stored.
const T = (from, n, step) => Array.from({ length: n }, (_, i) => from + i * step);
const scenarios = [
  { name: 'net-connect', gfx: 'net', w: 390, h: 380, data: { cy: '0.5', r: '0.36', hudClear: '124' },
    frames: [...T(1000, 30, 16.6667).map(ts => ({ ts })), { ts: 9000 }, ...T(9016, 10, 16.6667).map(ts => ({ ts })),
             ...T(9200, 40, 16.6667).map(ts => ({ ts, connected: false })), ...T(9900, 50, 16.6667).map(ts => ({ ts, connected: true }))],
    rec: [0, 1, 29, 30, 35, 45, 52, 60, 79, 90, 100, 129] },
  { name: 'net-onboarding-60-nofloor-nohud', gfx: 'net', w: 390, h: 540, data: { cy: '0.5', r: '0.4' },
    frames: T(500, 40, 8.3333).map(ts => ({ ts, density: 60, floor: false, hud: false })), rec: [0, 39] },
  { name: 'net-lock-reduce-motion', gfx: 'net', w: 390, h: 520, data: { cy: '0.55', r: '0.42' },
    frames: T(2000, 20, 16.6667).map((ts, i) => ({ ts, density: 170, reduceMotion: i >= 10, connected: i < 5 })), rec: [4, 9, 19] },
  { name: 'globe-fra', gfx: 'globe', w: 390, h: 420, data: { r: '0.4' },
    frames: [...T(3000, 30, 16.6667).map(ts => ({ ts, active: 3, hubLabels: { ...base.hubLabels, 3: ['FRA-01', '270ms · ACTIVE'] } })),
             ...T(3500, 30, 16.6667).map(ts => ({ ts, active: 3, connected: false, hubLabels: { ...base.hubLabels, 3: ['FRA-01', 'STANDBY'] } }))],
    rec: [0, 29, 40, 59] },
  { name: 'globe-syd-long', gfx: 'globe', w: 390, h: 420, data: { r: '0.4' },
    frames: T(0, 400, 33.3333).map(ts => ({ ts })), rec: [0, 133, 266, 399] },
  { name: 'globe-reduce-motion', gfx: 'globe', w: 390, h: 420, data: { r: '0.4' },
    frames: T(100, 10, 16.6667).map(ts => ({ ts, reduceMotion: true, active: 12, hubLabels: { 12: ['MEL-01', '22ms · ACTIVE'] } })), rec: [9] },
  { name: 'radar-sweep', gfx: 'radar', w: 320, h: 280, data: { r: '0.4' },
    frames: T(0, 360, 16.6667).map(ts => ({ ts })), rec: [0, 60, 120, 180, 240, 300, 359] },
];

const out = { generator: 'clients/ios/scripts/engine-vectors.mjs', engine: path.basename(enginePath), quantum: 1e-4, measure: 'utf16 length * 9 * 0.6',
  base: { density: base.density, hud: base.hud, floor: base.floor, labels: base.labels, active: base.active, hubLabels: base.hubLabels, radar: base.radar }, scenarios: [] };
if (dumpDir) fs.mkdirSync(dumpDir, { recursive: true });
for (const sc of scenarios) {
  const c = mkCanvas(sc.gfx, sc.w, sc.h, sc.data);
  const recorded = [];
  sc.frames.forEach((f, i) => {
    const { ts, ...ov } = f;
    c.rec = new Recorder();
    E.draw(c, ts, { ...base, connected: true, ...ov });
    if (sc.rec.includes(i)) {
      const text = c.rec.ops.join('\n');
      const counts = {}; for (const op of c.rec.ops) { const k = op.slice(0, op.indexOf(',')); counts[k] = (counts[k] || 0) + 1; }
      recorded.push({ frame: i, ops: c.rec.ops.length, counts, fnv: fnv(text), head: c.rec.ops.slice(0, 12) });
      if (dumpDir) fs.writeFileSync(path.join(dumpDir, `${sc.name}-${i}.txt`), text + '\n');
    }
  });
  out.scenarios.push({ name: sc.name, gfx: sc.gfx, w: sc.w, h: sc.h, data: sc.data, frames: sc.frames, recorded });
}

// Geometry facts: deterministic generation is what makes the hashes reproducible at all.
const r11 = E.rng(11), r5 = E.rng(5);
const net210 = E.genNet(210), net60 = E.genNet(60), net170 = E.genNet(170), globe = E.genGlobe(), radar = E.genRadar();
const geomText = G => G.P.map(n => `${n.k},${n.p.map(Q).join(',')},${Q(n.r)}`).join('\n') + '\n#\n' + G.L.map(l => `${l[0]},${l[1]},${Q(l[2])},${l[3]}`).join('\n') + '\n#\n' + G.hubs.join(',') + ',' + Q(G.maxd);
out.geometry = {
  // mulberry32 outputs are k / 2^32: store k, exact through any JSON parser
  rng11: Array.from({ length: 8 }, () => r11() * 4294967296), rng5: Array.from({ length: 8 }, () => r5() * 4294967296),
  net: Object.fromEntries([[210, net210], [170, net170], [60, net60]].map(([n, G]) => [n, { nodes: G.P.length, links: G.L.length, trunks: G.L.filter(l => l[3]).length, hubs: G.hubs, maxd: G.maxd, fnv: fnv(geomText(G)) }])),
  globe: { land: globe.land.length, sea: globe.sea.length, grid: globe.grid.length, hubs: globe.hubs.length, arcs: globe.arcs.length,
           fnv: fnv([globe.land, globe.sea].map(a => a.map(v => v.map(Q).join(',')).join(';')).join('#')) },
  radar: { blips: radar.B.length, threats: radar.B.map((b, i) => b.s === 2 ? i : -1).filter(i => i >= 0), warns: radar.B.filter(b => b.s === 1).length,
           fnv: fnv(radar.B.map(b => `${Q(b.a)},${Q(b.r)},${b.s}`).join(';')) },
};
// Telemetry formulas, verbatim from renderVals() in SHAIP iOS v2.dc.html: values and the strings
// the screens print (toFixed rounding, Math.round ties).
const f = k => 150 + 28 * Math.sin(k * .55) + 16 * Math.sin(k * 1.7 + 1) + 8 * Math.sin(k * 3.1);
const g = k => 38 + 10 * Math.sin(k * .8 + 2) + 6 * Math.sin(k * 2.3);
const ticks = Array.from({ length: 160 }, (_, i) => i - 47);
out.telemetry = {
  ticks,
  down: ticks.map(t => f(t).toFixed(1)), downInt: ticks.map(t => f(t).toFixed(0)), up: ticks.map(t => g(t).toFixed(1)),
  rtt14: ticks.map(t => 14 + Math.round(Math.sin(t * 1.3) * 2)),
  jitter: ticks.map(t => (1.2 + Math.abs(Math.sin(t)) * .6).toFixed(1)),
  session: ticks.map(t => (2.41 + t * .018).toFixed(2)), packets: ticks.map(t => (1.84 + t * .0021).toFixed(2)),
  bars: [0, 3, 6].map(i => [0, 1, 77].map(t => Array.from({ length: 16 }, (_, k) => (3 + 13 * Math.abs(Math.sin(k * 1.7 + i * 0.9 + t * 0.35))).toFixed(1)))),
};
fs.writeFileSync(outPath, JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${outPath}: ${out.scenarios.reduce((a, s) => a + s.recorded.length, 0)} frames`);
for (const s of out.scenarios) console.log(`  ${s.name}: ${s.recorded.map(r => `#${r.frame} ${r.ops} ops ${r.fnv}`).join(' | ')}`);
