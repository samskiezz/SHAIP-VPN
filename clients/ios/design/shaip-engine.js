// SHAIP render engine — Canvas2D with perspective projection, additive bloom sprites, HUD overlays.
//
// Reference maths for the native port (clients/ios/SHAIPCore/Sources/SHAIPCore/Render), which
// reproduces this file op-for-op (see clients/ios/scripts/engine-vectors.mjs). Changes from the
// handoff as delivered, each a bug fix or a Motion/Accessibility item from HANDOFF.md:
//  - Floor reflection: the radial gradient was built in screen coordinates and then painted under
//    translate()+scale(), which moved its centre ~400 px off the ellipse; the reflection painted
//    nothing. It is now built at the ellipse's local origin.
//  - Radar HUD labels were handed to whichever threat blip happened to be visible, so "C2 BEACON
//    BLOCKED" jumped between three different blips. Each label is now bound to one threat blip.
//  - Globe: the ACTIVE hub (double pulse ring, larger glow, label) was hard-wired to Sydney and the
//    hub labels carried wrong node IDs (TYO-01, AKL-01). The active hub and the labels now come from
//    the caller (o.active, o.hubLabels) and the pulse fades out when the tunnel is down. LAX replaces
//    SFO and MEL is added so every node in the Nodes table exists on the globe.
//  - Connection changes ease over 550 ms (ease-in-out): the mesh palette cross-fades to grey and
//    its speed eases to 25% instead of snapping.
//  - Reduce Motion (o.reduceMotion): rotation frozen, pulses static, packets and streaks hidden.
//  - Mesh HUD labels can keep clear of a centre radius (data-hud-clear) so they don't sit under the orb.
//  - The backing store is also resized when only the height changes.
const RGB = {};
const rgb = h => RGB[h] || (RGB[h] = (n => [n >> 16, (n >> 8) & 255, n & 255])(parseInt(h.slice(1), 16)));
const rgba = (h, a) => { const c = rgb(h); a = a < 0 ? 0 : a > 1 ? 1 : a; return `rgba(${c[0]},${c[1]},${c[2]},${a})`; };
const SPR = {};
function spr(col) {
  if (SPR[col]) return SPR[col];
  const c = document.createElement('canvas'); c.width = c.height = 128;
  const x = c.getContext('2d'), g = x.createRadialGradient(64, 64, 0, 64, 64, 64);
  g.addColorStop(0, 'rgba(255,255,255,1)'); g.addColorStop(0.1, rgba(col, 1)); g.addColorStop(0.24, rgba(col, 0.42));
  g.addColorStop(0.5, rgba(col, 0.08)); g.addColorStop(1, rgba(col, 0));
  x.fillStyle = g; x.fillRect(0, 0, 128, 128); return SPR[col] = c;
}
function rng(seed) { return () => { seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function fib(n) { const o = []; for (let i = 0; i < n; i++) { const y = 1 - (i + .5) / n * 2, r = Math.sqrt(1 - y * y), th = i * 2.399963; o.push([Math.cos(th) * r, y, Math.sin(th) * r]); } return o; }
const ll = (la, lo) => { const p = la * Math.PI / 180, l = lo * Math.PI / 180; return [Math.cos(p) * Math.cos(l), Math.sin(p), Math.cos(p) * Math.sin(l)]; };
function proj(a, b, cx, cy, R, cam = 3.2) {
  const ca = Math.cos(a), sa = Math.sin(a), cb = Math.cos(b), sb = Math.sin(b);
  return (x, y, z) => { const X = x * ca + z * sa; let Z = -x * sa + z * ca; const Y = y * cb - Z * sb; Z = y * sb + Z * cb; const s = cam / (cam + Z); return [cx + X * R * s, cy - Y * R * s, Z, s, Math.max(0, Math.min(1, (1 - Z) / 2))]; };
}
function glowAt(ctx, col, x, y, size, alpha) { ctx.globalAlpha = alpha; ctx.drawImage(spr(col), x - size / 2, y - size / 2, size, size); ctx.globalAlpha = 1; }
function hudLabel(ctx, C, x, y, cx, w, l1, l2, al) {
  ctx.globalCompositeOperation = 'source-over';
  ctx.font = '500 9px ui-monospace, "SF Mono", Menlo, monospace';
  const tw = Math.max(ctx.measureText(l1).width, ctx.measureText(l2).width);
  let side = x > cx ? 1 : -1; if (x + side * (34 + tw) > w - 4 || x + side * (34 + tw) < 4) side = -side;
  const b = 7, l = 3; ctx.strokeStyle = rgba(C.c1, .85 * al); ctx.lineWidth = .75; ctx.beginPath();
  [[-1, -1], [1, -1], [1, 1], [-1, 1]].forEach(([sx, sy]) => { ctx.moveTo(x + sx * b, y + sy * (b - l)); ctx.lineTo(x + sx * b, y + sy * b); ctx.lineTo(x + sx * (b - l), y + sy * b); });
  ctx.stroke();
  const lx = x + side * 22, ly = y - 20;
  ctx.strokeStyle = rgba('#FFFFFF', .32 * al); ctx.beginPath(); ctx.moveTo(x + side * b, y - b); ctx.lineTo(lx, ly); ctx.lineTo(lx + side * (tw + 8), ly); ctx.stroke();
  ctx.textAlign = side > 0 ? 'left' : 'right';
  ctx.fillStyle = rgba('#F5F7FC', .95 * al); ctx.fillText(l1, lx + side * 4, ly - 5);
  ctx.fillStyle = rgba(C.c1, .75 * al); ctx.fillText(l2, lx + side * 4, ly + 11);
  ctx.globalCompositeOperation = 'lighter';
}

/* ---------- NET ---------- */
function genNet(n) {
  const r = rng(11), P = [], nc = Math.max(10, Math.round(n * .14)), nm = Math.round(n * .38), no = n - nc - nm;
  for (let i = 0; i < nc; i++) { const u = r() * 2 - 1, t = r() * 6.283, s = Math.sqrt(1 - u * u), q = .08 + .2 * r(); P.push({ p: [s * Math.cos(t) * q, u * q, s * Math.sin(t) * q], k: 0 }); }
  fib(nm).forEach(v => { const q = .56 + .1 * r(); P.push({ p: v.map(c => c * q + (r() - .5) * .05), k: 1 }); });
  fib(no).forEach(v => { const q = .97 + .06 * r(); P.push({ p: v.map(c => c * q), k: 2 }); });
  P.forEach(o => o.r = Math.hypot(...o.p));
  const D = (a, b) => Math.hypot(a.p[0] - b.p[0], a.p[1] - b.p[1], a.p[2] - b.p[2]);
  const L = [], seen = new Set();
  P.forEach((a, i) => {
    const c = []; P.forEach((b, j) => { if (i !== j && Math.abs(a.k - b.k) <= 1) c.push([D(a, b), j]); });
    c.sort((x, y) => x[0] - y[0]);
    c.slice(0, a.k === 2 ? 3 : 4).forEach(([d, j]) => { const key = i < j ? i + '_' + j : j + '_' + i; if (!seen.has(key)) { seen.add(key); L.push([i, j, d, 0]); } });
  });
  const hubs = []; for (let i = 0; i < 6; i++) hubs.push(nc + nm + Math.floor(i * no / 6 + no / 12));
  hubs.forEach(h => { let best = 0, bd = 9; for (let j = 0; j < nc; j++) { const d = D(P[h], P[j]); if (d < bd) { bd = d; best = j; } } L.push([h, best, bd, 1]); });
  return { P, L, hubs, maxd: Math.max(...L.filter(l => !l[3]).map(l => l[2])) };
}
function drawNet(ctx, w, h, G, o, ph, ts, C) {
  const cx = w / 2, cy = h * o.cyF, R = Math.min(w, h) * o.rF, mix = o.mix, lerp = (a, b) => a + (b - a) * mix;
  const pr = proj(ph * .00012, -.3 - .08 * Math.sin(ph * .00017), cx, cy, R);
  let g = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 1.5);
  g.addColorStop(0, rgba(C.c1, lerp(.04, .15))); g.addColorStop(.45, rgba(C.c2, lerp(.02, .06))); g.addColorStop(1, rgba(C.c2, 0));
  ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
  if (o.floor) {
    const fy = -1.3, E = 2.2, S = .275; ctx.lineWidth = .6;
    for (let ax = 0; ax < 2; ax++) for (let k = -8; k <= 8; k++) {
      let prev = null;
      for (let m = 0; m <= 16; m++) {
        const u = k * S, v = -E + m * E / 8, x = ax ? u : v, z = ax ? v : u, q = pr(x, fy, z);
        if (prev) { const al = .17 * (1 - Math.hypot(x, z) / E); if (al > 0) { ctx.strokeStyle = rgba(C.c2, al); ctx.beginPath(); ctx.moveTo(prev[0], prev[1]); ctx.lineTo(q[0], q[1]); ctx.stroke(); } }
        prev = q;
      }
    }
    // Gradients paint in the coordinate space current at fill time, so build it at the local origin.
    const fq = pr(0, fy, 0); g = ctx.createRadialGradient(0, 0, 0, 0, 0, R * 1.2);
    g.addColorStop(0, rgba(C.c1, lerp(.05, .2))); g.addColorStop(1, rgba(C.c1, 0));
    ctx.save(); ctx.translate(fq[0], fq[1]); ctx.scale(1, .3); ctx.fillStyle = g; ctx.beginPath(); ctx.arc(0, 0, R * 1.2, 0, 7); ctx.fill(); ctx.restore();
  }
  ctx.globalCompositeOperation = 'lighter';
  [[1.22, .9, .00021, 0], [1.4, -.5, -.00014, 1], [1.1, 1.9, .00028, 2]].forEach(([rr, tilt, sp, i]) => {
    const ct = Math.cos(tilt), st = Math.sin(tilt), rot = ph * sp, cr = Math.cos(rot), sr = Math.sin(rot);
    const pt = t => { const x = Math.cos(t) * rr, z = Math.sin(t) * rr, y2 = -z * st, z2 = z * ct; return pr(x * cr + z2 * sr, y2, -x * sr + z2 * cr); };
    let prev = pt(0); ctx.lineWidth = i === 1 ? .6 : .8;
    for (let s = 1; s <= 120; s++) {
      const q = pt(s / 120 * 6.2832);
      if (!(i === 1 && s % 3 === 0)) { ctx.strokeStyle = rgba(i === 2 ? C.c2 : C.c1, (.04 + .3 * q[4] * q[4]) * lerp(.5, 1)); ctx.beginPath(); ctx.moveTo(prev[0], prev[1]); ctx.lineTo(q[0], q[1]); ctx.stroke(); }
      prev = q;
    }
    if (mix > 0) { const q = pt(ph * .0005 * (i + 1)); glowAt(ctx, C.c1, q[0], q[1], 30 * q[3], (.3 + .7 * q[4]) * mix); }
  });
  const P = G.P.map(n => pr(...n.p));
  const wv = ((ph * .00032) % 1) * 1.5 - .1;
  const glow = G.P.map(n => Math.max(0, 1 - Math.abs(n.r - wv) / .14) * mix);
  for (const [i, j, d, tr] of G.L) {
    const A = P[i], B = P[j], dd = (A[4] + B[4]) / 2, lit = Math.max(glow[i], glow[j]);
    const base = tr ? .14 : .05 + (1 - d / G.maxd) * .12;
    ctx.lineWidth = tr ? .9 : .4 + .7 * dd;
    ctx.strokeStyle = rgba(lit > .2 || tr ? C.c1 : C.c2, (base + .36 * dd * dd) * (1 + lit * 2.2) * lerp(.5, 1));
    ctx.beginPath(); ctx.moveTo(A[0], A[1]); ctx.lineTo(B[0], B[1]); ctx.stroke();
  }
  if (mix > 0 && !o.reduceMotion) {
    const L = G.L, K = Math.min(44, L.length);
    for (let k = 0; k < K; k++) {
      const l = L[(k * 61 + 7) % L.length], A = P[l[0]], B = P[l[1]], dd = (A[4] + B[4]) / 2, t = (ph * (.0005 + (k % 5) * .00012) + k * .287) % 1;
      for (let m = 6; m >= 1; m--) { const tt = t - m * .03; if (tt < 0) continue; ctx.fillStyle = rgba(C.c1, (1 - m / 7) * (.3 + .7 * dd) * mix); ctx.fillRect(A[0] + (B[0] - A[0]) * tt - .6, A[1] + (B[1] - A[1]) * tt - .6, 1.2, 1.2); }
      const x = A[0] + (B[0] - A[0]) * t, y = A[1] + (B[1] - A[1]) * t;
      glowAt(ctx, '#FFFFFF', x, y, 9, (.3 + .7 * dd) * mix);
    }
  }
  const ord = P.map((q, i) => i).sort((x, y) => P[y][2] - P[x][2]);
  for (const i of ord) {
    const q = P[i], n = G.P[i], gl = glow[i], hub = G.hubs.includes(i);
    const base = hub ? 3 : n.k === 0 ? 1.9 : n.k === 1 ? 1.45 : 1.15, r = base * q[3] * (1 + gl * 1.1);
    const col = hub || n.k === 0 ? C.c1 : (i % 4 ? C.c2 : C.c1);
    const al = Math.min(1, (.15 + .85 * q[4] * q[4]) * lerp(.55, 1) + gl * .4);
    glowAt(ctx, col, q[0], q[1], r * (hub ? 9 : 6), al);
    ctx.fillStyle = rgba('#FFFFFF', al * (hub ? .95 : .6)); ctx.beginPath(); ctx.arc(q[0], q[1], r * .5, 0, 7); ctx.fill();
  }
  G.hubs.forEach((hI, idx) => {
    const q = P[hI]; if (q[4] < .5 || !(mix > 0)) return;
    const p = (ts * .0007 + idx * .19) % 1; ctx.strokeStyle = rgba(C.c1, (1 - p) * .55 * q[4] * mix); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(q[0], q[1], 4 + p * 18, 0, 7); ctx.stroke();
  });
  if (o.hud) G.hubs.slice(0, 4).forEach((hI, idx) => {
    const q = P[hI]; if (q[4] < .58) return; const lab = o.labels[idx] || ['', ''];
    if (o.hudClear > 0 && Math.hypot(q[0] - cx, q[1] - cy) < o.hudClear) return;
    hudLabel(ctx, C, q[0], q[1], cx, w, lab[0], mix >= .5 ? lab[1] : 'STANDBY', Math.min(1, (q[4] - .58) * 5) * lerp(.5, 1));
  });
}

/* ---------- GLOBE ---------- */
const LAND = [[48, -100, 18, 28], [62, -110, 10, 30], [20, -100, 10, 10], [-12, -58, 20, 13], [-35, -65, 10, 7], [52, 12, 9, 18], [60, 40, 10, 30], [8, 20, 22, 18], [-22, 25, 12, 12], [48, 95, 16, 45], [30, 80, 8, 18], [22, 78, 9, 7], [12, 103, 9, 9], [0, 115, 6, 14], [-25, 134, 11, 17], [72, -40, 7, 16], [36, 138, 6, 5], [64, -150, 6, 12], [-6, 142, 4, 7]];
const isLand = (la, lo) => LAND.some(([a, b, ra, rb]) => { let dl = lo - b; if (dl > 180) dl -= 360; if (dl < -180) dl += 360; return ((la - a) / ra) ** 2 + (dl / rb) ** 2 < 1; });
// Hub order is fixed: arcs index into it. LAX (a node in the Nodes table) replaces SFO; MEL is appended.
const CITIES = [[-33.9, 151.2, 'SYD'], [1.3, 103.8, 'SIN'], [35.7, 139.7, 'TYO'], [50.1, 8.7, 'FRA'], [51.5, -.1, 'LON'], [40.7, -74, 'NYC'], [33.9, -118.4, 'LAX'], [-23.5, -46.6, 'GRU'], [19, 72.8, 'BOM'], [-36.8, 174.7, 'AKL'], [43.7, -79.4, 'YYZ'], [25.2, 55.3, 'DXB'], [-37.8, 145, 'MEL']];
const ARCS = [[0, 1], [0, 2], [1, 3], [3, 4], [4, 5], [5, 6], [0, 9], [1, 8], [8, 11], [11, 3], [6, 2], [5, 7]];
function genGlobe() {
  const land = [], sea = [];
  fib(4200).forEach((v, i) => { const la = Math.asin(v[1]) * 180 / Math.PI, lo = Math.atan2(v[2], v[0]) * 180 / Math.PI; if (isLand(la, lo)) land.push(v); else if (i % 5 === 0) sea.push(v); });
  const grid = [];
  for (let lo = -180; lo < 180; lo += 30) { const a = []; for (let la = -90; la <= 90; la += 6) a.push(ll(la, lo)); grid.push(a); }
  for (let la = -60; la <= 60; la += 30) { const a = []; for (let lo = -180; lo <= 180; lo += 6) a.push(ll(la, lo)); grid.push(a); }
  const hubs = CITIES.map(([a, b]) => ll(a, b));
  const arcs = ARCS.map(([i, j]) => { const A = hubs[i], B = hubs[j], s = []; for (let k = 0; k <= 40; k++) { const t = k / 40, x = A[0] + (B[0] - A[0]) * t, y = A[1] + (B[1] - A[1]) * t, z = A[2] + (B[2] - A[2]) * t, L = Math.hypot(x, y, z), f = (1 + .25 * Math.sin(Math.PI * t)) / L; s.push([x * f, y * f, z * f]); } return s; });
  return { land, sea, grid, hubs, arcs };
}
function drawGlobe(ctx, w, h, G, o, ph, ts, C) {
  const cx = w / 2, cy = h / 2, R = Math.min(w, h) * o.rF, cam = 3.6, Rs = R * cam / Math.sqrt(cam * cam - 1);
  const pr = proj(ph * .00009 + 2.2, -.32, cx, cy, R, cam);
  let g = ctx.createRadialGradient(cx, cy, Rs * .92, cx, cy, Rs * 1.4);
  g.addColorStop(0, rgba(C.c1, .3)); g.addColorStop(.2, rgba(C.c1, .1)); g.addColorStop(.5, rgba(C.c2, .05)); g.addColorStop(1, rgba(C.c2, 0));
  ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
  g = ctx.createRadialGradient(cx - Rs * .35, cy - Rs * .45, Rs * .05, cx, cy, Rs);
  g.addColorStop(0, 'rgba(46,70,130,0.55)'); g.addColorStop(.6, 'rgba(10,16,34,0.92)'); g.addColorStop(1, 'rgba(3,5,12,0.98)');
  ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, Rs, 0, 7); ctx.fill();
  ctx.strokeStyle = rgba(C.c1, .45); ctx.lineWidth = 1; ctx.stroke();
  ctx.globalCompositeOperation = 'lighter';
  ctx.lineWidth = .6;
  G.grid.forEach(line => { let prev = pr(...line[0]); for (let k = 1; k < line.length; k++) { const q = pr(...line[k]); if (q[4] > .45) { ctx.strokeStyle = rgba(C.c2, .02 + .14 * q[4] * q[4]); ctx.beginPath(); ctx.moveTo(prev[0], prev[1]); ctx.lineTo(q[0], q[1]); ctx.stroke(); } prev = q; } });
  ctx.fillStyle = C.c2;
  for (const v of G.sea) { const q = pr(...v); if (q[4] < .5) continue; ctx.globalAlpha = .18 * q[4]; ctx.fillRect(q[0] - .4, q[1] - .4, .8, .8); }
  ctx.fillStyle = C.c1;
  for (const v of G.land) { const q = pr(...v); if (q[4] < .44) continue; const r = (.5 + .9 * q[4]) * q[3]; ctx.globalAlpha = .12 + .78 * q[4] ** 1.6; ctx.fillRect(q[0] - r / 2, q[1] - r / 2, r, r); }
  ctx.globalAlpha = 1;
  const sl = Math.sin(ph * .00035) * 62; let prev = null; ctx.lineWidth = 1.2;
  for (let lo = -180; lo <= 180; lo += 4) { const q = pr(...ll(sl, lo)); if (prev && q[4] > .5) { ctx.strokeStyle = rgba(C.c1, .55 * q[4]); ctx.beginPath(); ctx.moveTo(prev[0], prev[1]); ctx.lineTo(q[0], q[1]); ctx.stroke(); } prev = q; }
  G.arcs.forEach((arc, k) => {
    const S = arc.map(p => pr(...p)); ctx.lineWidth = .8;
    for (let s = 1; s < S.length; s++) { ctx.strokeStyle = rgba(C.c1, .04 + .22 * S[s][4] ** 2); ctx.beginPath(); ctx.moveTo(S[s - 1][0], S[s - 1][1]); ctx.lineTo(S[s][0], S[s][1]); ctx.stroke(); }
    if (o.reduceMotion) return;
    const t = (ph * .00026 + k * .137) % 1, head = t * 40; ctx.lineWidth = 1.8;
    for (let s = Math.max(1, Math.floor(head - 12)); s <= Math.min(40, head); s++) { const f = 1 - (head - s) / 12; ctx.strokeStyle = rgba(C.c1, f * (.2 + .8 * S[s][4])); ctx.beginPath(); ctx.moveTo(S[s - 1][0], S[s - 1][1]); ctx.lineTo(S[s][0], S[s][1]); ctx.stroke(); }
    const q = S[Math.min(40, Math.round(head))]; glowAt(ctx, '#FFFFFF', q[0], q[1], 12, .3 + .7 * q[4]);
  });
  const act = o.active ?? 0, labels = o.hubLabels || {};
  G.hubs.forEach((p, i) => {
    const q = pr(...p); if (q[4] < .42) return;
    const a = i === act;
    glowAt(ctx, C.c1, q[0], q[1], a ? 46 : 26, q[4]);
    ctx.fillStyle = rgba('#FFFFFF', q[4]); ctx.beginPath(); ctx.arc(q[0], q[1], a ? 2.6 : 1.6, 0, 7); ctx.fill();
    if (a && o.link > 0) for (let m = 0; m < 2; m++) { const p2 = (ts * .0008 + m * .5) % 1; ctx.strokeStyle = rgba(C.c1, (1 - p2) * .7 * q[4] * o.link); ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(q[0], q[1], 4 + p2 * 24, 0, 7); ctx.stroke(); }
    const lab = labels[i];
    if (o.hud && lab && q[4] > .6) hudLabel(ctx, C, q[0], q[1], cx, w, lab[0], lab[1], Math.min(1, (q[4] - .6) * 5));
  });
}

/* ---------- RADAR ---------- */
function genRadar() { const r = rng(5), B = []; for (let i = 0; i < 22; i++) B.push({ a: r() * 6.283, r: .18 + .76 * r(), s: r() < .18 ? 2 : r() < .45 ? 1 : 0 }); return { B }; }
function drawRadar(ctx, w, h, G, o, ph, ts, C) {
  const cx = w / 2, cy = h / 2, R = Math.min(w, h) * o.rF, A = (ph * .0011) % 6.2832;
  let g = ctx.createRadialGradient(cx, cy, 0, cx, cy, R * 1.2); g.addColorStop(0, rgba(C.c1, .1)); g.addColorStop(1, rgba(C.c1, 0));
  ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
  ctx.lineWidth = .7;
  for (let k = 1; k <= 4; k++) { ctx.strokeStyle = rgba(C.c1, k === 4 ? .35 : .12); ctx.beginPath(); ctx.arc(cx, cy, R * k / 4, 0, 7); ctx.stroke(); }
  ctx.strokeStyle = rgba(C.c1, .08); ctx.beginPath(); ctx.moveTo(cx - R, cy); ctx.lineTo(cx + R, cy); ctx.moveTo(cx, cy - R); ctx.lineTo(cx, cy + R); ctx.stroke();
  for (let k = 0; k < 120; k++) { const a = k / 120 * 6.2832, l = k % 10 ? 4 : 9; ctx.strokeStyle = rgba(C.c1, k % 10 ? .25 : .6); ctx.beginPath(); ctx.moveTo(cx + Math.cos(a) * (R + 3), cy + Math.sin(a) * (R + 3)); ctx.lineTo(cx + Math.cos(a) * (R + 3 + l), cy + Math.sin(a) * (R + 3 + l)); ctx.stroke(); }
  ctx.globalCompositeOperation = 'lighter';
  if (ctx.createConicGradient) {
    const span = 1.3, f = span / 6.2832; g = ctx.createConicGradient(A - span, cx, cy);
    g.addColorStop(0, rgba(C.c1, 0)); g.addColorStop(f, rgba(C.c1, .34)); g.addColorStop(Math.min(1, f + .002), rgba(C.c1, 0)); g.addColorStop(1, rgba(C.c1, 0));
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.fill();
  }
  ctx.strokeStyle = rgba(C.c1, .9); ctx.lineWidth = 1.2; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(A) * R, cy + Math.sin(A) * R); ctx.stroke();
  let n = 0;
  G.B.forEach(b => {
    const dt = ((A - b.a) % 6.2832 + 6.2832) % 6.2832, al = Math.pow(1 - dt / 6.2832, 2.5), col = b.s === 2 ? C.bad : b.s === 1 ? C.warn : C.c1;
    const x = cx + Math.cos(b.a) * b.r * R, y = cy + Math.sin(b.a) * b.r * R;
    glowAt(ctx, col, x, y, b.s ? 26 : 16, .15 + .85 * al);
    if (b.s === 2) { const lab = o.radar && o.radar[n]; if (o.hud && lab && al > .35) hudLabel(ctx, { c1: C.bad }, x, y, cx, w, lab[0], lab[1], Math.min(1, (al - .35) * 3)); n++; }
  });
  glowAt(ctx, C.c1, cx, cy, 30, 1);
}

const STATE = new WeakMap();
const ease = u => u < .5 ? 4 * u * u * u : 1 - Math.pow(-2 * u + 2, 3) / 2;
const mixHex = (a, b, t) => { const x = rgb(a), y = rgb(b); return '#' + [0, 1, 2].map(i => Math.round(x[i] + (y[i] - x[i]) * t).toString(16).padStart(2, '0')).join('').toUpperCase(); };
export function draw(c, ts, o) {
  const st0 = STATE.get(c), rect = c.getBoundingClientRect();
  if (!rect.width || rect.bottom < 0 || rect.top > innerHeight || rect.right < 0 || rect.left > innerWidth) { if (st0) st0.last = ts; return; }
  const w = c.clientWidth, h = c.clientHeight, dpr = o.quality === 'Standard' ? Math.min(2, devicePixelRatio || 1) : Math.max(3, devicePixelRatio || 1);
  if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) { c.width = Math.round(w * dpr); c.height = Math.round(h * dpr); }
  const mode = c.dataset.gfx; let st = st0;
  if (!st || (mode === 'net' && st.n !== o.density)) { st = { G: mode === 'globe' ? genGlobe() : mode === 'radar' ? genRadar() : genNet(o.density), ph: st0 ? st0.ph : 0, last: ts, n: o.density, u: st0 ? st0.u : (o.connected ? 1 : 0) }; STATE.set(c, st); }
  const dt = Math.min(50, Math.max(0, ts - st.last)); st.last = ts;
  st.u = Math.max(0, Math.min(1, st.u + (o.connected ? dt : -dt) / 550));
  const link = ease(st.u), mix = mode === 'net' ? link : 1;
  if (!o.reduceMotion) st.ph += dt * (.25 + .75 * mix);
  const C = { c1: mixHex('#8A93A8', o.c1, mix), c2: mixHex('#3E4558', o.c2, mix), bad: o.bad, warn: o.warn };
  const ctx = c.getContext('2d'); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, w, h);
  ctx.globalCompositeOperation = 'source-over'; ctx.globalAlpha = 1;
  const oo = { ...o, mix, link, cyF: +(c.dataset.cy || .5), rF: +(c.dataset.r || (mode === 'globe' ? .38 : mode === 'radar' ? .4 : .34)), hudClear: +(c.dataset.hudClear || 0) };
  const t = o.reduceMotion ? 0 : ts;
  if (mode === 'globe') drawGlobe(ctx, w, h, st.G, oo, st.ph, t, C);
  else if (mode === 'radar') drawRadar(ctx, w, h, st.G, oo, st.ph, t, C);
  else drawNet(ctx, w, h, st.G, oo, st.ph, t, C);
  ctx.globalCompositeOperation = 'source-over'; ctx.globalAlpha = 1;
}
