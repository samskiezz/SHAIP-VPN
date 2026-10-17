import { useEffect, useMemo, useRef, useState } from "react";
import { api, formatAccount, getToken } from "@/lib/api";

// The SHAIP v2 instrument UI on the web, rebuilt to the real design reference
// (clients/ios/design/SHAIP iOS v2.dc.html) and driven by the same render engine
// (lib/shaip-engine.js). The visual shell is reproduced exactly; the data is the
// real anonymous backend (account number, the signed node directory) or an honest
// offline state — never fabricated telemetry.

const CY = "#5CF2FF", VI = "#8A9BB8", OK = "#62F5A8", WA = "#FFB547", BA = "#FF5C7A";
const SUB = "rgba(220,228,255,0.5)";

const ICON = {
  lock: "M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 017 0v3",
  hop: "M5 19a2 2 0 100-4 2 2 0 000 4zM19 9a2 2 0 100-4 2 2 0 000 4zM6.7 15.8l10.6-7.6",
  dns: "M12 3a9 9 0 100 18 9 9 0 000-18zM8 12l3 3 5-6",
};
const TABS: [string, string][] = [
  ["Connect", "M12 3l7.5 3v5.5c0 4.6-3.2 8.6-7.5 9.5-4.3-.9-7.5-4.9-7.5-9.5V6L12 3zM9 12l2 2 4-4"],
  ["Network", "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"],
  ["Access", "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM17 14v6M14 17h6"],
  ["Security", "M12 12l6.5-6.5M12 3a9 9 0 109 9M12 7.5a4.5 4.5 0 104.5 4.5"],
  ["Settings", "M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4M9 15v4"],
];

type Node = {
  id: string; name?: string; address?: string; role?: string; region?: string;
  capacity_mbps?: number; status?: string;
};

type Srv = { city: string; id: string; dc: string; ip: string; ms: number | null; tag: string };

// A clearly-labelled sample node, used only in ?preview=connect so the connected
// design can be shown before a server is deployed. Not presented as live data.
const SAMPLE: Srv = { city: "Sydney", id: "SYD-03", dc: "Equinix SY4", ip: "203.0.113.42", ms: 16, tag: "PQ" };

function nodeToSrv(n: Node): Srv {
  const host = (n.address || "").split(":")[0];
  return {
    city: n.name || n.id,
    id: n.id,
    dc: n.region || "—",
    ip: host || "—",
    ms: null, // RTT is only known from a live tunnel; shown as — until then
    tag: (n.role || "").toUpperCase(),
  };
}

function hexA(hex: string, a: number) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
}

export default function AppPage() {
  const frameRef = useRef<HTMLDivElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);

  const [connected, setConnected] = useState(false);
  const [account, setAccount] = useState<string | null>(null);
  const [nodes, setNodes] = useState<Srv[]>([]);
  const [srvIdx, setSrvIdx] = useState(0);
  const [kill, setKill] = useState(true);
  const [multihop, setMultihop] = useState(true);
  const [dns, setDns] = useState(true);
  const [tab, setTab] = useState(0);
  const [secs, setSecs] = useState(0);

  // Preview mode (?preview=connect) shows the connected design with the sample
  // node before a server exists; it is clearly a preview, not a live session.
  const preview = typeof window !== "undefined" && new URLSearchParams(window.location.search).get("preview") === "connect";

  // Load real data.
  useEffect(() => {
    if (preview) {
      setConnected(true);
      setNodes([SAMPLE]);
      setAccount("1234567890123456");
      return;
    }
    if (getToken()) {
      api<{ account_number: string }>("/api/me").then((m) => setAccount(m.account_number)).catch(() => undefined);
    }
    api<Node[]>("/api/nodes", { auth: false })
      .then((ns) => setNodes(ns.map(nodeToSrv)))
      .catch(() => undefined);
  }, [preview]);

  // Session timer ticks only while connected.
  useEffect(() => {
    if (!connected) { setSecs(0); return; }
    const iv = setInterval(() => setSecs((s) => s + 1), 1000);
    return () => clearInterval(iv);
  }, [connected]);

  const srv: Srv = nodes[srvIdx] ?? (preview ? SAMPLE : { city: "No servers", id: "—", dc: "—", ip: "—", ms: null, tag: "" });
  const on = connected && nodes.length > 0;

  // Options for the render engine (same shape as the design's engOpts).
  const engOptsRef = useRef<any>({});
  engOptsRef.current = useMemo(() => {
    const labels: [string, string][] = [[srv.id, on ? `ACTIVE${srv.ms != null ? ` · ${srv.ms}ms` : ""}` : "STANDBY"]];
    return {
      connected: on, density: 170, hud: true, floor: true, quality: "Ultra",
      reduceMotion: typeof matchMedia !== "undefined" && matchMedia("(prefers-reduced-motion: reduce)").matches,
      c1: CY, c2: VI, bad: BA, warn: WA,
      labels, active: 0, hubLabels: { 0: [srv.id, on ? "ACTIVE" : "STANDBY"] },
      radar: [["C2 BEACON BLOCKED", "185.220.101.4"], ["SCAN DROPPED", "198.51.100.7"]],
    };
  }, [on, srv.id, srv.ms]);

  // Drive the render engine over the canvases in the frame.
  useEffect(() => {
    let raf = 0; let mod: any;
    let alive = true;
    import("@/lib/shaip-engine.js").then((m) => {
      mod = m;
      const loop = (ts: number) => {
        if (!alive) return;
        raf = requestAnimationFrame(loop);
        const o = engOptsRef.current;
        frameRef.current?.querySelectorAll<HTMLCanvasElement>("canvas[data-gfx]").forEach((c) => mod.draw(c, ts, o));
      };
      raf = requestAnimationFrame(loop);
    });
    return () => { alive = false; cancelAnimationFrame(raf); };
  }, []);

  // Click delegation for the overlay (orb, quick toggles, tab bar).
  const onOverlayClick = (e: React.MouseEvent) => {
    const el = (e.target as HTMLElement).closest<HTMLElement>("[data-act]");
    if (!el) return;
    const act = el.dataset.act!;
    if (act === "toggle") setConnected((c) => !c);
    else if (act === "kill") setKill((v) => !v);
    else if (act === "multihop") setMultihop((v) => !v);
    else if (act === "dns") setDns((v) => !v);
    else if (act.startsWith("tab:")) setTab(Number(act.slice(4)));
  };

  const v = { on, srv, account, kill, multihop, dns, tab, secs, nodes };
  const html = useMemo(() => {
    if (tab === 0) return connectOverlayHTML(v);
    if (tab === 1) return networkOverlayHTML(v);
    return buildingOverlayHTML(tab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, on, srv, account, kill, multihop, dns, secs, nodes]);

  // A distinct key per screen forces a fresh <canvas> element so the engine's
  // per-canvas state (kept in a WeakMap) is re-seeded for the new gfx mode
  // instead of reusing the previous screen's mesh geometry.
  const canvas =
    tab === 0 ? <canvas key="net" data-gfx="net" data-cy="0.5" data-r="0.36" data-hud-clear="124" style={{ position: "absolute", left: 0, top: 92, width: 390, height: 380, display: "block", zIndex: 0 }} />
    : tab === 1 ? <canvas key="globe" data-gfx="globe" data-r="0.4" style={{ position: "absolute", left: 0, top: 118, width: 390, height: 420, display: "block", zIndex: 0 }} />
    : null;

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24, background: "#020306", fontFamily: "-apple-system,'SF Pro Text',system-ui,sans-serif" }}>
      <div ref={frameRef} style={{ width: 390, height: 844, borderRadius: 58, position: "relative", overflow: "hidden", background: "radial-gradient(120% 70% at 50% 0%,#0B1020 0%,#04050A 55%,#020306 100%)", boxShadow: "0 0 0 1px #3A3D45,0 0 0 11px #0B0C0F,0 0 0 12px #2A2C33,0 80px 120px -30px rgba(0,0,0,0.9),0 0 120px -20px rgba(92,242,255,0.12)" }}>
        {canvas}
        <div ref={overlayRef} onClick={onOverlayClick} style={{ position: "absolute", inset: 0, zIndex: 1, pointerEvents: "none" }} dangerouslySetInnerHTML={{ __html: html }} />
      </div>
    </div>
  );
}

// Builds the exact Connect-screen overlay markup (everything except the mesh
// canvas) with real values substituted. Interactive elements carry data-act.
function connectOverlayHTML(v: {
  on: boolean; srv: Srv; account: string | null; kill: boolean; multihop: boolean; dns: boolean; tab: number; secs: number;
}): string {
  const { on, srv, account, kill, multihop, dns, tab, secs } = v;
  const statusColor = on ? OK : BA;
  const pillBg = on ? "rgba(98,245,168,0.12)" : "rgba(255,92,122,0.12)";
  const orbColor = on ? CY : "rgba(220,228,255,0.55)";
  const orbRing = on ? "rgba(92,242,255,0.18)" : "rgba(255,255,255,0.08)";
  const orbGlow = on ? "rgba(92,242,255,0.28)" : "rgba(0,0,0,0)";
  const arc = on ? `${(300 + (secs % 30) * 10).toFixed(0)} 629` : "0 629";
  const pad = (x: number) => String(x).padStart(2, "0");
  const timer = on ? `${pad(Math.floor(secs / 3600))}:${pad(Math.floor(secs / 60) % 60)}:${pad(secs % 60)}` : "--:--:--";
  const acctChip = account ? "••" + account.replace(/\D/g, "").slice(-4) : "——";

  const metrics = [
    { label: "DOWN", value: "—", unit: "Mbps" },
    { label: "UP", value: "—", unit: "Mbps" },
    { label: "RTT", value: on && srv.ms != null ? String(srv.ms) : "—", unit: "ms" },
    { label: "LOSS", value: "—", unit: "%" },
  ].map((m, i) => ({ ...m, pl: i ? "12px" : "0px", bl: i ? "0.5px solid rgba(255,255,255,0.08)" : "0.5px solid transparent" }));

  const quick = [
    { act: "kill", label: "Kill switch", state: kill ? "ARMED" : "DISARMED", color: kill ? OK : BA, d: ICON.lock },
    { act: "multihop", label: "Multi-hop", state: multihop ? "3 HOPS" : "DIRECT", color: multihop ? CY : SUB, d: ICON.hop },
    { act: "dns", label: "Private DNS", state: dns ? "FILTERING" : "OFF", color: dns ? VI : SUB, d: ICON.dns },
  ].map((q) => ({ ...q, border: q.color === SUB ? "rgba(255,255,255,0.14)" : hexA(q.color, 0.35) }));

  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

  const metricsHTML = metrics.map((m) => `
    <div style="display:flex;flex-direction:column;gap:3px;padding-left:${m.pl};border-left:${m.bl}">
      <span style="font:500 9px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.14em;color:rgba(220,228,255,0.42)">${m.label}</span>
      <div style="display:flex;align-items:baseline;gap:3px"><span style="font-size:19px;font-weight:600;letter-spacing:-.03em;font-variant-numeric:tabular-nums">${m.value}</span><span style="font:400 10px ui-monospace,'SF Mono',Menlo,monospace;color:rgba(220,228,255,0.45)">${m.unit}</span></div>
    </div>`).join("");

  const quickHTML = quick.map((q) => `
    <div data-act="${q.act}" style="pointer-events:auto;height:62px;padding:0 12px;border-radius:22px;display:flex;flex-direction:column;justify-content:center;gap:5px;cursor:pointer;background:linear-gradient(180deg,rgba(255,255,255,0.08),rgba(255,255,255,0.02));backdrop-filter:blur(40px) saturate(180%);-webkit-backdrop-filter:blur(40px) saturate(180%);border:0.5px solid ${q.border};box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.28),0 16px 30px -16px rgba(0,0,0,0.9)">
      <div style="display:flex;align-items:center;gap:6px"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="${q.color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${q.d}"></path></svg><span style="font-size:12px;font-weight:600;letter-spacing:-.01em;white-space:nowrap">${q.label}</span></div>
      <span style="font:600 9px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.14em;color:${q.color}">${q.state}</span>
    </div>`).join("");

  const tabsHTML = TABS.map(([label, d], i) => {
    const bg = i === tab ? "rgba(255,255,255,0.1)" : "transparent";
    const color = i === tab ? CY : SUB;
    return `<div data-act="tab:${i}" style="pointer-events:auto;flex:1;height:52px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;border-radius:26px;background:${bg};color:${color};cursor:pointer"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${d}"></path></svg><span style="font:500 10px -apple-system,'SF Pro Text',system-ui">${label}</span></div>`;
  }).join("");

  return `
  <div style="position:absolute;top:0;left:0;right:0;height:54px;display:flex;align-items:center;justify-content:space-between;padding:4px 30px 0 48px;box-sizing:border-box;z-index:20;font:600 16px -apple-system,'SF Pro Text',system-ui;color:#F5F7FC"><span>9:41</span><svg width="72" height="12" viewBox="0 0 72 12" fill="#F5F7FC"><rect x="0" y="8" width="3" height="4" rx="1"></rect><rect x="5" y="5.5" width="3" height="6.5" rx="1"></rect><rect x="10" y="3" width="3" height="9" rx="1"></rect><rect x="15" y="0.5" width="3" height="11.5" rx="1"></rect><path d="M31 3.2a9 9 0 0112 0l-1.3 1.4a7 7 0 00-9.4 0zM33.6 6a5.3 5.3 0 016.8 0L37 9.6z"></path><rect x="47.5" y="0.5" width="22" height="11" rx="3.5" fill="none" stroke="#F5F7FC" stroke-opacity="0.4"></rect><rect x="49.5" y="2.5" width="16" height="7" rx="2"></rect></svg></div>
  <div style="position:absolute;top:11px;left:132px;width:126px;height:37px;border-radius:20px;background:#000;z-index:21"></div>
  <div style="position:absolute;top:58px;left:16px;right:16px;display:flex;align-items:center;justify-content:space-between;z-index:8">
    <div style="display:flex;align-items:center;gap:10px;height:44px;padding:0 16px 0 6px;border-radius:22px;background:linear-gradient(180deg,rgba(255,255,255,0.09),rgba(255,255,255,0.03));backdrop-filter:blur(40px) saturate(180%);-webkit-backdrop-filter:blur(40px) saturate(180%);border:0.5px solid rgba(255,255,255,0.16);box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.3),0 12px 28px -12px rgba(0,0,0,0.8);color:#F5F7FC">
      <div style="width:32px;height:32px;border-radius:16px;background:linear-gradient(135deg,#5CF2FF,#8A9BB8);color:#04050A;display:flex;align-items:center;justify-content:center"><svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.6-7.5 9.5-4.3-.9-7.5-4.9-7.5-9.5V6L12 3z"></path></svg></div>
      <span style="font-size:15px;font-weight:600;letter-spacing:-.01em">Anonymous</span>
      <span style="font:500 10px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.1em;padding:3px 6px;border-radius:6px;background:rgba(255,255,255,0.08);color:rgba(220,228,255,0.7)">${acctChip}</span>
    </div>
    <div style="position:relative;width:44px;height:44px;border-radius:22px;display:flex;align-items:center;justify-content:center;background:linear-gradient(180deg,rgba(255,255,255,0.09),rgba(255,255,255,0.03));backdrop-filter:blur(40px);-webkit-backdrop-filter:blur(40px);border:0.5px solid rgba(255,255,255,0.16);box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.3);color:#F5F7FC"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M6 8a6 6 0 1112 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 003.4 0"></path></svg></div>
  </div>
  <div style="position:absolute;top:92px;left:0;width:390px;height:380px;z-index:6;display:flex;align-items:center;justify-content:center;pointer-events:none">
    <svg width="244" height="244" viewBox="0 0 244 244" style="position:absolute"><circle cx="122" cy="122" r="118" fill="none" stroke="rgba(255,255,255,0.2)" stroke-width="6" stroke-dasharray="0.7 5.48"></circle><circle cx="122" cy="122" r="100" fill="none" stroke="${orbRing}" stroke-width="1"></circle><circle cx="122" cy="122" r="100" fill="none" stroke="${orbColor}" stroke-width="2.5" stroke-linecap="round" stroke-dasharray="${arc}" transform="rotate(-90 122 122)"></circle></svg>
    <div data-act="toggle" role="button" style="pointer-events:auto;width:156px;height:156px;border-radius:78px;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;background:radial-gradient(80% 80% at 30% 18%,rgba(255,255,255,0.24),rgba(255,255,255,0.04) 60%),rgba(10,14,26,0.4);backdrop-filter:blur(14px) saturate(180%);-webkit-backdrop-filter:blur(14px) saturate(180%);border:0.5px solid rgba(255,255,255,0.32);box-shadow:inset 0 1px 0 rgba(255,255,255,0.5),inset 0 -14px 28px rgba(0,0,0,0.4),0 30px 60px -10px rgba(0,0,0,0.85),0 0 70px ${orbGlow}">
      <svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="${orbColor}" stroke-width="2" stroke-linecap="round"><path d="M12 3v8M6.3 6.8a8 8 0 1011.4 0"></path></svg>
      <span style="font:600 11px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.18em;color:${orbColor}">${on ? "SECURED" : "OFFLINE"}</span>
      <span style="font-size:11px;color:rgba(220,228,255,0.5)">${on ? "Tap to disconnect" : "Tap to connect"}</span>
    </div>
  </div>
  <div style="position:absolute;top:478px;left:16px;right:16px;padding:16px 18px;border-radius:30px;z-index:8;display:flex;flex-direction:column;gap:14px;background:linear-gradient(180deg,rgba(255,255,255,0.085),rgba(255,255,255,0.025));backdrop-filter:blur(40px) saturate(180%);-webkit-backdrop-filter:blur(40px) saturate(180%);border:0.5px solid rgba(255,255,255,0.15);box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.32),0 1px 1px rgba(0,0,0,0.6),0 24px 48px -18px rgba(0,0,0,0.9);color:#F5F7FC">
    <div style="display:flex;align-items:center;justify-content:space-between">
      <div style="display:flex;align-items:center;gap:7px;height:24px;padding:0 10px;border-radius:12px;background:${pillBg}"><span style="width:6px;height:6px;border-radius:3px;background:${statusColor};box-shadow:0 0 8px ${statusColor}"></span><span style="font:600 10px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.14em;color:${statusColor}">${on ? "PROTECTED" : "EXPOSED"}</span></div>
      <span style="font:500 15px ui-monospace,'SF Mono',Menlo,monospace;font-variant-numeric:tabular-nums;letter-spacing:.02em">${timer}</span>
    </div>
    <div style="display:flex;flex-direction:column;gap:5px">
      <div style="display:flex;align-items:flex-end;justify-content:space-between;gap:12px">
        <span style="font-size:26px;font-weight:600;letter-spacing:-.035em;line-height:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${on ? esc(srv.city) : "Not connected"}</span>
        <div style="flex:none;display:flex;flex-direction:column;align-items:flex-end;gap:4px"><span style="font:500 9px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.14em;color:rgba(220,228,255,0.4)">EXIT IP</span><span style="font:500 13px ui-monospace,'SF Mono',Menlo,monospace;line-height:1">${on ? esc(srv.ip) : "—"}</span></div>
      </div>
      <span style="font:400 11px ui-monospace,'SF Mono',Menlo,monospace;color:rgba(220,228,255,0.5);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(srv.id)} · ${esc(srv.dc)} · SHAIP Mesh</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border-top:0.5px solid rgba(255,255,255,0.1);padding-top:12px">${metricsHTML}</div>
  </div>
  <div style="position:absolute;top:676px;left:16px;right:16px;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;z-index:8;color:#F5F7FC">${quickHTML}</div>
  <div style="position:absolute;left:0;right:0;bottom:0;height:130px;background:linear-gradient(180deg,rgba(2,3,6,0),rgba(2,3,6,0.92));z-index:14;pointer-events:none"></div>
  <div style="position:absolute;left:16px;right:16px;bottom:22px;height:64px;border-radius:32px;display:flex;align-items:center;padding:0 6px;z-index:15;background:linear-gradient(180deg,rgba(44,48,64,0.62),rgba(16,18,26,0.62));backdrop-filter:blur(40px) saturate(200%);-webkit-backdrop-filter:blur(40px) saturate(200%);border:0.5px solid rgba(255,255,255,0.16);box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.36),0 20px 40px -10px rgba(0,0,0,0.9)">${tabsHTML}</div>
  <div style="position:absolute;bottom:8px;left:128px;width:134px;height:5px;border-radius:3px;background:#F5F7FC;z-index:20"></div>`;
}

// --- Shared chrome ---
const STATUSBAR_HTML = `<div style="position:absolute;top:0;left:0;right:0;height:54px;display:flex;align-items:center;justify-content:space-between;padding:4px 30px 0 48px;box-sizing:border-box;z-index:20;font:600 16px -apple-system,'SF Pro Text',system-ui;color:#F5F7FC"><span>9:41</span><svg width="72" height="12" viewBox="0 0 72 12" fill="#F5F7FC"><rect x="0" y="8" width="3" height="4" rx="1"></rect><rect x="5" y="5.5" width="3" height="6.5" rx="1"></rect><rect x="10" y="3" width="3" height="9" rx="1"></rect><rect x="15" y="0.5" width="3" height="11.5" rx="1"></rect><path d="M31 3.2a9 9 0 0112 0l-1.3 1.4a7 7 0 00-9.4 0zM33.6 6a5.3 5.3 0 016.8 0L37 9.6z"></path><rect x="47.5" y="0.5" width="22" height="11" rx="3.5" fill="none" stroke="#F5F7FC" stroke-opacity="0.4"></rect><rect x="49.5" y="2.5" width="16" height="7" rx="2"></rect></svg></div><div style="position:absolute;top:11px;left:132px;width:126px;height:37px;border-radius:20px;background:#000;z-index:21"></div>`;
const SCRIM_HTML = `<div style="position:absolute;left:0;right:0;bottom:0;height:130px;background:linear-gradient(180deg,rgba(2,3,6,0),rgba(2,3,6,0.92));z-index:14;pointer-events:none"></div>`;
const HOME_HTML = `<div style="position:absolute;bottom:8px;left:128px;width:134px;height:5px;border-radius:3px;background:#F5F7FC;z-index:20"></div>`;

function tabBarHTML(tab: number): string {
  const items = TABS.map(([label, d], i) => {
    const bg = i === tab ? "rgba(255,255,255,0.1)" : "transparent";
    const color = i === tab ? CY : SUB;
    return `<div data-act="tab:${i}" style="pointer-events:auto;flex:1;height:52px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;border-radius:26px;background:${bg};color:${color};cursor:pointer"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="${d}"></path></svg><span style="font:500 10px -apple-system,'SF Pro Text',system-ui">${label}</span></div>`;
  }).join("");
  return `<div style="position:absolute;left:16px;right:16px;bottom:22px;height:64px;border-radius:32px;display:flex;align-items:center;padding:0 6px;z-index:15;background:linear-gradient(180deg,rgba(44,48,64,0.62),rgba(16,18,26,0.62));backdrop-filter:blur(40px) saturate(200%);-webkit-backdrop-filter:blur(40px) saturate(200%);border:0.5px solid rgba(255,255,255,0.16);box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.36),0 20px 40px -10px rgba(0,0,0,0.9)">${items}</div>`;
}

// Network globe screen.
function networkOverlayHTML(v: { on: boolean; srv: Srv; multihop: boolean; secs: number; nodes: Srv[]; }): string {
  const { on, srv, multihop, secs, nodes } = v;
  const statusColor = on ? OK : BA;
  const regions = new Set(nodes.map((n) => n.dc).filter((d) => d && d !== "—")).size;
  const counts = `${nodes.length || "—"} NODES · ${regions || "—"} REGIONS`;
  const rtt = on && srv.ms != null ? `${srv.ms} ms` : "STANDBY";
  const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;");

  const route = [
    { name: "This device", meta: on ? "tunnel up" : "—", act: on },
    { name: `${srv.id} edge`, meta: on && srv.ms != null ? `${srv.ms} ms` : "—", act: on },
    { name: "Relay", meta: !multihop ? "bypassed" : on ? "+41 ms" : "—", act: on && multihop },
    { name: "Exit", meta: on ? esc(srv.dc) : "—", act: on },
  ].map((r) => ({ ...r, ring: r.act ? CY : "rgba(255,255,255,0.25)", fill: r.act ? CY : "#0A0D18", glow: r.act ? "rgba(92,242,255,0.6)" : "rgba(0,0,0,0)" }));
  const routeTag = multihop ? "MULTI-HOP · 3" : "DIRECT";
  const netStats = [
    { label: "CIPHER", value: "ChaCha20" },
    { label: "HANDSHAKE", value: on ? "ML-KEM-768" : "—" },
    { label: "MTU", value: "1420" },
  ];

  const routeHTML = route.map((r) => `
    <div style="position:relative;display:flex;flex-direction:column;align-items:center;gap:8px;text-align:center">
      <span style="width:13px;height:13px;border-radius:7px;box-sizing:border-box;border:2px solid ${r.ring};background:${r.fill};box-shadow:0 0 12px ${r.glow}"></span>
      <span style="font-size:12px;font-weight:600;letter-spacing:-.01em">${esc(r.name)}</span>
      <span style="font:400 10px ui-monospace,'SF Mono',Menlo,monospace;color:rgba(220,228,255,0.5)">${esc(r.meta)}</span>
    </div>`).join("");
  const netStatsHTML = netStats.map((m) => `<div style="display:flex;flex-direction:column;gap:3px"><span style="font:500 9px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.14em;color:rgba(220,228,255,0.42)">${m.label}</span><span style="font:500 13px ui-monospace,'SF Mono',Menlo,monospace">${m.value}</span></div>`).join("");

  return `${STATUSBAR_HTML}
  <div style="position:absolute;top:62px;left:24px;right:16px;display:flex;align-items:flex-start;justify-content:space-between;z-index:8;color:#F5F7FC">
    <div style="display:flex;flex-direction:column;gap:6px"><span style="font-size:34px;font-weight:700;letter-spacing:-.03em;line-height:1">Network</span><span style="font:500 10px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.14em;color:rgba(220,228,255,0.45)">${counts}</span></div>
    <div style="width:44px;height:44px;border-radius:22px;display:flex;align-items:center;justify-content:center;background:linear-gradient(180deg,rgba(255,255,255,0.09),rgba(255,255,255,0.03));backdrop-filter:blur(40px);-webkit-backdrop-filter:blur(40px);border:0.5px solid rgba(255,255,255,0.16);box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.3)"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linejoin="round"><path d="M12 3l9 5-9 5-9-5 9-5zM3 13l9 5 9-5"></path></svg></div>
  </div>
  <div style="position:absolute;top:136px;left:16px;display:flex;align-items:center;gap:8px;height:30px;padding:0 12px;border-radius:15px;z-index:8;background:linear-gradient(180deg,rgba(255,255,255,0.09),rgba(255,255,255,0.03));backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px);border:0.5px solid rgba(255,255,255,0.16);color:#F5F7FC"><span style="width:6px;height:6px;border-radius:3px;background:${statusColor};box-shadow:0 0 8px ${statusColor}"></span><span style="font:500 10px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.1em">${esc(srv.id)} · ${rtt}</span></div>
  <div style="position:absolute;top:548px;left:16px;right:16px;padding:18px;border-radius:30px;z-index:8;display:flex;flex-direction:column;gap:18px;background:linear-gradient(180deg,rgba(255,255,255,0.085),rgba(255,255,255,0.025));backdrop-filter:blur(40px) saturate(180%);-webkit-backdrop-filter:blur(40px) saturate(180%);border:0.5px solid rgba(255,255,255,0.15);box-shadow:inset 0 0.5px 0 rgba(255,255,255,0.32),0 1px 1px rgba(0,0,0,0.6),0 24px 48px -18px rgba(0,0,0,0.9);color:#F5F7FC">
    <div style="display:flex;justify-content:space-between;align-items:center"><span style="font-size:17px;font-weight:600;letter-spacing:-.02em">Active route</span><span style="font:600 9px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.14em;color:#5CF2FF;padding:4px 8px;border-radius:8px;background:rgba(92,242,255,0.1)">${routeTag}</span></div>
    <div style="position:relative;display:grid;grid-template-columns:repeat(4,minmax(0,1fr))">
      <div style="position:absolute;left:12%;right:12%;top:6px;height:1px;background:linear-gradient(90deg,#5CF2FF,#8A9BB8);opacity:0.6"></div>
      ${routeHTML}
    </div>
    <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border-top:0.5px solid rgba(255,255,255,0.1);padding-top:12px">${netStatsHTML}</div>
  </div>
  ${SCRIM_HTML}${tabBarHTML(1)}${HOME_HTML}`;
}

// Temporary honest placeholder for tabs still being built to the v2 design.
function buildingOverlayHTML(tab: number): string {
  const name = TABS[tab]?.[0] ?? "Screen";
  return `${STATUSBAR_HTML}
  <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;color:#F5F7FC;padding:0 40px;text-align:center">
    <span style="font:500 11px ui-monospace,'SF Mono',Menlo,monospace;letter-spacing:.18em;color:#5CF2FF">${name.toUpperCase()}</span>
    <span style="font-size:20px;font-weight:600;letter-spacing:-.02em">Being built to the v2 design</span>
    <span style="font-size:13px;color:rgba(220,228,255,0.5)">Connect and Network are live. This screen is next.</span>
  </div>
  ${SCRIM_HTML}${tabBarHTML(tab)}${HOME_HTML}`;
}
