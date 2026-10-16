import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Nav from "@/components/Nav";
import { api, clearToken, getToken } from "@/lib/api";

type Network = {
  nodes_online: number;
  nodes_total: number;
};

type Me = { account_number: string; created_at: string };

export default function Dashboard() {
  const router = useRouter();
  const [net, setNet] = useState<Network | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    api<Network>("/api/dashboard").then(setNet).catch((e) => setErr(e.message));
    api<Me>("/api/me").then(setMe).catch(() => undefined);
  }, [router]);

  return (
    <div>
      <Nav />
      <div className="mx-auto max-w-4xl space-y-6 p-6">
        <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
        {err && <div className="text-threat">Error: {err}</div>}
        {!net && !err && <div className="text-ink-2">Loading…</div>}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 md:grid-cols-3">
          {me && <Card label="Your account number" value={me.account_number} mono accent />}
          {net && <Card label="Servers online" value={`${net.nodes_online} of ${net.nodes_total}`} />}
        </div>
        <p className="max-w-2xl text-sm text-ink-2">
          This page shows the network, never your activity: the control plane keeps no record of
          your connections, traffic or the sites you visit, and doesn&apos;t log the address you
          sign in from.
        </p>
        <p className="max-w-2xl text-sm text-ink-2">
          The tunnel connects straight to one VPN server. Mix nodes can register and be listed in the
          directory, but traffic does not route through them yet, so there is no mixnet protection.
        </p>
        <DeleteAccount onDeleted={() => { clearToken(); router.replace("/login"); }} />
      </div>
    </div>
  );
}

// Erases the account and everything stored about it (devices, API keys, the
// security log). Enrolled devices stay refused by every server.
function DeleteAccount({ onDeleted }: { onDeleted: () => void }) {
  const [open, setOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!open) {
    return (
      <button onClick={() => setOpen(true)} className="text-sm text-threat hover:underline">
        Delete account…
      </button>
    );
  }
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setErr(null);
        try {
          await api("/api/me", { method: "DELETE", body: { password } });
          onDeleted();
        } catch (e) {
          setErr(e instanceof Error ? e.message : "request failed");
        } finally {
          setBusy(false);
        }
      }}
      className="max-w-md space-y-3 rounded-2xl border border-threat/30 bg-threat/5 p-4"
    >
      <div className="font-semibold text-threat">Delete this account</div>
      <p className="text-sm text-ink-2">
        Everything stored about it is erased: its devices, API keys and security log. Its devices are
        refused by every server from now on. This can&apos;t be undone.
      </p>
      <input
        type="password"
        required
        autoComplete="current-password"
        placeholder="your password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="field"
      />
      {err && <div className="text-sm text-threat">{err}</div>}
      <div className="flex gap-3">
        <button type="submit" disabled={busy} className="rounded-full bg-threat px-4 py-2 text-sm font-semibold text-[#160409] disabled:opacity-50">
          {busy ? "…" : "Delete forever"}
        </button>
        <button type="button" onClick={() => setOpen(false)} className="text-sm text-ink-2">
          Cancel
        </button>
      </div>
    </form>
  );
}

function Card({ label, value, mono, accent }: { label: string; value: string | number; mono?: boolean; accent?: boolean }) {
  return (
    <div className="glass p-4">
      <div className="eyebrow">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${mono ? "font-mono tracking-wider" : ""} ${accent ? "text-signal" : "text-ink"}`}>
        {value}
      </div>
    </div>
  );
}
