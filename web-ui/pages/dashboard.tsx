import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Nav from "@/components/Nav";
import { api, getToken } from "@/lib/api";

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
      <div className="space-y-6 p-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        {err && <div className="text-red-600">Error: {err}</div>}
        {!net && !err && <div className="text-gray-500">Loading…</div>}
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          {me && <Card label="Your account number" value={me.account_number} mono />}
          {net && <Card label="Servers online" value={`${net.nodes_online} of ${net.nodes_total}`} />}
        </div>
        <p className="max-w-2xl text-sm text-gray-500">
          This page shows the network, never your activity: the control plane keeps no record of
          your connections, traffic or the sites you visit, and doesn&apos;t log the address you
          sign in from.
        </p>
        <p className="max-w-2xl text-sm text-gray-500">
          The tunnel connects straight to one VPN server. Mix nodes can register and be listed in the
          directory, but traffic does not route through them yet, so there is no mixnet protection.
        </p>
      </div>
    </div>
  );
}

function Card({ label, value, mono }: { label: string; value: string | number; mono?: boolean }) {
  return (
    <div className="rounded-xl border bg-white p-4 shadow-sm">
      <div className="text-xs uppercase text-gray-500">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${mono ? "font-mono tracking-wider" : ""}`}>{value}</div>
    </div>
  );
}
