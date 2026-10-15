import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import Nav from "@/components/Nav";
import { api, getToken } from "@/lib/api";

type Stats = {
  active_connections: number;
  bandwidth_mb: number;
  latency_ms: number;
  mixnet_status: string;
};

export default function Dashboard() {
  const router = useRouter();
  const [stats, setStats] = useState<Stats | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    api<Stats>("/api/dashboard").then(setStats).catch((e) => setErr(e.message));
  }, [router]);

  return (
    <div>
      <Nav />
      <div className="space-y-6 p-6">
        <h1 className="text-2xl font-bold">Dashboard</h1>
        {err && <div className="text-red-600">Error: {err}</div>}
        {!stats && !err && <div className="text-gray-500">Loading…</div>}
        {stats && (
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Card label="Active connections" value={stats.active_connections} />
            <Card label="Bandwidth (MB)" value={stats.bandwidth_mb} />
            <Card label="Latency (ms)" value={stats.latency_ms} />
            <Card label="Mixnet" value={stats.mixnet_status} />
          </div>
        )}
      </div>
    </div>
  );
}

function Card({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border bg-white p-4 shadow-sm">
      <div className="text-xs uppercase text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
    </div>
  );
}
