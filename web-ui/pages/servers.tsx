import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/router";
import Nav from "@/components/Nav";
import { api, getToken } from "@/lib/api";

// The network of VPN servers, from the control plane's signed node directory.
// Every row is a real registered node — there are no invented servers, exit IPs
// or loads here. When no server has registered, the list is honestly empty.
type Node = {
  id: string;
  name: string;
  address: string;
  role: string;
  region: string;
  capacity_mbps: number;
  status: string;
  stake_sats: number;
  created_at: string;
};

const ROLE_LABEL: Record<string, string> = {
  entry: "Entry",
  exit: "Exit",
  gateway: "Gateway",
  mix: "Mix",
};

function statusClass(s: string): string {
  if (s === "active" || s === "listed" || s === "online") return "text-emerald-600";
  if (s === "jailed" || s === "slashed") return "text-red-600";
  return "text-gray-500";
}

export default function Servers() {
  const router = useRouter();
  const [nodes, setNodes] = useState<Node[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api<Node[]>("/api/nodes")
      .then((n) => setNodes(n ?? []))
      .catch((e) => setErr(e.message));
  }, []);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    load();
  }, [router, load]);

  const online = (nodes ?? []).filter((n) => ["active", "listed", "online"].includes(n.status)).length;
  const regions = new Set((nodes ?? []).map((n) => n.region).filter(Boolean)).size;

  return (
    <div>
      <Nav />
      <div className="space-y-6 p-6">
        <div className="flex items-end justify-between">
          <h1 className="text-2xl font-bold">Servers</h1>
          {nodes && (
            <span className="font-mono text-xs uppercase tracking-wide text-gray-500">
              {nodes.length} {nodes.length === 1 ? "node" : "nodes"} · {online} online · {regions}{" "}
              {regions === 1 ? "region" : "regions"}
            </span>
          )}
        </div>

        {err && <div className="text-red-600">Error: {err}</div>}
        {!nodes && !err && <div className="text-gray-500">Loading…</div>}

        {nodes && nodes.length === 0 && (
          <div className="max-w-2xl rounded-xl border bg-white p-6 text-sm text-gray-600 shadow-sm">
            <div className="font-semibold text-gray-800">No servers registered yet.</div>
            <p className="mt-2">
              Servers appear here once an operator registers one with the control plane and bonds
              stake to be listed in the signed directory. This list is exactly the directory — never
              placeholder or sample nodes.
            </p>
          </div>
        )}

        {nodes && nodes.length > 0 && (
          <div className="max-w-4xl overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-gray-500">
                <tr>
                  <th className="py-2">Server</th>
                  <th>Region</th>
                  <th>Role</th>
                  <th className="text-right">Capacity</th>
                  <th className="text-right">Stake</th>
                  <th className="pl-4">Status</th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((n) => (
                  <tr key={n.id} className="border-t">
                    <td className="py-2">
                      <div className="font-medium">{n.name || n.id.slice(0, 8)}</div>
                      <div className="font-mono text-xs text-gray-400">{n.address}</div>
                    </td>
                    <td className="font-mono text-xs">{n.region || "—"}</td>
                    <td>{ROLE_LABEL[n.role] ?? n.role}</td>
                    <td className="text-right font-mono">
                      {n.capacity_mbps ? `${n.capacity_mbps} Mbps` : "—"}
                    </td>
                    <td className="text-right font-mono">
                      {n.stake_sats ? `${(n.stake_sats / 1e8).toFixed(3)} BTC` : "—"}
                    </td>
                    <td className={`pl-4 font-medium ${statusClass(n.status)}`}>{n.status || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <p className="max-w-2xl text-sm text-gray-500">
          The directory is signed by the control plane and verified by the client before it trusts a
          server (see docs/directory.md). A server must bond stake to be listed; equivocation is
          slashable. The tunnel connects to one server at a time — there is no mix routing yet, so
          traffic does not hop between these nodes.
        </p>
      </div>
    </div>
  );
}
