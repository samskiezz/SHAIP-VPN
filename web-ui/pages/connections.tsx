import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/router";
import Nav from "@/components/Nav";
import { api, getToken } from "@/lib/api";

type Conn = {
  id: string;
  node_id: string;
  route: "fast" | "anon";
  bytes_in: number;
  bytes_out: number;
  started_at: string;
};

export default function Connections() {
  const router = useRouter();
  const [rows, setRows] = useState<Conn[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api<Conn[]>("/api/connections")
      .then((r) => setRows(r ?? []))
      .catch((e) => setErr(e.message));
  }, []);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    load();
  }, [router, load]);

  const disconnect = async (id: string) => {
    try {
      await api(`/api/connections/${id}`, { method: "DELETE" });
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed");
    }
  };

  return (
    <div>
      <Nav />
      <div className="p-6">
        <h1 className="mb-4 text-2xl font-bold">Connections</h1>
        {err && <div className="mb-4 text-red-600">Error: {err}</div>}
        {rows.length === 0 ? (
          <div className="text-gray-500">No active connections.</div>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b text-left text-sm text-gray-500">
                <th className="py-2">ID</th>
                <th>Node</th>
                <th>Route</th>
                <th>Bytes in</th>
                <th>Bytes out</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} className="border-b">
                  <td className="py-2 font-mono text-xs">{c.id.slice(0, 8)}</td>
                  <td className="font-mono text-xs">{c.node_id.slice(0, 8)}</td>
                  <td>
                    <span
                      className={
                        c.route === "anon" ? "text-purple-600" : "text-brand-dark"
                      }
                    >
                      {c.route}
                    </span>
                  </td>
                  <td>{c.bytes_in}</td>
                  <td>{c.bytes_out}</td>
                  <td>
                    <button
                      onClick={() => disconnect(c.id)}
                      className="text-red-600 hover:underline"
                    >
                      Disconnect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
