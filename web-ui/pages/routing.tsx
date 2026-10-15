import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/router";
import Nav from "@/components/Nav";
import { api, getToken } from "@/lib/api";

type Rule = {
  id: string;
  domain: string;
  route: "fast" | "anon";
  priority: number;
};

export default function Routing() {
  const router = useRouter();
  const [rules, setRules] = useState<Rule[]>([]);
  const [domain, setDomain] = useState("");
  const [route, setRoute] = useState<"fast" | "anon">("anon");
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api<Rule[]>("/api/routing");
      setRules(data ?? []);
      setErr(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed to load rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    load();
  }, [router, load]);

  const add = async () => {
    const d = domain.trim();
    if (!d || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const created = await api<Rule>("/api/routing", {
        method: "POST",
        body: { domain: d, route, priority: 0 },
      });
      setRules((rs) => [created, ...rs]);
      setDomain("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "failed to add rule");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (id: string) => {
    const prev = rules;
    setRules((rs) => rs.filter((r) => r.id !== id)); // optimistic
    try {
      await api(`/api/routing/${id}`, { method: "DELETE" });
    } catch (e) {
      setRules(prev); // roll back on failure
      setErr(e instanceof Error ? e.message : "failed to remove rule");
    }
  };

  return (
    <div>
      <Nav />
      <div className="p-6">
        <h1 className="mb-4 text-2xl font-bold">Routing Rules</h1>
        <p className="mb-4 text-sm text-gray-500">
          <span className="text-brand-dark">fast</span> = low-latency single hop ·{" "}
          <span className="text-purple-600">anon</span> = 5-hop mixnet path
        </p>

        <div className="mb-4 flex flex-col gap-2 sm:flex-row">
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && add()}
            placeholder="*.example.com"
            className="flex-1 rounded border px-3 py-2"
          />
          <select
            value={route}
            onChange={(e) => setRoute(e.target.value as "fast" | "anon")}
            className="rounded border px-3 py-2"
          >
            <option value="fast">Fast</option>
            <option value="anon">Anon</option>
          </select>
          <button
            onClick={add}
            disabled={busy || !domain.trim()}
            className="rounded bg-black px-4 py-2 text-white disabled:opacity-50"
          >
            {busy ? "…" : "Add"}
          </button>
        </div>

        {err && <div className="mb-4 text-sm text-red-600">{err}</div>}
        {loading ? (
          <div className="text-gray-500">Loading…</div>
        ) : rules.length === 0 ? (
          <div className="text-sm text-gray-400">
            No routing rules yet. Add one above — anything not matched uses your
            default route.
          </div>
        ) : (
          <ul className="space-y-2">
            {rules.map((r) => (
              <li
                key={r.id}
                className="flex items-center justify-between border-b py-2"
              >
                <span className="font-mono">{r.domain}</span>
                <span className="flex items-center gap-4">
                  <span
                    className={
                      r.route === "anon" ? "text-purple-600" : "text-brand-dark"
                    }
                  >
                    {r.route}
                  </span>
                  <button
                    onClick={() => remove(r.id)}
                    className="text-sm text-gray-400 hover:text-red-600"
                  >
                    remove
                  </button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
