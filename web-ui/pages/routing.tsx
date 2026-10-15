import { useState } from "react";
import Nav from "@/components/Nav";

type Rule = { domain: string; route: "fast" | "anon" };

export default function Routing() {
  const [rules, setRules] = useState<Rule[]>([
    { domain: "*.journalist.org", route: "anon" },
    { domain: "*.cdn.example.com", route: "fast" },
  ]);
  const [domain, setDomain] = useState("");
  const [route, setRoute] = useState<"fast" | "anon">("anon");

  const add = () => {
    if (!domain) return;
    setRules([...rules, { domain, route }]);
    setDomain("");
  };

  const remove = (i: number) => setRules(rules.filter((_, idx) => idx !== i));

  return (
    <div>
      <Nav />
      <div className="p-6">
        <h1 className="mb-4 text-2xl font-bold">Routing Rules</h1>
        <p className="mb-4 text-sm text-gray-500">
          <span className="text-brand-dark">fast</span> = low-latency single hop ·{" "}
          <span className="text-purple-600">anon</span> = 5-hop mixnet path
        </p>
        <div className="mb-4 flex gap-2">
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
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
            className="rounded bg-black px-4 py-2 text-white"
          >
            Add
          </button>
        </div>
        <ul className="space-y-2">
          {rules.map((r, i) => (
            <li key={i} className="flex items-center justify-between border-b py-2">
              <span className="font-mono">{r.domain}</span>
              <span className="flex items-center gap-4">
                <span
                  className={r.route === "anon" ? "text-purple-600" : "text-brand-dark"}
                >
                  {r.route}
                </span>
                <button
                  onClick={() => remove(i)}
                  className="text-sm text-gray-400 hover:text-red-600"
                >
                  remove
                </button>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
