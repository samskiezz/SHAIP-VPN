import { useEffect, useState } from "react";
import { api } from "@/lib/api";

// The payment page is deliberately public and identity-free: no login, no email,
// no card. It shows the plans and their prices, explains the unlinkable-token
// flow and its limits, and lets you look up an order's status by id. Buying (blinding tokens)
// happens in the app/CLI, where the tokens live — the web page never sees a
// nonce or a blinding secret.

type Denom = {
  id: string;
  label: string;
  duration_days: number;
  price_xmr: string;
  price_btc: string;
};

type DenomResp = { rails: string[]; default_rail: string; denominations: Denom[] };

type Order = {
  id: string;
  denom: string;
  rail: string;
  address: string;
  amount_label: string;
  status: string;
  expires_at: string;
  uri?: string;
};

const statusColor: Record<string, string> = {
  awaiting_payment: "text-amber-600",
  paid: "text-emerald-600",
  collected: "text-emerald-700",
  expired: "text-gray-400",
};

export default function Pay() {
  const [rails, setRails] = useState<string[]>([]);
  const [denoms, setDenoms] = useState<Denom[]>([]);
  const [err, setErr] = useState<string>("");

  const [orderId, setOrderId] = useState("");
  const [order, setOrder] = useState<Order | null>(null);
  const [lookupErr, setLookupErr] = useState("");

  useEffect(() => {
    api<DenomResp>("/api/pay/denominations", { auth: false })
      .then((d) => {
        setRails(d.rails ?? []);
        setDenoms(d.denominations);
      })
      .catch((e) => setErr(e.message));
  }, []);

  const lookup = async () => {
    setLookupErr("");
    setOrder(null);
    try {
      const o = await api<Order>(`/api/pay/order/${orderId.trim()}`, { auth: false });
      setOrder(o);
    } catch (e) {
      setLookupErr((e as Error).message);
    }
  };

  return (
    <main className="mx-auto max-w-2xl p-6">
      <h1 className="font-mono text-2xl font-bold text-brand-dark">PQ·ANON — Private access</h1>
      <p className="mt-2 text-gray-600">
        Pay with Monero or Bitcoin. Get blind-signed access tokens: the token you redeem carries
        nothing that links it to your payment (RFC&nbsp;9474 blind signatures).
      </p>

      {/* How it works */}
      <ol className="mt-6 space-y-2 rounded-lg border bg-white p-5 text-sm text-gray-700 shadow-sm">
        <li>
          <span className="font-semibold">1.</span> In the app, pick a plan and get a one-time Monero
          address.
        </li>
        <li>
          <span className="font-semibold">2.</span> Pay it. Monero obscures the amount, sender and
          receiver on its public ledger; a Bitcoin payment is public on-chain.
        </li>
        <li>
          <span className="font-semibold">3.</span> The app collects tokens the mint signed{" "}
          <em>without seeing them</em> (RFC&nbsp;9474 blind signatures).
        </li>
        <li>
          <span className="font-semibold">4.</span> Redeeming a token grants VPN access. The token
          carries no link back to the payment, and a redemption records only a hash of the token and
          the day: no account, no address, no time of day.
        </li>
      </ol>

      {/* Plans */}
      <section className="mt-6">
        <h2 className="text-lg font-semibold text-brand-dark">
          Plans{" "}
          {rails.length > 0 && (
            <span className="text-sm font-normal text-gray-400">· paid in {rails.join(" / ")}</span>
          )}
        </h2>
        {err && <p className="mt-2 text-sm text-red-600">Could not load plans: {err}</p>}
        <div className="mt-3 overflow-x-auto">
        <table className="w-full overflow-hidden rounded-lg border bg-white text-sm shadow-sm">
          <thead className="bg-gray-50 text-left text-gray-500">
            <tr>
              <th className="px-4 py-2">Plan</th>
              <th className="px-4 py-2">Duration</th>
              <th className="px-4 py-2 text-right">Monero</th>
              <th className="px-4 py-2 text-right">Bitcoin</th>
            </tr>
          </thead>
          <tbody>
            {denoms.map((d) => (
              <tr key={d.id} className="border-t">
                <td className="px-4 py-2 font-medium">{d.label}</td>
                <td className="px-4 py-2 text-gray-600">
                  {d.duration_days} {d.duration_days === 1 ? "day" : "days"}
                </td>
                <td className="px-4 py-2 text-right font-mono">{d.price_xmr} XMR</td>
                <td className="px-4 py-2 text-right font-mono">{d.price_btc} BTC</td>
              </tr>
            ))}
            {denoms.length === 0 && !err && (
              <tr>
                <td colSpan={4} className="px-4 py-3 text-gray-400">
                  Loading…
                </td>
              </tr>
            )}
          </tbody>
        </table>
        </div>
        <p className="mt-2 text-xs text-gray-500">
          Buy from the app:{" "}
          <code className="rounded bg-gray-100 px-1">pqanon buy --plan month --server &lt;url&gt;</code>
        </p>
      </section>

      {/* Order status lookup */}
      <section className="mt-8">
        <h2 className="text-lg font-semibold text-brand-dark">Check an order</h2>
        <div className="mt-3 flex gap-2">
          <input
            value={orderId}
            onChange={(e) => setOrderId(e.target.value)}
            placeholder="order id"
            className="flex-1 rounded-lg border px-3 py-2 font-mono text-sm"
          />
          <button
            onClick={lookup}
            disabled={!orderId.trim()}
            className="rounded-lg bg-brand-dark px-4 py-2 text-sm font-semibold text-white disabled:opacity-40"
          >
            Look up
          </button>
        </div>
        {lookupErr && <p className="mt-2 text-sm text-red-600">{lookupErr}</p>}
        {order && (
          <div className="mt-3 rounded-lg border bg-white p-4 text-sm shadow-sm">
            <div className="flex justify-between">
              <span className="text-gray-500">Status</span>
              <span className={`font-semibold ${statusColor[order.status] ?? ""}`}>
                {order.status.replace("_", " ")}
              </span>
            </div>
            <div className="mt-1 flex justify-between">
              <span className="text-gray-500">Plan</span>
              <span>{order.denom}</span>
            </div>
            <div className="mt-1 flex justify-between">
              <span className="text-gray-500">Amount</span>
              <span className="font-mono">{order.amount_label}</span>
            </div>
            {order.status === "awaiting_payment" && (
              <div className="mt-2 break-all rounded bg-gray-50 p-2 font-mono text-xs text-gray-700">
                {order.address}
              </div>
            )}
          </div>
        )}
      </section>

      <p className="mt-8 rounded-lg border bg-white p-4 text-xs text-gray-600 shadow-sm">
        <span className="font-semibold">Limits.</span> No account or email is needed to pay. The token
        is unlinkable, but timing and IP addresses are not: if you buy and connect from the same
        network, or connect right after paying, the operator can guess the link. The VPN server can
        see where your traffic goes, as any VPN operator can. See docs/payments.md for the full
        threat model.
      </p>
    </main>
  );
}
