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
  paid: "text-ok",
  collected: "text-ok",
  expired: "text-ink-3",
};

type Grant = { session_id: string; grant: string; plan: string; expires_at: string };

export default function Pay() {
  const [rails, setRails] = useState<string[]>([]);
  const [denoms, setDenoms] = useState<Denom[]>([]);
  const [err, setErr] = useState<string>("");

  const [orderId, setOrderId] = useState("");
  const [order, setOrder] = useState<Order | null>(null);
  const [lookupErr, setLookupErr] = useState("");

  const [code, setCode] = useState("");
  const [grant, setGrant] = useState<Grant | null>(null);
  const [codeErr, setCodeErr] = useState("");
  const [claiming, setClaiming] = useState(false);

  const claimCode = async () => {
    setCodeErr("");
    setGrant(null);
    setClaiming(true);
    try {
      const g = await api<Grant>("/api/pay/claim-code", {
        method: "POST",
        auth: false,
        body: { code: code.trim() },
      });
      setGrant(g);
    } catch (e) {
      setCodeErr((e as Error).message);
    } finally {
      setClaiming(false);
    }
  };

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
      <h1 className="font-mono text-2xl font-bold text-signal">SHAIP VPN — Private access</h1>
      <p className="mt-2 text-ink-2">
        Pay with Monero or Bitcoin. Get blind-signed access tokens: the token you redeem carries
        nothing that links it to your payment (RFC&nbsp;9474 blind signatures).
      </p>

      {/* How it works */}
      <ol className="mt-6 space-y-2 glass-tile p-5 text-sm text-ink-2">
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
        <h2 className="text-lg font-semibold text-signal">
          Plans{" "}
          {rails.length > 0 && (
            <span className="text-sm font-normal text-ink-3">· paid in {rails.join(" / ")}</span>
          )}
        </h2>
        {err && <p className="mt-2 text-sm text-threat">Could not load plans: {err}</p>}
        <div className="mt-3 overflow-x-auto">
        <table className="w-full overflow-hidden glass-tile text-sm">
          <thead className="text-left text-ink-3">
            <tr>
              <th className="px-4 py-2">Plan</th>
              <th className="px-4 py-2">Duration</th>
              <th className="px-4 py-2 text-right">Monero</th>
              <th className="px-4 py-2 text-right">Bitcoin</th>
            </tr>
          </thead>
          <tbody>
            {denoms.map((d) => (
              <tr key={d.id} className="border-t border-white/10">
                <td className="px-4 py-2 font-medium">{d.label}</td>
                <td className="px-4 py-2 text-ink-2">
                  {d.duration_days} {d.duration_days === 1 ? "day" : "days"}
                </td>
                <td className="px-4 py-2 text-right font-mono">{d.price_xmr} XMR</td>
                <td className="px-4 py-2 text-right font-mono">{d.price_btc} BTC</td>
              </tr>
            ))}
            {denoms.length === 0 && !err && (
              <tr>
                <td colSpan={4} className="px-4 py-3 text-ink-3">
                  Loading…
                </td>
              </tr>
            )}
          </tbody>
        </table>
        </div>
        <p className="mt-2 text-xs text-ink-2">
          Buy from the app:{" "}
          <code className="rounded bg-white/10 px-1">shaip buy --plan month --server &lt;url&gt;</code>
        </p>
      </section>

      {/* Discount / comp code */}
      <section className="mt-8">
        <h2 className="text-lg font-semibold text-signal">Have a code?</h2>
        <p className="mt-1 text-sm text-ink-2">
          A discount, promo, or test code grants access without a payment. Like a redeemed token,
          claiming a code is identity-free: no account, no card, and it records only that one use was
          spent.
        </p>
        <div className="mt-3 flex gap-2">
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && code.trim()) claimCode();
            }}
            placeholder="SHAIP-XXXX-XXXX-XXXX"
            aria-label="discount or comp code"
            className="field flex-1 font-mono text-sm uppercase"
          />
          <button
            onClick={claimCode}
            disabled={!code.trim() || claiming}
            className="btn-glass px-4 py-2 text-sm"
          >
            {claiming ? "Redeeming…" : "Redeem"}
          </button>
        </div>
        {codeErr && <p className="mt-2 text-sm text-threat">{codeErr}</p>}
        {grant && (
          <div className="mt-3 rounded-2xl border border-ok/30 bg-ok/5 p-4 text-sm">
            <p className="font-semibold text-ok">Access granted — plan: {grant.plan}</p>
            <p className="mt-1 text-ok">
              Valid until <span className="font-mono">{grant.expires_at.slice(0, 10)}</span>.
            </p>
            <p className="mt-2 text-ink-2">
              Paste this access grant into the app (Setup → Paste config, or{" "}
              <code className="rounded bg-white/10 px-1 text-signal">shaip redeem --grant …</code>):
            </p>
            <textarea
              readOnly
              value={grant.grant}
              onFocus={(e) => e.currentTarget.select()}
              className="field mt-2 h-20 font-mono text-xs"
            />
          </div>
        )}
      </section>

      {/* Order status lookup */}
      <section className="mt-8">
        <h2 className="text-lg font-semibold text-signal">Check an order</h2>
        <div className="mt-3 flex gap-2">
          <input
            value={orderId}
            onChange={(e) => setOrderId(e.target.value)}
            placeholder="order id"
            className="field flex-1 font-mono text-sm"
          />
          <button
            onClick={lookup}
            disabled={!orderId.trim()}
            className="btn-glass px-4 py-2 text-sm"
          >
            Look up
          </button>
        </div>
        {lookupErr && <p className="mt-2 text-sm text-threat">{lookupErr}</p>}
        {order && (
          <div className="mt-3 glass-tile p-4 text-sm">
            <div className="flex justify-between">
              <span className="text-ink-2">Status</span>
              <span className={`font-semibold ${statusColor[order.status] ?? ""}`}>
                {order.status.replace("_", " ")}
              </span>
            </div>
            <div className="mt-1 flex justify-between">
              <span className="text-ink-2">Plan</span>
              <span>{order.denom}</span>
            </div>
            <div className="mt-1 flex justify-between">
              <span className="text-ink-2">Amount</span>
              <span className="font-mono">{order.amount_label}</span>
            </div>
            {order.status === "awaiting_payment" && (
              <div className="mt-2 break-all rounded bg-white/5 p-2 font-mono text-xs text-ink-2">
                {order.address}
              </div>
            )}
          </div>
        )}
      </section>

      <p className="mt-8 glass-tile p-4 text-xs text-ink-2">
        <span className="font-semibold">Limits.</span> No account or email is needed to pay. The token
        is unlinkable, but timing and IP addresses are not: if you buy and connect from the same
        network, or connect right after paying, the operator can guess the link. The VPN server can
        see where your traffic goes, as any VPN operator can. See docs/payments.md for the full
        threat model.
      </p>
    </main>
  );
}
