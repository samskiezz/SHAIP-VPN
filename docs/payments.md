# Untraceable payments (§20)

SHAIP-VPN takes **no fiat, no cards, no identity**. Access is bought with Monero
and redeemed through **Chaumian e-cash**, so the operator cannot link a payment
to the VPN usage it funded — not by policy, by cryptography.

Two independent privacy properties stack:

| Layer | Primitive | What it hides |
|-------|-----------|---------------|
| Payment rail | **Monero** (per-order subaddress) | amount, sender, receiver — on-chain |
| Access tokens | **RFC 9474 RSA blind signatures** (RSABSSA-SHA384-PSS-Deterministic) | the link between the payment and the token that is later redeemed |

No Stripe, no PayPal, no KYC, no account. You never give a name or an email.

## The flow

```
            buyer (app/CLI)                         mint (control plane)
  ──────────────────────────────────────────────────────────────────────
  1. GET /api/pay/denominations  ───────────────▶  plans + RSA public keys
  2. pick plan, make N random nonces
     blind each under the plan key
  3. POST /api/pay/order {blinded_tokens} ──────▶  reserve order, return a
                                                   one-time Monero subaddress
  4. pay the subaddress in Monero  ─ ─ ─ ─ ─ ─ ▶  monerod / wallet-rpc
  5. GET /api/pay/order/{id}  ───────────────────▶ "paid" once confirmed
  6. POST /api/pay/collect {order_id} ──────────▶  BLIND-SIGN each blinded
                                                   token (never sees the nonce)
  7. unblind → ordinary RSA signatures over your nonces
  ...                      (later, unlinkably)                       ...
  8. POST /api/pay/redeem {nonce, signature} ───▶  verify + check not spent →
                                                   issue a VPN access grant
```

Step 6 is the crux: the mint signs a **blinded** nonce, so the signature it
produces cannot be recognised when the unblinded token comes back at step 8. The
mint stores only a hash of each spent nonce (never the nonce itself), so even its
own records reveal nothing.

## Why it is untraceable

- **Blind signatures (unlinkability).** The mint's view at signing time is a
  blinded value `H(nonce)·r^e mod N`; the blinding factor `r` never leaves the
  client. The finalized token is an ordinary RSASSA-PSS signature over `nonce`.
  There is no information linking the two, so a redeemed token cannot be tied to
  any order or payment — even by the operator, even under subpoena.
- **Denominations, not amounts.** Each plan (`day`/`week`/`month`/`quarter`) has
  its own RSA key. The plan you bought is encoded by *which key* signs your
  tokens, so the mint never needs to see a per-token amount.
- **Monero.** The payment leg itself leaks nothing on-chain: stealth addresses,
  ring signatures and confidential amounts hide who paid, who received, and how
  much.
- **No identity anywhere.** The `/api/pay/*` endpoints take and return no account,
  email, or card. The access grant carries a random session id and the plan's
  expiry, nothing else.

## Double-spend protection

A token is one-time. At redemption the mint records `SHA-256(denom || nonce)` in
`spent_tokens` (a unique primary key); a second redemption of the same token is
refused with `409`. This is the only thing the mint remembers about a token, and
it is not reversible to the nonce or linkable to a payment.

## Crypto, not hand-rolled

- Server (Go): Cloudflare **CIRCL** `blindsign/blindrsa` for blind-signing and
  verification.
- Client (Rust): **`blind-rsa-signatures`** for blinding and finalizing.
- Both speak RFC 9474, variant **RSABSSA-SHA384-PSS-Deterministic** (the
  deterministic variant is safe here because nonces are 32 bytes of CSPRNG
  output — high entropy — so no message randomizer is needed).

Cross-implementation interop (Rust blind → Go sign → Rust finalize → Go verify)
is proven by the live `pay: untraceable buy→redeem (cross-language)` stage in
`scripts/test-all.sh`.

## Running it

**Client**

```sh
pqanon plans   --server https://cp.example
pqanon buy     --plan month --server https://cp.example      # prints a Monero address
# …pay the address…
pqanon collect --order <id> --server https://cp.example      # unblinds the tokens
pqanon redeem  --plan month --server https://cp.example      # → VPN access grant
```

Tokens and in-flight orders live in `~/.pqanon/wallet.json` (override with
`--store`).

**Operator — Monero rail**

Point the control plane at a `monero-wallet-rpc` (which fronts a `monerod`):

```sh
export MONERO_WALLET_RPC=http://127.0.0.1:18083/json_rpc
export MONERO_ACCOUNT_INDEX=0        # optional (default 0)
export MONERO_MIN_CONF=10            # optional (default 10)
export PAY_KEY_DIR=/var/lib/pqanon/denoms   # persist denomination keys across restarts
```

Without `MONERO_WALLET_RPC` the control plane uses an in-process **dev rail** (no
chain) so the whole flow runs in tests and local dev; its manual settle endpoint
is gated behind `PAY_DEV_SETTLE` and must never be enabled in production.

Each order gets a fresh subaddress via `create_address`; the rail confirms an
order by summing confirmed transfers to that subaddress with `get_transfers`.

## Threat model (what this does and does not defend)

Defends:

- The operator cannot answer "who paid for this session?" — the blinding makes it
  cryptographically impossible, so there is nothing to log, leak, or subpoena.
- An on-chain observer cannot see amounts, payer, or payee (Monero).
- A stolen `spent_tokens` table reveals no nonces and no payment links.

Does **not** defend (out of scope for the payment layer):

- Network-level correlation of your connection (that is the VPN/mixnet's job —
  see the obfuscation and mix layers).
- A buyer who deanonymizes *themselves* by paying from a KYC exchange withdrawal
  with no intermediate hop, or by reusing one token across identities.
- Compromise of the client device holding the wallet.
