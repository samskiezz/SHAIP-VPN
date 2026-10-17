# Unlinkable payments (§20)

SHAIP-VPN takes **no fiat, no cards, no identity**. Access is bought with Monero
(or Bitcoin) and redeemed through **Chaumian e-cash**: the token you redeem
carries nothing that links it to the payment that bought it. That is a property
of the cryptography, not a promise about logs. It covers the token only; the
operator can still guess a link from IP addresses and timing (see the threat
model below), which is up to how you buy and connect.

Two independent privacy properties stack:

| Layer | Primitive | What it hides |
|-------|-----------|---------------|
| Payment rail | **Monero** (per-order subaddress) or **Bitcoin + Lightning** (self-hosted BTCPay) | the on-chain payment (Monero hides amount/sender/receiver; BTCPay keeps it KYC-free and processor-free) |
| Access tokens | **RFC 9474 RSA blind signatures** (RSABSSA-SHA384-PSS-Deterministic) | the link between the payment and the token that is later redeemed |

No Stripe, no PayPal, no KYC, no account. You never give a name or an email.
Whichever coin funds the order, the tokens the mint signs are unlinkable to it.
A Bitcoin payment is still public on-chain, though: it can be traced to the coins
that paid it even though it can't be tied to the token you later redeem.

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
own records cannot connect a redemption to an order.

## Why the tokens are unlinkable

- **Blind signatures (unlinkability).** The mint's view at signing time is a
  blinded value `H(nonce)·r^e mod N`; the blinding factor `r` never leaves the
  client. The finalized token is an ordinary RSASSA-PSS signature over `nonce`.
  Nothing in the token identifies the order it came from, so the token alone
  can't tie a redemption to an order or payment, for the operator or anyone
  asking it. Timing and network metadata are a separate matter (below).
- **Denominations, not amounts.** Each plan (`day`/`week`/`month`/`quarter`) has
  its own RSA key. The plan you bought is encoded by *which key* signs your
  tokens, so the mint never needs to see a per-token amount.
- **Monero.** Stealth addresses, ring signatures and confidential amounts
  obscure who paid, who received and how much on the public ledger. Ring
  signatures hide the payer among decoys, which is strong but has known
  statistical limits; Monero's own research documents them.
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
is proven by the live `pay: unlinkable-token buy→redeem (cross-language)` stage in
`scripts/test-all.sh`.

## Running it

**Client**

```sh
shaip plans   --server https://cp.example
shaip buy     --plan month --server https://cp.example      # prints a Monero address
# …pay the address…
shaip collect --order <id> --server https://cp.example      # unblinds the tokens
shaip redeem  --plan month --server https://cp.example      # → VPN access grant
```

Tokens and in-flight orders live in `~/.shaip/wallet.json` (override with
`--store`).

**Operator — payment rails**

Any combination of rails can be enabled; the default rail is Monero if present,
else BTCPay, else the dev rail. A denomination carries a price in each coin's own
unit (piconero and satoshis), so no exchange-rate feed is needed — the operator
sets both.

Monero — point at a `monero-wallet-rpc` (which fronts a `monerod`):

```sh
export MONERO_WALLET_RPC=http://127.0.0.1:18083
export MONERO_ACCOUNT_INDEX=0        # optional (default 0)
export MONERO_MIN_CONF=10            # optional (default 10)
export MONERO_RPC_USER=...           # optional (if wallet-rpc requires auth)
export MONERO_RPC_PASS=...
```

Each order gets a fresh subaddress via `create_address`; the rail confirms it by
summing confirmed transfers to that subaddress with `get_transfers`.

Bitcoin + Lightning — point at a self-hosted **BTCPay Server** (no KYC, no
processor):

```sh
export BTCPAY_URL=https://btcpay.example.com
export BTCPAY_STORE_ID=...
export BTCPAY_API_KEY=...            # a store API key with invoice permissions
```

Each order creates a BTCPay invoice (priced in BTC); the rail returns the on-chain
address and Lightning invoice, and confirms the order when BTCPay marks it
`Settled`.

Shared:

```sh
export PAY_KEY_DIR=/var/lib/shaip/denoms   # persist denomination keys across restarts
```

Without any rail configured the control plane uses an in-process **dev rail** (no
chain) so the whole flow runs in tests and local dev; its manual settle endpoint
is gated behind `PAY_DEV_SETTLE` and must never be enabled in production.

The client picks a rail with `shaip buy --rail monero|btcpay` (or omit it for the
server default); `shaip plans` lists the rails and per-coin prices.

## Threat model (what this does and does not defend)

Defends:

- From the token, the operator cannot tell which order paid for a session; it
  keeps no record that links the two, so there is none to leak or hand over.
  A redemption records only a hash of the token's nonce and the day: no
  account, no address, no moment. Orders keep days, not moments, too, and
  access grants expire at a day boundary, so the redemption moment can't be
  read back from a grant.
- The live order and redemption counters are on a private metrics listener,
  not the public API, so outsiders can't watch for the moment someone pays.
- An on-chain observer sees no amounts and no addresses for a Monero payment
  (within Monero's known limits, above).
- A stolen `spent_tokens` table reveals no nonces and no payment links.

Does **not** defend (out of scope for the payment layer):

- Correlation by IP address and timing. If you buy, collect and redeem from the
  same address, or connect right after paying, the operator can guess the link.
  Use a different network to buy than to connect, and let time pass in between.
  (The mix layer that would hide the network side is not in the tunnel yet.)
- A Bitcoin payment's on-chain trail (it is public; only the token is
  unlinkable).
- A buyer who deanonymizes *themselves* by paying from a KYC exchange withdrawal
  with no intermediate hop, or by reusing one token across identities.
- Compromise of the client device holding the wallet.
