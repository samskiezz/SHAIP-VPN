# Node staking and slashing

Nodes post **stake** to be listed in the directory that clients build paths
from. A node that provably misbehaves loses part of that stake and is dropped.
Each property below is enforced by code and tested, not just described.

| Property | How |
|---|---|
| Stake is **paid**, never declared | A bond is a charge on a real payment rail. It counts only once the rail confirms payment. `POST /api/nodes` refuses a `stake_sats` field, and the demo seed no longer invents stake. |
| Paid stake counts **without anyone polling** | A bond watcher (every `STAKE_WATCH_SECS`, default 30) credits paid bonds. Crediting is exactly-once, including under concurrent checks. |
| Leaving takes time, and stays **slashable** | Unbonding stake is locked for `STAKE_UNBONDING_HOURS` (default 14 days) and remains slashable until released. A node cannot misbehave and withdraw at once. |
| Slashing needs **proof**, not trust | Anyone may submit two conflicting **signed descriptors** for the same epoch. They must verify under the key the node *registered*, so nobody can frame a node with descriptors they signed themselves. |
| It **gates path selection** | `GET /api/directory` serves a signed consensus of nodes with at least `STAKE_MIN_SATS` bonded (default 100 000) that are not jailed. Clients verify it against the pinned authority key. |

## Descriptors and equivocation

Each epoch a node publishes **one** descriptor: its id, the epoch, its address,
its mix (X25519) and node (Ed25519) keys, its capacity and its region. The
descriptor is signed with the node's Ed25519 key, which for `pqanond` is its
identity key:

```bash
pqanond --identity /var/lib/pqanon/pqanond.id --sign-descriptor \
  --node-id <id from POST /api/nodes> --epoch 42 --advertise 203.0.113.5:443 \
  --region CH --capacity-mbps 500 [--mix-pub <hex>]
#  PQD1.<base64url(body)>.<base64url(sig)>
```

Two *different* descriptors for the same epoch are **equivocation**. That is
how a node shows different keys or addresses to different clients, the
partitioning attack a directory exists to prevent. Re-publishing an identical
descriptor is not equivocation. To change its address, a node publishes in
the next epoch.

The body is deterministic and length-prefixed, and starts with the
length-prefixed magic `PQANON-NODEDESC-V1`. It can therefore never coincide
with a PQANON-HS/1 transcript (which starts with a 4-byte ML-KEM key length) or
an enrollment proof (`PQANON-ENROLL-CLAIM-V1:`), even though the same key signs
all three. The identity's `sign_node_descriptor` refuses any body without that
prefix. Go (`control-plane/staking`) and Rust (`client/src/descriptor.rs`)
produce byte-identical descriptors; a shared vector pins this.

## API

| Endpoint | Auth | Does |
|---|---|---|
| `POST /api/nodes` | session | Register a node with its `ed_pub` (required for staking), `mix_pub`, `role`, `region` and `capacity_mbps`. The caller becomes its operator. |
| `POST /api/stake/{node}/bond` | operator | `{amount_sats, rail}` returns a charge to pay. Sats-denominated rails only: `btcpay`, or `dev` in tests. |
| `GET /api/stake/{node}` | public | Bonded, unbonding, withdrawable and slashed amounts, `jailed`, `eligible`, pending bonds, and slash records. It also credits newly paid bonds. |
| `POST /api/stake/{node}/unbond` | operator | `{amount_sats}` starts unbonding. |
| `POST /api/stake/slash` | **public** | `{descriptor_a, descriptor_b}`: verify, then slash `STAKE_SLASH_PERCENT` (default 50%) of bonded **and** unreleased unbonding stake, and jail the node. One slash per (node, epoch). |
| `GET /api/directory` | public | The signed consensus of eligible nodes. |

The directory is signed by the control plane acting as a directory authority.
Its key (`DIRECTORY_SIGNER`, or `KEY_DIR/directory.key`) is resolved like every
other key and can live in an HSM. `GET /api/enroll/keys` publishes
`directory_authority` and `directory_pub` for pinning, and
`pqanon directory --url … --authority NAME=HEX` verifies and lists the nodes.

## Tested

- `control-plane/staking`: round trips, a signer that refuses a descriptor
  naming another key, equivocation versus identical / other-epoch / other-node
  descriptors, forged and tampered evidence rejected, the slash arithmetic, and
  the cross-language vector. The Rust signer reproduces it byte-for-byte.
- `handlers_stake_test.go`: self-declared stake refused; a bond counts only once
  paid, and only once; operator-only bonding, sats rails only, and no bonding a
  keyless node; unbonding and over-unbonding; rejected evidence changes
  nothing; exact slash arithmetic; a repeat slash refused; no re-bonding while
  jailed; a directory that verifies and lists only bonded, unjailed nodes.
- The **store contract** runs the same ledger checks on the in-memory store and
  on **real PostgreSQL**. That covers an 8-way concurrent credit race with one
  winner and no double-counted stake, released versus locked unbondings under a
  slash, and idempotent repeat slashes. Running against real Postgres caught a
  pool deadlock: a transaction took a second pool connection to check existence,
  which wedges once concurrent credits exhaust the pool. Every in-transaction
  query now uses the transaction's own connection.
- Battery stage `stake` (real Go control plane + real `pqanond` keys):
  - self-declared stake is refused;
  - an unbonded node is absent from the **Rust-verified** directory;
  - a non-operator cannot bond;
  - a paid bond is credited by the watcher alone, and the node appears with its
    exact advertised line;
  - unbonding works;
  - the node's real key signs two conflicting descriptors;
  - identical and forged evidence are rejected;
  - real evidence slashes exactly 100 000 (50% of 150 000 bonded plus 50 000
    unbonding), permissionlessly and only once;
  - the node is jailed and leaves the directory;
  - the directory is refused under the wrong pin.

## Not done here

- **Payouts.** Matured unbonding stake is reported as `withdrawable`, but the
  control plane has no hot wallet, so paying it out is an operator process.
- **Delegation.** Only a node's operator bonds it. Third-party stake, with
  pro-rata slashing, is a natural extension of the same ledger.
- **Liveness.** Node `status` is not consulted for directory eligibility,
  because no heartbeat feeds it yet. Stake and jail state are the gate.
- **Multi-authority directories.** One control plane signs with threshold 1.
  The directory format and the Rust verifier already handle N-of-M; collecting
  signatures across independent authorities is coordination work.
- **Monero bonds.** Stake is denominated in satoshis, so XMR bonds would need an
  XMR-denominated stake unit or a price feed.
