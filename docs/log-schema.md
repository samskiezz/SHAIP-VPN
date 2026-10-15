# Log Schema

`pqanond`, `pqanon-mixd`, the `pqanon` client, and the Go control plane emit
structured logs. The Rust daemons use `tracing` (set `RUST_LOG`/`PQANON_LANG`);
the control plane uses chi's request logger. This document defines the event
vocabulary a log consumer can rely on.

## Common fields

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | RFC3339 | Event time (UTC) |
| `level` | string | `trace` \| `debug` \| `info` \| `warn` \| `error` |
| `target` / `service` | string | `pqanon`, `pqanond`, `pqanon-mixd`, `control-plane` |

## Events — `pqanond` (tunnel server)

| Event | Extra fields |
|---|---|
| listening | `listen` |
| handshake OK | `conn_id`, `peer` |
| handshake failed | `peer`, `reason` |
| session open | `conn_id`, `peer` |
| session close | `conn_id`, `peer`, `bytes_in`, `bytes_out` |

## Events — `pqanon-mixd` (mix node)

| Event | Extra fields |
|---|---|
| identity | `mix_pubkey` |
| listening | `listen` |
| relaying cell | `src`, `next` |
| dropping replayed cell | `src` |
| exit: delivering payload | `src`, `bytes` |
| cell not for this hop | `src`, `error` |

## Events — `pqanon` (client)

| Event | Extra fields |
|---|---|
| handshake OK | `conn_id` |
| DATA sealed→morphed→demorphed→opened | — |
| transport bound | `local` |

## Events — control plane

The chi `middleware.Logger` emits one line per request with method, path,
status, and latency. The `middleware.RequestID` adds a correlation id. Domain
mutations (register, node create/delete, routing-rule create/delete,
disconnect) are visible through their request lines and response status.

## Localization

User-facing CLI strings are keyed in `i18n/*.toml` and resolved through
`pqanon::i18n` (active language from `PQANON_LANG`, else `LANG`, else `en`;
missing keys fall back to English then to the key). Structured log *targets* and
field names are not localized — only human-readable message bodies.
