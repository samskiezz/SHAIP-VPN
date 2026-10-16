# Log Schema

`pqanond`, `pqanon-mixd`, `pqanon-decoy`, the `pqanon` client and the Go control
plane write plain-text logs to stderr. This document lists what each one logs.

## The rule: nothing about a customer

No server component logs anything about a customer, at any log level:

- no IP address or port of a client, a visitor, or a relayed cell's source or
  next hop;
- no identity, device id, certificate, account or account number;
- no tunnel address;
- no line per request, handshake, session, cell or connection, so no record of
  when anyone connected, for how long, or how much they sent;
- no request path, SNI, request line or DNS name.

There is no option, flag or log level that turns any of this on. What the
servers do is visible only as aggregate counters (docs/monitoring.md).

As a backstop, every line a server writes passes through an address redactor
(`client/src/redact.rs` for the Rust daemons, `control-plane/logredact.go` for
the control plane): any IPv4 or IPv6 address in the line, with its port, is
replaced by `[addr]` before the line is written, even when it is glued to other
text. That includes the servers' own addresses, so a listening line reads
`listen=[addr] port=443`. Panics go through it too. Colour codes are off.

The netns VPN lab (`scripts/e2e/vpn_lab.sh`) checks the rule end to end: after a
full session, a graceful restart, a crash and a reconnect, the server's logs
must contain no IPv4 address at all, no part of the client's identity, and no
per-session line. Unit tests run a whole session lifecycle in the server core at
trace level, and a whole customer journey through the control plane's router,
and assert the same.

## `pqanond` (tunnel server)

Startup and configuration only:

| Event | Fields |
|---|---|
| created a new persistent server identity | `path` |
| pqanond identity | `server_identity` (the server's own) |
| device-bound / open admission | — |
| CRL loaded / refreshed / refresh failed | `revoked_devices` (a count), `error` |
| server TUN up | `device`, `gateway`, `prefix`, `mtu` |
| DNS forwarder up | `listen`, `upstream` |
| egress NAT on / removed | `tun`, `egress`, `subnet` |
| pqanond listening (echo / TUN mode) | `listen`, `port` |
| half-open handshake limit reached (at most once a minute) | `limit` |
| pqanond stopping; every client was sent Close | `clients_told` (a count) |
| TUN read failed, metrics server failed, DNS forwarder stopped | `error` |

## `pqanon-mixd` (mix node)

| Event | Fields |
|---|---|
| created a new persistent mix key / ephemeral key warning | `path` |
| pqanon-mixd identity | `mix_pubkey` (its own) |
| pqanon-mixd listening | `listen` |
| global cover traffic enabled | `rate`, `peers` (a count) |

Cells are never logged: not where one came from, where it went, its size or
when. A mix that logged that would undo the mixing it exists for.

## TLS decoy (`pqanon-decoy`, `pqanond --decoy`)

| Event | Fields |
|---|---|
| starting TLS decoy / TLS decoy listening | `cert_fp`, `addr` |
| loaded / generated / wrote the decoy certificate | `cert`, `key` |
| decoy accept failed | `err` |

Visitors are never logged: not their address, SNI, ALPN or request line.

## Control plane

Startup and configuration only: where its signing keys come from, staking
parameters, the payment rails in use, the store, and the listening and metrics
ports. It has no request logger and reads neither the client's address nor
forwarding headers, so a request leaves no log line. A handler panic is logged
with its value and stack, never the request.

## `pqanon` (client)

The client runs on the customer's own machine and logs for its owner: the
server it connects to, its tunnel address, reconnects and errors. It never logs
the destinations of traffic or DNS names.

## Localization

User-facing CLI strings are keyed in `i18n/*.toml` and resolved through
`pqanon::i18n` (active language from `PQANON_LANG`, else `LANG`, else `en`;
missing keys fall back to English then to the key). Structured log *targets* and
field names are not localized — only human-readable message bodies.
