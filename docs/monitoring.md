# Monitoring (§16)

`docker compose up` brings up a working monitoring stack alongside the services:

| Component | URL | Purpose |
|-----------|-----|---------|
| Prometheus | http://localhost:9090 | scrapes `/metrics`, evaluates alert rules |
| Grafana | http://localhost:3001 | the **SHAIP VPN Overview** dashboard (auto-provisioned) |
| Alertmanager | http://localhost:9093 | routes alerts to Slack / PagerDuty |

Every series the rules and dashboard use is really emitted — nothing is scraped
that the code doesn't export.

**Metrics carry nothing about a customer.** Every series is an aggregate count
with no address, identity, device, account or session label. Keep them private
all the same: on a server with very few users, an aggregate count reflects
those few users' activity, and live order and redemption counters would show
outsiders the moment someone pays. So no metrics endpoint is on a public port:
the control plane serves `/metrics` on its own listener (`METRICS_ADDR`,
default `127.0.0.1:9102`; `:9102` inside the compose network, not published),
and the daemons on the `--metrics` address you give them. Keep Prometheus's
retention no longer than you need.

## What exports metrics

- **Control plane** (Go, `client_golang`) on `METRICS_ADDR`, `GET /metrics`:
  - `shaip_cp_requests_total{method,route,status}` — route labelled by chi
    pattern, not raw path, so cardinality stays bounded
  - `shaip_cp_errors_total{route}` (5xx)
  - `shaip_cp_request_duration_seconds` (histogram)
  - `shaip_cp_auth_failures_total`
  - `shaip_cp_uptime_seconds`
  - `shaip_cp_orders_total{rail,denom}` and
    `shaip_cp_redemptions_total{denom,result}` (ok/spent/invalid)
- **Tunnel daemon** `shaipd --metrics 127.0.0.1:9100`:
  - `shaip_server_handshakes_ok_total`, `shaip_server_handshakes_failed_total`,
    `shaip_server_handshakes_dropped_total` (at the half-open limit)
  - `shaip_server_sessions_established_total`, `shaip_server_sessions_ended_total`,
    `shaip_server_sessions_active`, `shaip_server_handshakes_pending`
  - `shaip_server_pool_exhausted_total` (sessions refused: no tunnel address free)
  - `shaip_server_data_packets_total`, `shaip_server_keepalives_total`,
    `shaip_server_client_bytes_in_total`, `shaip_server_client_bytes_out_total`
  - `shaip_server_spoofed_packets_total`, `shaip_server_filtered_packets_total`
  - `shaip_server_decoy_probes_total` — increments when a prober completes a
    TLS handshake against the decoy
- **Mix daemon** `shaip-mixd --metrics 127.0.0.1:9101`:
  - `shaip_mix_cells_forwarded_total`, `shaip_mix_cover_cells_total`,
    `shaip_mix_cells_dropped_total`, `shaip_mix_forward_failed_total`,
    `shaip_mix_payloads_delivered_total`
- Standard **node-exporter** and **postgres-exporter** for host and DB.

The Rust daemons expose metrics over plain HTTP with a tiny built-in server
(`shaip::metrics`): a handful of lock-free atomic counters rendered in the
Prometheus text format, no extra dependency.

## Alerts

`deploy/prometheus/rules/shaip.yml` — all against the series above plus the
standard `up`, `node_*`, `pg_*`:

- `InstanceDown` (any target), `PostgresDown`
- `ControlPlaneErrorRate` (>2% 5xx), `ControlPlaneLatencyHigh` (p99 > 500ms)
- `AuthFailureSpike`, `TokenForgerySpike` (forged e-cash tokens)
- `HandshakeFailureRatioHigh` (>50% of tunnel handshakes failing)
- `DiskFillingUp`

Set `SLACK_WEBHOOK_URL` and `PAGERDUTY_SERVICE_KEY` in the environment to wire
Alertmanager delivery.

## Verifying it locally

```sh
shaipd --listen 127.0.0.1:4455 --decoy 127.0.0.1:8444 --metrics 127.0.0.1:9100
curl -s http://127.0.0.1:9100/metrics | grep shaip_server_
# probe the decoy, then watch shaip_server_decoy_probes_total increment:
openssl s_client -connect 127.0.0.1:8444 -tls1_3 </dev/null
curl -s http://127.0.0.1:9100/metrics | grep decoy_probes
```
