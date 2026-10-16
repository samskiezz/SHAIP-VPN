# Monitoring (§16)

`docker compose up` brings up a working monitoring stack alongside the services:

| Component | URL | Purpose |
|-----------|-----|---------|
| Prometheus | http://localhost:9090 | scrapes `/metrics`, evaluates alert rules |
| Grafana | http://localhost:3001 | the **PQ-ANON Overview** dashboard (auto-provisioned) |
| Alertmanager | http://localhost:9093 | routes alerts to Slack / PagerDuty |

Every series the rules and dashboard use is really emitted — nothing is scraped
that the code doesn't export.

## What exports metrics

- **Control plane** (Go, `client_golang`) on its main port, `GET /metrics`:
  - `pqanon_cp_requests_total{method,route,status}` — route labelled by chi
    pattern, not raw path, so cardinality stays bounded
  - `pqanon_cp_errors_total{route}` (5xx)
  - `pqanon_cp_request_duration_seconds` (histogram)
  - `pqanon_cp_auth_failures_total`
  - `pqanon_cp_uptime_seconds`
  - `pqanon_cp_orders_total{rail,denom}` and
    `pqanon_cp_redemptions_total{denom,result}` (ok/spent/invalid)
- **Tunnel daemon** `pqanond --metrics 0.0.0.0:9100`:
  - `pqanon_server_handshakes_ok_total`, `pqanon_server_handshakes_failed_total`
  - `pqanon_server_sessions_established_total`
  - `pqanon_server_data_packets_total`
  - `pqanon_server_decoy_probes_total` — increments when a prober completes a
    TLS handshake against the decoy
- **Mix daemon** `pqanon-mixd --metrics 0.0.0.0:9101`:
  - `pqanon_mix_cells_forwarded_total`, `pqanon_mix_cover_cells_total`
- Standard **node-exporter** and **postgres-exporter** for host and DB.

The Rust daemons expose metrics over plain HTTP with a tiny built-in server
(`pqanon::metrics`): a handful of lock-free atomic counters rendered in the
Prometheus text format, no extra dependency.

## Alerts

`deploy/prometheus/rules/pqanon.yml` — all against the series above plus the
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
pqanond --listen 127.0.0.1:4455 --decoy 127.0.0.1:8444 --metrics 127.0.0.1:9100
curl -s http://127.0.0.1:9100/metrics | grep pqanon_server_
# probe the decoy, then watch pqanon_server_decoy_probes_total increment:
openssl s_client -connect 127.0.0.1:8444 -tls1_3 </dev/null
curl -s http://127.0.0.1:9100/metrics | grep decoy_probes
```
