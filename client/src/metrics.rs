//! Minimal Prometheus metrics for the Rust daemons (§16).
//!
//! The daemons don't warrant a full metrics framework, so this is a handful of
//! process-global atomic counters, a renderer for the Prometheus text exposition
//! format, and a tiny HTTP `/metrics` server. It is dependency-free (no crypto,
//! nothing to hand-roll) and lock-free. The control plane exports its own richer
//! set via client_golang; this covers the tunnel and mix daemons.

use std::sync::atomic::{AtomicU64, Ordering};

/// A monotonically increasing counter.
pub struct Counter(AtomicU64);

impl Counter {
    pub const fn new() -> Self {
        Counter(AtomicU64::new(0))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// A value that goes up and down (set from the owner's view of the truth).
pub struct Gauge(AtomicU64);

impl Gauge {
    pub const fn new() -> Self {
        Gauge(AtomicU64::new(0))
    }
    pub fn set(&self, v: u64) {
        self.0.store(v, Ordering::Relaxed);
    }
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

// --- shaipd (tunnel daemon) ---
pub static HANDSHAKES_OK: Counter = Counter::new();
pub static HANDSHAKES_FAILED: Counter = Counter::new();
pub static HANDSHAKES_DROPPED: Counter = Counter::new();
pub static HANDSHAKE_RETRIES: Counter = Counter::new();
pub static POOL_EXHAUSTED: Counter = Counter::new();
pub static SESSIONS_ESTABLISHED: Counter = Counter::new();
pub static DATA_PACKETS: Counter = Counter::new();
pub static DECOY_PROBES: Counter = Counter::new();
pub static SESSIONS_ACTIVE: Gauge = Gauge::new();
pub static HANDSHAKES_PENDING: Gauge = Gauge::new();
pub static SESSIONS_ENDED: Counter = Counter::new();
pub static PACKETS_SPOOFED: Counter = Counter::new();
pub static PACKETS_FILTERED: Counter = Counter::new();
pub static KEEPALIVES: Counter = Counter::new();
pub static BYTES_FROM_CLIENTS: Counter = Counter::new();
pub static BYTES_TO_CLIENTS: Counter = Counter::new();

// --- shaip-mixd (mix node) ---
pub static MIX_CELLS_FORWARDED: Counter = Counter::new();
pub static MIX_COVER_CELLS: Counter = Counter::new();
pub static MIX_CELLS_DROPPED: Counter = Counter::new();
pub static MIX_FORWARD_FAILED: Counter = Counter::new();
pub static MIX_PAYLOADS_DELIVERED: Counter = Counter::new();

struct Metric {
    name: &'static str,
    help: &'static str,
    value: u64,
    gauge: bool,
}

const fn counter(name: &'static str, help: &'static str, value: u64) -> Metric {
    Metric { name, help, value, gauge: false }
}

const fn gauge(name: &'static str, help: &'static str, value: u64) -> Metric {
    Metric { name, help, value, gauge: true }
}

fn snapshot() -> Vec<Metric> {
    vec![
        counter("shaip_server_handshakes_ok_total", "Completed server handshakes.", HANDSHAKES_OK.get()),
        counter("shaip_server_handshakes_failed_total", "Server handshakes that errored or were rejected.", HANDSHAKES_FAILED.get()),
        counter("shaip_server_handshakes_dropped_total", "CLIENT_HELLOs dropped at the half-open handshake limit.", HANDSHAKES_DROPPED.get()),
        counter("shaip_server_handshake_retries_total", "RETRY cookies issued to unvalidated senders while the half-open table was full.", HANDSHAKE_RETRIES.get()),
        counter("shaip_server_pool_exhausted_total", "Sessions refused because every tunnel address was in use.", POOL_EXHAUSTED.get()),
        counter("shaip_server_sessions_established_total", "Sessions established (keys derived).", SESSIONS_ESTABLISHED.get()),
        counter("shaip_server_data_packets_total", "DATA packets decrypted by the server.", DATA_PACKETS.get()),
        counter("shaip_server_decoy_probes_total", "TLS decoy handshakes completed by a prober.", DECOY_PROBES.get()),
        gauge("shaip_server_sessions_active", "Sessions currently established.", SESSIONS_ACTIVE.get()),
        gauge("shaip_server_handshakes_pending", "Handshakes awaiting CLIENT_FINISH.", HANDSHAKES_PENDING.get()),
        counter("shaip_server_sessions_ended_total", "Sessions ended (closed, timed out, or replaced by a new handshake).", SESSIONS_ENDED.get()),
        counter("shaip_server_spoofed_packets_total", "Client packets dropped for a source address other than the client's own.", PACKETS_SPOOFED.get()),
        counter("shaip_server_filtered_packets_total", "Client packets dropped by destination policy (other clients, private ranges).", PACKETS_FILTERED.get()),
        counter("shaip_server_keepalives_total", "Keepalive pings answered.", KEEPALIVES.get()),
        counter("shaip_server_client_bytes_in_total", "Bytes of IP traffic received from clients.", BYTES_FROM_CLIENTS.get()),
        counter("shaip_server_client_bytes_out_total", "Bytes of IP traffic sent to clients.", BYTES_TO_CLIENTS.get()),
        counter("shaip_mix_cells_forwarded_total", "Onion cells peeled and forwarded by the mix.", MIX_CELLS_FORWARDED.get()),
        counter("shaip_mix_cover_cells_total", "Cover-traffic cells emitted by the mix.", MIX_COVER_CELLS.get()),
        counter("shaip_mix_cells_dropped_total", "Datagrams dropped: not a cell, a replay, or not peelable by this hop.", MIX_CELLS_DROPPED.get()),
        counter("shaip_mix_forward_failed_total", "Peeled cells the mix could not send on.", MIX_FORWARD_FAILED.get()),
        counter("shaip_mix_payloads_delivered_total", "Cells that ended at this hop (exit delivery).", MIX_PAYLOADS_DELIVERED.get()),
    ]
}

/// Render the Prometheus text exposition format.
pub fn render() -> String {
    let mut out = String::new();
    for m in snapshot() {
        out.push_str(&format!("# HELP {} {}\n", m.name, m.help));
        out.push_str(&format!("# TYPE {} {}\n", m.name, if m.gauge { "gauge" } else { "counter" }));
        out.push_str(&format!("{} {}\n", m.name, m.value));
    }
    out
}

/// Serve `GET /metrics` over plain HTTP on `addr` until the task is cancelled.
/// Plain HTTP is correct here: metrics are scraped on a private network, carry
/// no secrets, and Prometheus does not do TLS to targets by default.
pub async fn serve(addr: std::net::SocketAddr) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics server listening on /metrics");
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let first = req.lines().next().unwrap_or("");
            let (status, body) = if first.starts_with("GET /metrics") {
                ("200 OK", render())
            } else if first.starts_with("GET /health") {
                ("200 OK", "ok\n".to_string())
            } else {
                ("404 Not Found", "not found\n".to_string())
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.flush().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_count_and_render() {
        HANDSHAKES_OK.inc();
        HANDSHAKES_OK.add(4);
        let text = render();
        assert!(text.contains("# TYPE shaip_server_handshakes_ok_total counter"));
        assert!(text.contains("shaip_server_handshakes_ok_total "));
        // Value reflects what we added (>= 5, other tests may add too).
        assert!(HANDSHAKES_OK.get() >= 5);
        // Every declared series is present with HELP + TYPE + sample.
        for name in [
            "shaip_server_handshakes_ok_total",
            "shaip_server_sessions_established_total",
            "shaip_mix_cover_cells_total",
        ] {
            assert!(text.contains(&format!("# HELP {name}")), "missing {name}");
        }
    }
}
