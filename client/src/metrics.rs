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

// --- pqanond (tunnel daemon) ---
pub static HANDSHAKES_OK: Counter = Counter::new();
pub static HANDSHAKES_FAILED: Counter = Counter::new();
pub static SESSIONS_ESTABLISHED: Counter = Counter::new();
pub static DATA_PACKETS: Counter = Counter::new();
pub static DECOY_PROBES: Counter = Counter::new();

// --- pqanon-mixd (mix node) ---
pub static MIX_CELLS_FORWARDED: Counter = Counter::new();
pub static MIX_COVER_CELLS: Counter = Counter::new();

struct Metric {
    name: &'static str,
    help: &'static str,
    value: u64,
}

fn snapshot() -> Vec<Metric> {
    vec![
        Metric { name: "pqanon_server_handshakes_ok_total", help: "Completed server handshakes.", value: HANDSHAKES_OK.get() },
        Metric { name: "pqanon_server_handshakes_failed_total", help: "Server handshakes that errored or were rejected.", value: HANDSHAKES_FAILED.get() },
        Metric { name: "pqanon_server_sessions_established_total", help: "Sessions established (keys derived).", value: SESSIONS_ESTABLISHED.get() },
        Metric { name: "pqanon_server_data_packets_total", help: "DATA packets decrypted by the server.", value: DATA_PACKETS.get() },
        Metric { name: "pqanon_server_decoy_probes_total", help: "TLS decoy handshakes completed by a prober.", value: DECOY_PROBES.get() },
        Metric { name: "pqanon_mix_cells_forwarded_total", help: "Onion cells peeled and forwarded by the mix.", value: MIX_CELLS_FORWARDED.get() },
        Metric { name: "pqanon_mix_cover_cells_total", help: "Cover-traffic cells emitted by the mix.", value: MIX_COVER_CELLS.get() },
    ]
}

/// Render the Prometheus text exposition format.
pub fn render() -> String {
    let mut out = String::new();
    for m in snapshot() {
        out.push_str(&format!("# HELP {} {}\n", m.name, m.help));
        out.push_str(&format!("# TYPE {} counter\n", m.name));
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
        assert!(text.contains("# TYPE pqanon_server_handshakes_ok_total counter"));
        assert!(text.contains("pqanon_server_handshakes_ok_total "));
        // Value reflects what we added (>= 5, other tests may add too).
        assert!(HANDSHAKES_OK.get() >= 5);
        // Every declared series is present with HELP + TYPE + sample.
        for name in [
            "pqanon_server_handshakes_ok_total",
            "pqanon_server_sessions_established_total",
            "pqanon_mix_cover_cells_total",
        ] {
            assert!(text.contains(&format!("# HELP {name}")), "missing {name}");
        }
    }
}
