//! `pqanon-mixd` — SHAIP VPN mix node (§10, §11.1).
//!
//! Receives fixed-size (2048-byte) PQANON-MIX/1 cells, peels its own onion
//! layer with its long-term X25519 key, and either forwards the re-framed cell
//! to the next hop or, as the exit, delivers the payload. Holds no capabilities
//! and keeps no per-client tunnel state — it only routes cells.
//!
//! Replay protection is wired here: a Bloom filter over each received cell
//! drops exact replays (a sealed cell cannot be mutated in flight, so a replay
//! is byte-identical). Cover traffic is globally scheduled: with `--cover-peer`
//! set, the node emits cover cells to its peers at a network-wide Poisson rate
//! that is independent of client count or activity. Not yet wired (see §10): the
//! per-hop exponential delay queue and loop protection. The peel is complete.

use anyhow::Result;
use clap::Parser;
use pqanon::bloom::BloomFilter;
use pqanon::mix::{peel, Peeled, CELL_SIZE};
use pqanon::mix_cover::GlobalCoverScheduler;
use rand::rngs::OsRng;
use rand::RngCore;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(name = "pqanon-mixd", about = "SHAIP VPN mix node")]
struct Cli {
    /// UDP listen address.
    #[arg(short, long, default_value = "0.0.0.0:8443")]
    listen: String,

    /// Peer mix address to send cover cells to (repeatable). Enables the
    /// globally-scheduled cover-traffic process when at least one is given.
    #[arg(long = "cover-peer")]
    cover_peer: Vec<SocketAddr>,

    /// Network-wide cover emission rate, in cells/sec (ignored without peers).
    #[arg(long = "cover-rate", default_value_t = 1.0)]
    cover_rate: f64,

    /// Expose Prometheus metrics on this TCP address (e.g. 127.0.0.1:9101).
    #[arg(long)]
    metrics: Option<String>,

    /// Persistent X25519 onion key, created 0600 on first run. The directory
    /// lists each mix's public key, so without it the listing goes stale on
    /// every restart and clients build onions this node can no longer peel.
    #[arg(long)]
    key: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    pqanon::redact::init_server_logging("info");
    let cli = Cli::parse();

    // Long-term mix key: loaded from (or created in) --key so it survives
    // restarts and its public half can be published in the directory.
    let secret = match &cli.key {
        Some(path) => {
            let (raw, created) = pqanon::keystore::load_or_create_x25519(path)?;
            if created {
                tracing::info!(path = %path.display(), "created a new persistent mix key");
            }
            StaticSecret::from(*raw)
        }
        None => {
            tracing::warn!("no --key: using an ephemeral mix key; directory listings go stale on restart");
            StaticSecret::random_from_rng(OsRng)
        }
    };
    let public = PublicKey::from(&secret);
    tracing::info!(mix_pubkey = %hex(public.as_bytes()), "pqanon-mixd identity");

    let socket = Arc::new(UdpSocket::bind(&cli.listen).await?);
    tracing::info!(listen = %socket.local_addr()?, "pqanon-mixd listening");

    if let Some(metrics_addr) = cli.metrics.clone() {
        let addr: SocketAddr = metrics_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("bad --metrics address {metrics_addr:?}: {e}"))?;
        tokio::spawn(async move {
            if let Err(e) = pqanon::metrics::serve(addr).await {
                tracing::error!(err = %e, "metrics server failed");
            }
        });
    }

    // Globally-scheduled cover traffic: one Poisson process at a node-wide rate,
    // independent of how many clients are connected or active, so the emission
    // rate leaks nothing about the client population.
    if !cli.cover_peer.is_empty() && cli.cover_rate > 0.0 {
        let cover_sock = socket.clone();
        let peers = cli.cover_peer.clone();
        let rate = cli.cover_rate;
        tracing::info!(rate, peers = peers.len(), "global cover traffic enabled");
        tokio::spawn(async move {
            let mut sched = GlobalCoverScheduler::new(rate);
            let step = Duration::from_millis(20);
            let mut ticker = tokio::time::interval(step);
            loop {
                ticker.tick().await;
                let due = sched.tick(step.as_millis() as u64);
                for _ in 0..due {
                    // A fully-random 2048-byte cell is indistinguishable from a
                    // real framed cell on the wire; a receiving peer fails to
                    // peel it and drops it as "not for this hop".
                    let mut cell = [0u8; CELL_SIZE];
                    OsRng.fill_bytes(&mut cell);
                    let peer = peers[rand::random::<usize>() % peers.len()];
                    let _ = cover_sock.send_to(&cell, peer).await;
                    pqanon::metrics::MIX_COVER_CELLS.inc();
                }
            }
        });
    }

    // Replay filter over received cells (~2^20 bits, 3 hashes). A sealed cell
    // is immutable in flight, so an exact byte-for-byte repeat is a replay.
    let mut replay = BloomFilter::new(1 << 20, 3);

    // Nothing about a cell is logged, at any level: not where it came from,
    // where it went, its size, or when. A mix that logged "cell from A to B at
    // T" would undo the mixing it exists for. What it does is visible only as
    // counters (pqanon::metrics).
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        if n != CELL_SIZE {
            pqanon::metrics::MIX_CELLS_DROPPED.inc();
            continue;
        }
        let mut cell = [0u8; CELL_SIZE];
        cell.copy_from_slice(&buf[..CELL_SIZE]);
        let _ = src; // used only to receive; never stored or logged

        if replay.check_and_insert(&cell) {
            pqanon::metrics::MIX_CELLS_DROPPED.inc();
            continue;
        }

        match peel(&secret, &cell) {
            Ok(Peeled::Relay { next, cell }) => {
                if socket.send_to(&cell[..], next).await.is_ok() {
                    pqanon::metrics::MIX_CELLS_FORWARDED.inc();
                } else {
                    pqanon::metrics::MIX_FORWARD_FAILED.inc();
                }
            }
            Ok(Peeled::Deliver { payload }) => {
                // An exit gateway hands `payload` to the clearnet bridge
                // (pqanon-gw); this daemon only counts it.
                let _ = payload;
                pqanon::metrics::MIX_PAYLOADS_DELIVERED.inc();
            }
            Err(_) => pqanon::metrics::MIX_CELLS_DROPPED.inc(),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
