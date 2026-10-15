//! `pqanon-mixd` — PQ-ANON mix node (§10, §11.1).
//!
//! Receives fixed-size (2048-byte) PQANON-MIX/1 cells, peels its own onion
//! layer with its long-term X25519 key, and either forwards the re-framed cell
//! to the next hop or, as the exit, delivers the payload. Holds no capabilities
//! and keeps no per-client tunnel state — it only routes cells.
//!
//! Replay protection is wired here: a Bloom filter over each received cell
//! drops exact replays (a sealed cell cannot be mutated in flight, so a replay
//! is byte-identical). Not yet wired (see §10): the per-hop exponential delay
//! queue and loop protection. The cryptographic peel is real and complete.

use anyhow::Result;
use clap::Parser;
use pqanon::bloom::BloomFilter;
use pqanon::mix::{peel, Peeled, CELL_SIZE};
use rand::rngs::OsRng;
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(name = "pqanon-mixd", about = "PQ-ANON mix node")]
struct Cli {
    /// UDP listen address.
    #[arg(short, long, default_value = "0.0.0.0:8443")]
    listen: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();

    // Long-term mix key. In production this is loaded from disk and published to
    // the control plane; for the demo it is generated on boot.
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    tracing::info!(mix_pubkey = %hex(public.as_bytes()), "pqanon-mixd identity");

    let socket = UdpSocket::bind(&cli.listen).await?;
    tracing::info!(listen = %socket.local_addr()?, "pqanon-mixd listening");

    // Replay filter over received cells (~2^20 bits, 3 hashes). A sealed cell
    // is immutable in flight, so an exact byte-for-byte repeat is a replay.
    let mut replay = BloomFilter::new(1 << 20, 3);

    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        if n != CELL_SIZE {
            tracing::debug!(%src, n, "dropping non-cell datagram");
            continue;
        }
        let mut cell = [0u8; CELL_SIZE];
        cell.copy_from_slice(&buf[..CELL_SIZE]);

        if replay.check_and_insert(&cell) {
            tracing::debug!(%src, "dropping replayed cell");
            continue;
        }

        match peel(&secret, &cell) {
            Ok(Peeled::Relay { next, cell }) => {
                tracing::info!(%src, %next, "relaying cell");
                if let Err(e) = socket.send_to(&cell[..], next).await {
                    tracing::warn!(%next, error = %e, "forward failed");
                }
            }
            Ok(Peeled::Deliver { payload }) => {
                tracing::info!(%src, bytes = payload.len(), "exit: delivering payload");
                // An exit gateway hands `payload` to the clearnet bridge
                // (pqanon-gw); here we only log it.
            }
            Err(e) => tracing::debug!(%src, error = %e, "cell not for this hop"),
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
