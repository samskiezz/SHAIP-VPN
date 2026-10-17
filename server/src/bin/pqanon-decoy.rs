//! Standalone TLS decoy (§10.2). Runs a real HTTPS server so an active prober
//! scanning the host's TCP port sees an ordinary website, while PQANON lives on
//! the UDP port. Can run on its own or be launched by `pqanond --decoy`.

use anyhow::{Context, Result};
use clap::Parser;
use pqanon::decoy::{DecoyConfig, TlsDecoy, DEFAULT_INDEX_HTML};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "pqanon-decoy", about = "SHAIP VPN live TLS 1.3 decoy server")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: std::net::SocketAddr,

    /// Certificate path (PEM). Auto-generated self-signed if missing.
    #[arg(long, default_value = "/etc/pqanon/decoy/cert.pem")]
    cert: PathBuf,

    /// Private key path (PEM). Auto-generated if missing.
    #[arg(long, default_value = "/etc/pqanon/decoy/key.pem")]
    key: PathBuf,

    /// HTML file to serve at `/`. Uses a built-in page if omitted.
    #[arg(long)]
    index: Option<PathBuf>,

    /// Handshake timeout, seconds.
    #[arg(long, default_value_t = 10)]
    handshake_timeout_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    pqanon::redact::init_server_logging("pqanon=info");

    let args = Args::parse();
    let index_html = match &args.index {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("read index {}", p.display()))?,
        None => DEFAULT_INDEX_HTML.to_string(),
    };
    let cfg = DecoyConfig {
        listen: args.listen,
        cert_path: args.cert,
        key_path: args.key,
        index_html,
        handshake_timeout: Duration::from_secs(args.handshake_timeout_secs),
    };

    let decoy = TlsDecoy::new(cfg)?;
    tracing::info!(cert_fp = %decoy.cert_fingerprint(), "starting TLS decoy");

    tokio::select! {
        res = decoy.run() => res,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("SIGINT, stopping");
            Ok(())
        }
    }
}
