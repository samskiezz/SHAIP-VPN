//! `pqanon` — PQ-ANON client daemon / CLI.
//!
//! Subcommands:
//! - `keygen` — generate a long-term identity and print its id + keys.
//! - `selftest` — run a full in-process handshake + a DATA packet through
//!   obfuscation, proving the PQANON/1 stack.
//! - `run --config FILE` — load a client config and start the tunnel (the TUN
//!   read/write loop is the integration point described in §19; this wires up
//!   transport + obfuscation).

use anyhow::Result;
use clap::{Parser, Subcommand};
use pqanon::handshake::{ClientHandshake, Identity, ServerHandshake};
use pqanon::obf::Obfuscator;
use pqanon::transport::{Session, Transport};
use pqanon::wire::MsgType;

#[derive(Parser)]
#[command(
    name = "pqanon",
    version,
    about = "PQ-ANON post-quantum anonymizing VPN client"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a long-term identity (ML-DSA-65 + Ed25519) and print its id.
    Keygen,
    /// Run an end-to-end self-test of the PQANON/1 stack.
    Selftest,
    /// Start the client tunnel from a config file.
    Run {
        #[arg(short, long)]
        config: String,
        #[arg(short, long, default_value = "fast")]
        route: String,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => keygen(),
        Cmd::Selftest => selftest(),
        Cmd::Run { config, route } => run(&config, &route),
    }
}

fn keygen() -> Result<()> {
    let id = Identity::generate();
    let pubk = id.public();
    println!("identity_id : {}", hex::encode(id.identity_id()));
    println!("ml_dsa_pub  : {}", hex::encode(pubk.pq_bytes()));
    println!("ed_pub      : {}", hex::encode(pubk.ed_bytes()));
    Ok(())
}

/// Drive a full handshake between an in-process client and server, then send one
/// DATA packet through the session and the obfuscation layer and read it back.
fn selftest() -> Result<()> {
    tracing::info!("PQANON/1 self-test starting");

    let server_id = Identity::generate();
    let client_id = Identity::generate();
    let server_pub = server_id.public();
    let authorized = vec![client_id.identity_id()];

    let hs_conn_id: u64 = rand::random();
    let mut client = ClientHandshake::new(client_id, server_pub, hs_conn_id);
    let mut server = ServerHandshake::new(server_id, authorized, hs_conn_id);

    // Handshake messages travel plain-framed (pre-key), then obfuscated on wire.
    let hello = client.client_hello([0u8; 32])?;
    server.recv_client_hello(&hello, false)?;
    let shello = server.server_hello()?;
    client.recv_server_hello(&shello)?;
    let (finish, client_est) = client.client_finish()?;
    let server_est = server.recv_client_finish(&finish)?;

    anyhow::ensure!(
        client_est.ss_mix == server_est.ss_mix,
        "ss_mix disagreement"
    );
    tracing::info!(
        conn_id = format!("{:#018x}", client_est.conn_id),
        "handshake OK — both sides derived identical keys"
    );

    // Build directional sessions and round-trip one DATA packet.
    let addr = "127.0.0.1:0".parse().unwrap();
    let mut c = Session::new(
        client_est.conn_id,
        client_est.k_c2s,
        client_est.k_s2c,
        addr,
        true,
        1400,
    );
    let mut s = Session::new(
        server_est.conn_id,
        server_est.k_c2s,
        server_est.k_s2c,
        addr,
        false,
        1400,
    );

    let sealed = c.seal_data(MsgType::Data, b"hello over the tunnel".to_vec())?;

    // Obfuscate on the wire, then de-obfuscate on the far side.
    let obf_tx = Obfuscator::new(&client_est.ss_mix, 1);
    let obf_rx = Obfuscator::new(&server_est.ss_mix, 1);
    let wire = obf_tx.morph(&sealed);
    anyhow::ensure!(
        !wire.windows(4).any(|w| w == [0x50, 0x51, 0x41, 0x4E]),
        "PQAN magic leaked onto the wire"
    );
    let recovered = obf_rx.demorph(&wire)?;
    let env = s.open_data(&recovered)?;

    anyhow::ensure!(env.payload == b"hello over the tunnel", "payload mismatch");
    tracing::info!("DATA packet sealed → morphed → demorphed → opened OK");
    println!("SELFTEST OK");
    Ok(())
}

fn run(config: &str, route: &str) -> Result<()> {
    let raw = std::fs::read_to_string(config)
        .map_err(|e| anyhow::anyhow!("reading config {config}: {e}"))?;
    let cfg: toml::Value = toml::from_str(&raw)?;
    let server_addr = cfg
        .get("server")
        .and_then(|s| s.get("address"))
        .and_then(|a| a.as_str())
        .ok_or_else(|| anyhow::anyhow!("config missing [server].address"))?;

    tracing::info!(%server_addr, route, "pqanon run");
    // The async tunnel (UDP bind, PROBE/handshake exchange, TUN read/write loop,
    // rekey driver, cover-traffic scheduler) is assembled on top of the library
    // primitives — see §19 for the components to wire here.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let transport = Transport::bind("0.0.0.0:0").await?;
        tracing::info!(local = ?transport.local_addr()?, "transport bound");
        tracing::warn!("tunnel loop not yet wired — run `pqanon selftest` to exercise the stack");
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}
