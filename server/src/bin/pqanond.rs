//! `pqanond` — PQ-ANON tunnel daemon (§11.1).
//!
//! A real UDP server that:
//! 1. answers the PQANON-HS/1 handshake (plain-framed, pre-key),
//! 2. establishes a per-client [`Session`], and
//! 3. decrypts morphed DATA packets and echoes them back (a stand-in for TUN
//!    forwarding — the TUN read/write loop is the §19 integration point).
//!
//! Handshake messages are plain-framed because the per-epoch morph key is
//! derived from `ss_mix`, which does not exist until the handshake completes;
//! anti-probing (cookies + signature gating, §10) protects the handshake, and
//! all DATA is morphed.

use anyhow::Result;
use clap::Parser;
use pqanon::handshake::{Established, Identity, ServerHandshake};
use pqanon::obf::Obfuscator;
use pqanon::transport::Session;
use pqanon::wire::{Envelope, MsgType};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(name = "pqanond", about = "PQ-ANON tunnel daemon")]
struct Cli {
    /// UDP listen address.
    #[arg(short, long, default_value = "0.0.0.0:443")]
    listen: String,
}

enum PeerState {
    Handshaking(Box<ServerHandshake>),
    Established {
        session: Box<Session>,
        obf: Box<Obfuscator>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();

    let identity = Identity::generate();
    tracing::warn!(
        "demo mode: accepting ANY client identity (use a pinned allow-list in production)"
    );
    tracing::info!(server_identity = %hex16(identity.identity_id()), "pqanond identity");

    let socket = UdpSocket::bind(&cli.listen).await?;
    tracing::info!(listen = %socket.local_addr()?, "pqanond listening");

    let mut peers: HashMap<SocketAddr, PeerState> = HashMap::new();
    let mut buf = vec![0u8; 65536];

    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let pkt = &buf[..n];
        if let Err(e) = handle(&socket, &identity, &mut peers, src, pkt).await {
            tracing::debug!(%src, error = %e, "dropping packet");
        }
    }
}

async fn handle(
    socket: &UdpSocket,
    identity: &Identity,
    peers: &mut HashMap<SocketAddr, PeerState>,
    src: SocketAddr,
    pkt: &[u8],
) -> Result<()> {
    // Established peer: DATA is morphed.
    if let Some(PeerState::Established { session, obf }) = peers.get_mut(&src) {
        let sealed = obf.demorph(pkt)?;
        let env = session.open_data(&sealed)?;
        if env.msg_type == MsgType::Data {
            tracing::info!(%src, bytes = env.payload.len(), "DATA received; echoing");
            let reply = session.seal_data(MsgType::Data, env.payload)?;
            let wire = obf.morph(&reply);
            socket.send_to(&wire, src).await?;
        }
        return Ok(());
    }

    // Otherwise a plain-framed handshake message.
    let env = Envelope::from_plain(pkt)?;
    match env.msg_type {
        MsgType::ClientHello => {
            let mut hs = ServerHandshake::new_open(identity.clone(), env.conn_id);
            hs.recv_client_hello(&env, true)?;
            let shello = hs.server_hello()?;
            socket.send_to(&shello.to_plain(), src).await?;
            peers.insert(src, PeerState::Handshaking(Box::new(hs)));
            tracing::info!(%src, "CLIENT_HELLO ok; sent SERVER_HELLO");
        }
        MsgType::ClientFinish => {
            let Some(PeerState::Handshaking(hs)) = peers.remove(&src) else {
                anyhow::bail!("CLIENT_FINISH without pending handshake");
            };
            let mut hs = *hs;
            let est: Established = hs.recv_client_finish(&env)?;
            tracing::info!(%src, conn_id = format!("{:#018x}", est.conn_id),
                client = %hex16(est.peer_id), "session established");
            let session = Session::new(est.conn_id, est.k_c2s, est.k_s2c, src, false, 1400);
            let obf = Obfuscator::new(&est.ss_mix, 1);
            peers.insert(
                src,
                PeerState::Established {
                    session: Box::new(session),
                    obf: Box::new(obf),
                },
            );
        }
        other => anyhow::bail!("unexpected handshake type {other:?}"),
    }
    Ok(())
}

fn hex16(b: [u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
