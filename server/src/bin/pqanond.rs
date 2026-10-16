//! `pqanond` — PQ-ANON tunnel daemon (§11.1).
//!
//! A real UDP server that:
//! 1. answers the PQANON-HS/1 handshake (plain-framed, pre-key),
//! 2. establishes a per-client [`Session`], and
//! 3. with `--tun`, decrypts morphed DATA and writes the IP packet to a TUN
//!    device, and routes packets read back from TUN to the owning client by
//!    destination address (the real data plane, §19). Without `--tun` it echoes
//!    decrypted DATA back — a self-contained demo of the crypto path.
//!
//! Handshake messages are plain-framed because the per-epoch morph key is
//! derived from `ss_mix`, which does not exist until the handshake completes;
//! anti-probing (a TLS 1.3 decoy, §10.2) answers unrecognized datagrams, and
//! all DATA is morphed.

use anyhow::Result;
use clap::Parser;
use pqanon::handshake::{Established, Identity, ServerHandshake};
use pqanon::obf::Obfuscator;
use pqanon::transport::Session;
use pqanon::wire::{Envelope, MsgType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;

#[derive(Parser)]
#[command(name = "pqanond", about = "PQ-ANON tunnel daemon")]
struct Cli {
    /// UDP listen address.
    #[arg(short, long, default_value = "0.0.0.0:443")]
    listen: String,

    /// Open a TUN device and forward decrypted client traffic to it, routing
    /// return traffic by destination IP (Linux; needs CAP_NET_ADMIN). Without
    /// this flag the daemon echoes decrypted DATA back instead.
    #[arg(long)]
    tun: Option<String>,

    /// This server's tunnel IP (CIDR) when `--tun` is set.
    #[arg(long, default_value = "10.77.0.1/24")]
    tun_addr: String,

    /// Also run a live TLS 1.3 decoy on this TCP address (e.g. 0.0.0.0:443). A
    /// prober that scans the TCP port completes a real HTTPS handshake and sees
    /// an ordinary website; PQANON stays on the UDP port. TCP and UDP are
    /// independent, so the decoy may share the tunnel's port number.
    #[arg(long)]
    decoy: Option<String>,

    /// Expose Prometheus metrics on this TCP address (e.g. 127.0.0.1:9100).
    #[arg(long)]
    metrics: Option<String>,
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

    let socket = Arc::new(UdpSocket::bind(&cli.listen).await?);
    tracing::info!(listen = %socket.local_addr()?, "pqanond listening");

    // Optional Prometheus metrics endpoint.
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

    // Optional co-located TLS decoy on the TCP port.
    if let Some(decoy_addr) = cli.decoy.clone() {
        let addr: SocketAddr = decoy_addr
            .parse()
            .map_err(|e| anyhow::anyhow!("bad --decoy address {decoy_addr:?}: {e}"))?;
        let cfg = pqanon::decoy::DecoyConfig {
            listen: addr,
            ..Default::default()
        };
        match pqanon::decoy::TlsDecoy::new(cfg) {
            Ok(decoy) => {
                tracing::info!(fp = %decoy.cert_fingerprint(), %addr, "TLS decoy starting");
                tokio::spawn(async move {
                    if let Err(e) = decoy.run().await {
                        tracing::error!(err = %e, "decoy failed");
                    }
                });
            }
            Err(e) => tracing::error!(err = %e, "decoy could not start"),
        }
    }

    match cli.tun.clone() {
        Some(name) => {
            #[cfg(target_os = "linux")]
            {
                run_with_tun(socket, identity, &name, &cli.tun_addr).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                anyhow::bail!("--tun is Linux only (TUN is a Linux kernel interface)")
            }
        }
        None => run_echo(socket, identity).await,
    }
}

/// Default (no-TUN) loop: decrypt DATA and echo it back.
async fn run_echo(socket: Arc<UdpSocket>, identity: Identity) -> Result<()> {
    let mut peers: HashMap<SocketAddr, PeerState> = HashMap::new();
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        if let Err(e) = handle(&socket, &identity, &mut peers, src, &buf[..n]).await {
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
            pqanon::metrics::DATA_PACKETS.inc();
            tracing::info!(%src, bytes = env.payload.len(), "DATA received; echoing");
            let reply = session.seal_data(MsgType::Data, env.payload)?;
            let wire = obf.morph(&reply);
            socket.send_to(&wire, src).await?;
        }
        return Ok(());
    }

    let env = match Envelope::from_plain(pkt) {
        Ok(env) => env,
        Err(_) => {
            // Not our protocol — a scanner/DPI probe. Answer with a randomized
            // TLS 1.3 decoy so the port looks like an HTTPS server (§10.2).
            socket
                .send_to(&pqanon::tls_decoy::probe_response(), src)
                .await?;
            tracing::debug!(%src, "unrecognized packet; sent TLS decoy");
            return Ok(());
        }
    };
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
            let est: Established = match hs.recv_client_finish(&env) {
                Ok(e) => e,
                Err(e) => {
                    pqanon::metrics::HANDSHAKES_FAILED.inc();
                    return Err(e);
                }
            };
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
            pqanon::metrics::HANDSHAKES_OK.inc();
            pqanon::metrics::SESSIONS_ESTABLISHED.inc();
        }
        other => anyhow::bail!("unexpected handshake type {other:?}"),
    }
    Ok(())
}

// --- TUN data-plane mode (§19) ---

#[cfg(target_os = "linux")]
struct TunState {
    peers: HashMap<SocketAddr, PeerState>,
    router: pqanon::router::Router,
    conn_addr: HashMap<u64, SocketAddr>,
}

#[cfg(target_os = "linux")]
async fn run_with_tun(
    socket: Arc<UdpSocket>,
    identity: Identity,
    tun_name: &str,
    tun_addr: &str,
) -> Result<()> {
    use pqanon::tun::{AsyncTun, TunDevice};
    use tokio::sync::Mutex;

    let (ip, prefix) = parse_cidr(tun_addr)?;
    let dev = TunDevice::open(tun_name)?;
    dev.configure_v4(ip, prefix)?;
    let tun = Arc::new(AsyncTun::new(dev)?);
    tracing::info!(device = %tun.name(), %ip, "server TUN up; routing by destination IP");

    let state = Arc::new(Mutex::new(TunState {
        peers: HashMap::new(),
        router: pqanon::router::Router::new(),
        conn_addr: HashMap::new(),
    }));

    // TUN read task: route each kernel packet to its client session by dst IP.
    {
        let (tun, state, socket) = (tun.clone(), state.clone(), socket.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => continue,
                };
                let pkt = &buf[..n];
                // Compute the datagram under the lock, then send after dropping it.
                let out = {
                    let mut st = state.lock().await;
                    match st.router.route(pkt).and_then(|c| st.conn_addr.get(&c).copied()) {
                        Some(addr) => match st.peers.get_mut(&addr) {
                            Some(PeerState::Established { session, obf }) => session
                                .seal_data(MsgType::Data, pkt.to_vec())
                                .ok()
                                .map(|sealed| (obf.morph(&sealed), addr)),
                            _ => None,
                        },
                        None => None,
                    }
                };
                if let Some((wire, addr)) = out {
                    let _ = socket.send_to(&wire, addr).await;
                }
            }
        });
    }

    // UDP recv loop.
    let mut buf = vec![0u8; 65536];
    loop {
        let (n, src) = socket.recv_from(&mut buf).await?;
        let pkt = buf[..n].to_vec();
        if let Err(e) = handle_tun(&socket, &identity, &state, &tun, src, &pkt).await {
            tracing::debug!(%src, error = %e, "dropping packet");
        }
    }
}

#[cfg(target_os = "linux")]
async fn handle_tun(
    socket: &UdpSocket,
    identity: &Identity,
    state: &Arc<tokio::sync::Mutex<TunState>>,
    tun: &Arc<pqanon::tun::AsyncTun>,
    src: SocketAddr,
    pkt: &[u8],
) -> Result<()> {
    // Established peer: decrypt and write the IP packet to the TUN device.
    {
        let mut st = state.lock().await;
        if let Some(PeerState::Established { session, obf }) = st.peers.get_mut(&src) {
            let sealed = obf.demorph(pkt)?;
            let env = session.open_data(&sealed)?;
            let payload = (env.msg_type == MsgType::Data).then_some(env.payload);
            drop(st); // don't hold the lock across the TUN write
            if let Some(p) = payload {
                pqanon::metrics::DATA_PACKETS.inc();
                tun.send(&p).await?;
            }
            return Ok(());
        }
    }

    let env = match Envelope::from_plain(pkt) {
        Ok(env) => env,
        Err(_) => {
            socket
                .send_to(&pqanon::tls_decoy::probe_response(), src)
                .await?;
            return Ok(());
        }
    };
    match env.msg_type {
        MsgType::ClientHello => {
            let mut hs = ServerHandshake::new_open(identity.clone(), env.conn_id);
            hs.recv_client_hello(&env, true)?;
            let shello = hs.server_hello()?;
            socket.send_to(&shello.to_plain(), src).await?;
            state
                .lock()
                .await
                .peers
                .insert(src, PeerState::Handshaking(Box::new(hs)));
            tracing::info!(%src, "CLIENT_HELLO ok; sent SERVER_HELLO");
        }
        MsgType::ClientFinish => {
            let mut st = state.lock().await;
            let Some(PeerState::Handshaking(hs)) = st.peers.remove(&src) else {
                anyhow::bail!("CLIENT_FINISH without pending handshake");
            };
            let mut hs = *hs;
            let est = match hs.recv_client_finish(&env) {
                Ok(e) => e,
                Err(e) => {
                    pqanon::metrics::HANDSHAKES_FAILED.inc();
                    return Err(e);
                }
            };
            let assigned = st.router.allocate_v4(est.conn_id);
            st.conn_addr.insert(est.conn_id, src);
            let session = Session::new(est.conn_id, est.k_c2s, est.k_s2c, src, false, 1400);
            let obf = Obfuscator::new(&est.ss_mix, 1);
            st.peers.insert(
                src,
                PeerState::Established {
                    session: Box::new(session),
                    obf: Box::new(obf),
                },
            );
            pqanon::metrics::HANDSHAKES_OK.inc();
            pqanon::metrics::SESSIONS_ESTABLISHED.inc();
            tracing::info!(%src, conn_id = format!("{:#018x}", est.conn_id),
                assigned = ?assigned, "session established; tunnel IP assigned");
        }
        other => anyhow::bail!("unexpected handshake type {other:?}"),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_cidr(s: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "24"));
    Ok((ip.trim().parse()?, prefix.trim().parse()?))
}

fn hex16(b: [u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
