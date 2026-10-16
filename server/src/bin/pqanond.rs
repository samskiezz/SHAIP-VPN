//! `pqanond` — PQ-ANON tunnel daemon (§11.1).
//!
//! A real UDP server that answers the PQANON-HS/1 handshake, keeps one session
//! per client identity, and moves the client's IP traffic:
//!
//! - With `--tun`, decrypted packets go to a TUN device and return traffic is
//!   routed to the owning client by destination address. A client may send
//!   only from its own tunnel address. Add `--nat IFACE` and the server
//!   forwards and masquerades that traffic out to the internet; a DNS
//!   forwarder on the tunnel address serves the clients' lookups (pushed to
//!   them in the session ACK), so those never leave from the client's network.
//! - Without `--tun` it echoes decrypted DATA back: a self-contained demo of
//!   the crypto path, used by the tests.
//!
//! Sessions are kept alive by client keepalives, end on `Close` or after the
//! session timeout, and every client is sent `Close` when the daemon stops
//! (SIGINT/SIGTERM), so they reconnect at once. The session logic itself lives
//! in [`pqanon_server::core`].
//!
//! Handshake messages are plain-framed because the per-epoch morph key is
//! derived from `ss_mix`, which does not exist until the handshake completes;
//! anti-probing (a TLS 1.3 decoy, §10.2) answers unrecognized datagrams, and
//! all session traffic is morphed.

use anyhow::Result;
use clap::Parser;
use pqanon::handshake::{DevicePolicy, Identity};
use pqanon_server::core::{Core, Forwarding, Gate, Limits, Out};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

    /// This server's tunnel IP (CIDR) when `--tun` is set. Clients get the
    /// other addresses of this subnet.
    #[arg(long, default_value = "10.77.0.1/24")]
    tun_addr: String,

    /// Forward and masquerade client traffic out of this interface (e.g.
    /// eth0), so clients reach the internet through the server. Needs
    /// `--tun` and nftables; enables IPv4 forwarding while running.
    #[arg(long, requires = "tun")]
    nat: Option<String>,

    /// Upstream resolver for the in-tunnel DNS forwarder (default: the first
    /// nameserver in /etc/resolv.conf).
    #[arg(long)]
    dns_upstream: Option<String>,

    /// Do not run the DNS forwarder (and push no resolver to clients).
    #[arg(long)]
    no_dns: bool,

    /// Let clients reach each other's tunnel addresses (off: isolated).
    #[arg(long)]
    allow_client_to_client: bool,

    /// Let clients reach private, link-local (incl. cloud metadata), and
    /// reserved addresses from this server's network (off by default).
    #[arg(long)]
    allow_private_destinations: bool,

    /// End a session after this many seconds without a packet from it.
    #[arg(long, default_value_t = 180)]
    session_timeout_secs: u64,

    /// Drop a handshake that has not finished after this many seconds.
    #[arg(long, default_value_t = 10)]
    handshake_timeout_secs: u64,

    /// Also run a live TLS 1.3 decoy on this TCP address (e.g. 0.0.0.0:443). A
    /// prober that scans the TCP port completes a real HTTPS handshake and sees
    /// an ordinary website; PQANON stays on the UDP port. TCP and UDP are
    /// independent, so the decoy may share the tunnel's port number.
    #[arg(long)]
    decoy: Option<String>,

    /// Expose Prometheus metrics on this TCP address (e.g. 127.0.0.1:9100).
    #[arg(long)]
    metrics: Option<String>,

    /// Persistent server identity (ML-DSA-65 + Ed25519), created 0600 on first
    /// run. Clients pin its public keys, so without it the identity — and every
    /// client's pin — changes on each restart.
    #[arg(long)]
    identity: Option<std::path::PathBuf>,

    /// Print the public identity in client-config form (the `[server]` keys a
    /// client pins) and exit. Requires `--identity`.
    #[arg(long)]
    print_public: bool,

    /// Admit only enrolled devices: clients must present a device certificate
    /// signed by this device CA (hex Ed25519 key, the control plane's
    /// `device_ca_pub`). Without it the daemon runs in open demo mode.
    #[arg(long)]
    device_ca: Option<String>,

    /// Control-plane CRL (…/api/crl). Devices it lists are refused. The first
    /// fetch must succeed at startup; later failures keep the last verified list.
    #[arg(long, requires = "crl_pub", requires = "device_ca")]
    crl_url: Option<String>,

    /// Pinned CRL key (hex Ed25519, the control plane's `crl_pub`).
    #[arg(long, requires = "crl_url")]
    crl_pub: Option<String>,

    /// How often to refresh the CRL, in seconds.
    #[arg(long, default_value_t = 60)]
    crl_refresh_secs: u64,

    /// Sign this node's descriptor for one epoch with its identity key, print
    /// it, and exit. A node publishes ONE per epoch: two different descriptors
    /// for the same epoch are equivocation and get its stake slashed.
    #[arg(long, requires_all = ["node_id", "epoch", "advertise"])]
    sign_descriptor: bool,

    /// The control plane's id for this node (with --sign-descriptor).
    #[arg(long)]
    node_id: Option<String>,

    /// The epoch the descriptor is for (with --sign-descriptor).
    #[arg(long)]
    epoch: Option<u64>,

    /// The public address to advertise (with --sign-descriptor).
    #[arg(long)]
    advertise: Option<String>,

    /// Advertised capacity in Mbit/s (with --sign-descriptor).
    #[arg(long, default_value_t = 0)]
    capacity_mbps: u32,

    /// Advertised ISO 3166 region (with --sign-descriptor).
    #[arg(long, default_value = "")]
    region: String,

    /// Advertised X25519 mix key, hex (with --sign-descriptor).
    #[arg(long)]
    mix_pub: Option<String>,
}

/// A CRL older than this is treated as a replay (the control plane signs a
/// fresh list on every request).
const CRL_MAX_AGE_SECS: i64 = 600;

type Revoked = Arc<std::sync::RwLock<HashSet<[u8; 16]>>>;

/// Build the device-admission policy, loading the CRL first when configured.
async fn device_policy(cli: &Cli) -> Result<Option<DevicePolicy>> {
    let Some(ca_hex) = &cli.device_ca else {
        return Ok(None);
    };
    let ca = pqanon::enroll_client::parse_pin(ca_hex, "--device-ca")?;
    let revoked: Revoked = Arc::default();
    match (&cli.crl_url, &cli.crl_pub) {
        (Some(url), Some(pub_hex)) => {
            let pinned = pqanon::enroll_client::parse_pin(pub_hex, "--crl-pub")?;
            let (u, k) = (url.clone(), pinned);
            let crl = tokio::task::spawn_blocking(move || pqanon::crl::fetch(&u, &k, CRL_MAX_AGE_SECS))
                .await?
                .map_err(|e| anyhow::anyhow!("initial CRL fetch failed (refusing to start without it): {e}"))?;
            tracing::info!(revoked_devices = crl.revoked_devices.len(), "CRL loaded");
            let issued = crl.issued_at;
            *revoked.write().unwrap() = crl.revoked_devices;
            tokio::spawn(crl_refresher(
                url.clone(),
                pinned,
                revoked.clone(),
                std::time::Duration::from_secs(cli.crl_refresh_secs.max(1)),
                issued,
            ));
        }
        _ => tracing::warn!("--device-ca without --crl-url: revoked devices are NOT refused"),
    }
    let check = revoked.clone();
    Ok(Some(DevicePolicy {
        ca,
        is_revoked: Arc::new(move |id| check.read().unwrap().contains(id)),
    }))
}

/// Keep the revoked set current. A failed refresh keeps the last verified list;
/// a list older than the one in force is ignored as a replay.
async fn crl_refresher(
    url: String,
    pinned: ed25519_dalek::VerifyingKey,
    revoked: Revoked,
    every: std::time::Duration,
    mut last_issued: i64,
) {
    let mut tick = tokio::time::interval(every);
    tick.tick().await; // the first tick is immediate; the startup fetch covered it
    loop {
        tick.tick().await;
        let u = url.clone();
        match tokio::task::spawn_blocking(move || pqanon::crl::fetch(&u, &pinned, CRL_MAX_AGE_SECS)).await {
            Ok(Ok(crl)) if crl.issued_at >= last_issued => {
                last_issued = crl.issued_at;
                let n = crl.revoked_devices.len();
                *revoked.write().unwrap() = crl.revoked_devices;
                tracing::debug!(revoked_devices = n, "CRL refreshed");
            }
            Ok(Ok(_)) => tracing::warn!("ignoring a CRL older than the one in force (replay?)"),
            Ok(Err(e)) => tracing::warn!(error = %e, "CRL refresh failed; keeping the last verified list"),
            Err(e) => tracing::warn!(error = %e, "CRL refresh task failed"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr so stdout stays clean for --print-public.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();

    let identity = match &cli.identity {
        Some(path) => {
            let (id, created) = pqanon::keystore::load_or_create_identity(path)?;
            if created {
                tracing::info!(path = %path.display(), "created a new persistent server identity");
            }
            id
        }
        None if cli.print_public || cli.sign_descriptor => anyhow::bail!(
            "--print-public / --sign-descriptor need --identity: an ephemeral identity changes on every run"
        ),
        None => {
            tracing::warn!("no --identity: using an ephemeral server identity that clients cannot pin across restarts");
            Identity::generate()
        }
    };
    if cli.print_public {
        let p = identity.public();
        println!("identity_id       = \"{}\"", hex16(identity.identity_id()));
        println!("server_ml_dsa_pub = \"{}\"", pqanon::hex_util::encode(&p.pq_bytes()));
        println!("server_ed_pub     = \"{}\"", pqanon::hex_util::encode(&p.ed_bytes()));
        return Ok(());
    }
    if cli.sign_descriptor {
        let mut x25519 = [0u8; 32];
        if let Some(h) = &cli.mix_pub {
            x25519 = pqanon::hex_util::decode_32(h).map_err(|e| anyhow::anyhow!("--mix-pub: {e}"))?;
        }
        let d = pqanon::descriptor::NodeDescriptor {
            node_id: cli.node_id.clone().unwrap_or_default(),
            epoch: cli.epoch.unwrap_or_default(),
            address: cli.advertise.clone().unwrap_or_default(),
            x25519,
            ed25519: identity.public().ed_bytes(),
            capacity_mbps: cli.capacity_mbps,
            region: cli.region.to_uppercase(),
        };
        println!("{}", pqanon::descriptor::sign(&identity, &d)?);
        return Ok(());
    }
    let policy = device_policy(&cli).await?;
    match &policy {
        Some(_) => tracing::info!("device-bound: admitting only clients with a valid device certificate"),
        None => tracing::warn!(
            "demo mode: accepting ANY client identity (use --device-ca to admit enrolled devices only)"
        ),
    }
    tracing::info!(server_identity = %hex16(identity.identity_id()), "pqanond identity");
    let gate = Gate { identity, policy };
    let limits = Limits {
        handshake_timeout: Duration::from_secs(cli.handshake_timeout_secs.max(1)),
        session_timeout: Duration::from_secs(cli.session_timeout_secs.max(5)),
        ..Limits::default()
    };

    let socket = Arc::new(UdpSocket::bind(&cli.listen).await?);

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
                tun_mode(&cli, socket, gate, limits, &name).await
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (name, gate, limits);
                anyhow::bail!("--tun is Linux only (TUN is a Linux kernel interface)")
            }
        }
        None => {
            tracing::info!(listen = %socket.local_addr()?, "pqanond listening (echo mode)");
            serve(socket, Core::new(gate, Forwarding::Echo, limits)?, None).await
        }
    }
}

/// Bring up the TUN device, DNS forwarder and NAT, then serve.
#[cfg(target_os = "linux")]
async fn tun_mode(cli: &Cli, socket: Arc<UdpSocket>, gate: Gate, limits: Limits, name: &str) -> Result<()> {
    use pqanon::tun::{AsyncTun, TunDevice};
    use pqanon_server::core::TunPolicy;
    use pqanon_server::{dns_forward, nat};

    let (gateway, prefix) = parse_cidr(&cli.tun_addr)?;
    let dev = TunDevice::open(name)?;
    dev.configure_v4(gateway, prefix)?;
    dev.set_mtu(pqanon::client::TUNNEL_MTU)?;
    let tun = Arc::new(AsyncTun::new(dev)?);
    tracing::info!(device = %tun.name(), %gateway, prefix, mtu = pqanon::client::TUNNEL_MTU, "server TUN up");

    let dns = if cli.no_dns {
        tracing::warn!("--no-dns: clients get no resolver from this server and keep their own");
        None
    } else {
        let upstream: SocketAddr = match &cli.dns_upstream {
            Some(a) => a
                .parse()
                .or_else(|_| format!("{a}:53").parse())
                .map_err(|_| anyhow::anyhow!("bad --dns-upstream {a:?} (use IP or IP:PORT)"))?,
            None => dns_forward::upstream_from_resolv_conf(&std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())
                .ok_or_else(|| anyhow::anyhow!("no nameserver in /etc/resolv.conf: pass --dns-upstream or --no-dns"))?,
        };
        let (udp, tcp) = dns_forward::bind(gateway).await?;
        tokio::spawn(async move {
            if let Err(e) = dns_forward::serve(udp, tcp, upstream).await {
                tracing::error!(error = %e, "DNS forwarder stopped");
            }
        });
        Some(gateway)
    };

    let _nat = match &cli.nat {
        Some(egress) => Some(nat::enable(tun.name(), gateway, prefix, egress)?),
        None => {
            tracing::warn!("no --nat: clients can reach this server's tunnel address and nothing beyond it");
            None
        }
    };

    let core = Core::new(
        gate,
        Forwarding::Tun(TunPolicy {
            gateway,
            prefix,
            dns,
            allow_client_to_client: cli.allow_client_to_client,
            allow_private_destinations: cli.allow_private_destinations,
        }),
        limits,
    )?;
    tracing::info!(listen = %socket.local_addr()?, "pqanond listening (TUN mode)");
    serve(socket, core, Some(tun)).await
    // `_nat` drops here: forwarding and masquerade are removed.
}

#[cfg(target_os = "linux")]
type Tun = pqanon::tun::AsyncTun;
#[cfg(not(target_os = "linux"))]
type Tun = ();

/// The I/O shell: UDP datagrams and TUN packets in, [`Out`]s out, a 1 s
/// housekeeping tick, and a clean shutdown on SIGINT/SIGTERM.
async fn serve(socket: Arc<UdpSocket>, core: Core, tun: Option<Arc<Tun>>) -> Result<()> {
    let core = Arc::new(std::sync::Mutex::new(core));

    #[cfg(target_os = "linux")]
    if let Some(tun) = tun.clone() {
        let (core, socket) = (core.clone(), socket.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::error!(error = %e, "TUN read failed");
                        return;
                    }
                };
                let out = core.lock().expect("core lock").on_tun_packet(&buf[..n]);
                if let Some(Out::Udp(wire, to)) = out {
                    let _ = socket.send_to(&wire, to).await;
                }
            }
        });
    }

    {
        let core = core.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                core.lock().expect("core lock").on_tick(Instant::now());
            }
        });
    }

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut buf = vec![0u8; 65_536];
    loop {
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                let (n, src) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::debug!(error = %e, "recv_from failed");
                        continue;
                    }
                };
                let outs = core.lock().expect("core lock").on_datagram(src, &buf[..n], Instant::now());
                deliver(&socket, tun.as_deref(), outs).await;
            }
            _ = &mut shutdown => break,
        }
    }
    let outs = core.lock().expect("core lock").shutdown(Instant::now());
    let told = outs.len();
    deliver(&socket, tun.as_deref(), outs).await;
    tracing::info!(clients_told = told, "pqanond stopping; every client was sent Close");
    Ok(())
}

async fn deliver(socket: &UdpSocket, tun: Option<&Tun>, outs: Vec<Out>) {
    for o in outs {
        match o {
            Out::Udp(wire, to) => {
                let _ = socket.send_to(&wire, to).await;
            }
            #[cfg(target_os = "linux")]
            Out::Tun(pkt) => {
                if let Some(t) = tun {
                    if let Err(e) = t.send(&pkt).await {
                        tracing::debug!(error = %e, "TUN write failed");
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            Out::Tun(_) => {
                let _ = tun;
            }
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing the SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(target_os = "linux")]
fn parse_cidr(s: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "24"));
    Ok((ip.trim().parse()?, prefix.trim().parse()?))
}

fn hex16(b: [u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
