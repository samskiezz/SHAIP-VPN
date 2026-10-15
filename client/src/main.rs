//! `pqanon` — PQ-ANON client daemon / CLI.
//!
//! Subcommands:
//! - `keygen` — generate a long-term identity and print its id + keys.
//! - `selftest` — run a full in-process handshake + a DATA packet through
//!   obfuscation, proving the PQANON/1 stack.
//! - `run --config FILE` — load a client config and start the tunnel (the TUN
//!   read/write loop is the integration point described in §19; this wires up
//!   transport + obfuscation).
//! - `resolve NAME` — resolve a name through the DNSSEC-validating resolver and
//!   print the security verdict; a bogus (signed-but-invalid) answer is withheld.

use anyhow::Result;
use clap::{Parser, Subcommand};
use pqanon::handshake::{ClientHandshake, Identity, ServerHandshake};
use pqanon::obf::Obfuscator;
use pqanon::transport::Session;
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
    /// Create a real TUN device and prove IP packets flow from the kernel
    /// (Linux; needs CAP_NET_ADMIN).
    TunTest,
    /// Start the client tunnel from a config file.
    Run {
        #[arg(short, long)]
        config: String,
        #[arg(short, long, default_value = "fast")]
        route: String,
    },
    /// Resolve a name through the DNSSEC-validating resolver and print the
    /// security verdict (Secure / Insecure / Bogus). A bogus answer is withheld.
    Resolve {
        /// The hostname to resolve.
        name: String,
        /// Upstream DNS server (host:port).
        #[arg(short, long, default_value = "1.1.1.1:53")]
        server: String,
        /// Record type: a or aaaa.
        #[arg(short = 't', long, default_value = "a")]
        rtype: String,
        /// Pin a zone DNSKEY (hex Ed25519 public key, DNSSEC alg 15) as the
        /// validation anchor. Without one, signed answers can't be proven and
        /// are reported Insecure (or refused with --require-signed).
        #[arg(long)]
        trust_key: Option<String>,
        /// Refuse an unsigned answer instead of returning it Insecure.
        #[arg(long)]
        require_signed: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load the localization catalog (i18n/*.toml) if present. Absent or
    // partial catalogs fall back to English and then to the message key, so
    // this never fails.
    pqanon::i18n::init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => keygen(),
        Cmd::Selftest => selftest(),
        Cmd::TunTest => tun_test(),
        Cmd::Run { config, route } => run(&config, &route),
        Cmd::Resolve {
            name,
            server,
            rtype,
            trust_key,
            require_signed,
        } => resolve_cmd(&name, &server, &rtype, trust_key.as_deref(), require_signed),
    }
}

/// Resolve `name` through the DNSSEC-validating resolver over UDP.
fn resolve_cmd(
    name: &str,
    server: &str,
    rtype: &str,
    trust_key: Option<&str>,
    require_signed: bool,
) -> Result<()> {
    use pqanon::dns_resolver::{UdpDnsTransport, ValidatingResolver, TYPE_A, TYPE_AAAA};
    use pqanon::dnssec::{Dnskey, DNSKEY_FLAG_ZONE};

    let rr_type = match rtype.to_ascii_lowercase().as_str() {
        "a" => TYPE_A,
        "aaaa" => TYPE_AAAA,
        other => anyhow::bail!("unsupported record type {other:?} (use a or aaaa)"),
    };
    let server_sa: std::net::SocketAddr = server
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --server {server:?}: {e}"))?;

    // Pin a validation anchor if supplied.
    let mut keys = Vec::new();
    if let Some(hexkey) = trust_key {
        let raw = hex::decode(hexkey.trim())
            .map_err(|e| anyhow::anyhow!("--trust-key must be hex: {e}"))?;
        keys.push(Dnskey {
            flags: DNSKEY_FLAG_ZONE,
            algorithm: 15,
            public_key: raw,
        });
    }

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut resolver = ValidatingResolver::new(UdpDnsTransport::new(server_sa), keys);
        resolver.require_signed = require_signed;
        let ans = resolver.resolve(name, rr_type).await?;
        println!("name:     {name}");
        println!("security: {:?}", ans.security);
        if ans.addrs.is_empty() {
            println!("addresses: (none — withheld if Bogus)");
        } else {
            for a in &ans.addrs {
                println!("address:  {a}");
            }
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

/// Live proof of the TUN data plane: open a real kernel TUN device, configure
/// it, trigger a packet into its subnet, and capture that packet off the device.
#[cfg(target_os = "linux")]
fn tun_test() -> Result<()> {
    use pqanon::tun::TunDevice;
    use std::sync::mpsc;

    let dev = std::sync::Arc::new(TunDevice::open("pqtest0")?);
    let name = dev.name().to_string();
    tracing::info!(device = %name, "opened real TUN device");

    dev.configure_v4("10.99.0.1".parse().unwrap(), 24)?;
    tracing::info!("configured {name} 10.99.0.1/24 and brought it up (via ioctls)");

    // Reader: capture the first IPv4 packet the kernel routes out to 10.99.0.2.
    let (tx, rx) = mpsc::channel();
    let reader = dev.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        loop {
            match reader.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let pkt = &buf[..n];
                    if pqanon::ipparse::destination_ip(pkt)
                        == Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 99, 0, 2)))
                    {
                        let src = pqanon::ipparse::source_ip(pkt);
                        let _ = tx.send((src, n));
                        return;
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        return;
                    }
                }
            }
        }
    });

    // Trigger: send UDP into the subnet; the kernel emits it out the TUN device.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    for _ in 0..3 {
        let _ = sock.send_to(b"pqanon tun probe", "10.99.0.2:9999");
    }

    match rx.recv_timeout(std::time::Duration::from_secs(3)) {
        Ok((src, n)) => {
            println!(
                "TUN OK: captured a real {n}-byte IP packet from the kernel via {name} \
                 (src={src:?} dst=10.99.0.2)"
            );
            Ok(())
        }
        Err(_) => anyhow::bail!("no packet captured on {name} within 3s"),
    }
}

#[cfg(not(target_os = "linux"))]
fn tun_test() -> Result<()> {
    anyhow::bail!("tun-test is Linux only (TUN is a Linux kernel interface)")
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

#[cfg(target_os = "linux")]
fn run(config: &str, route: &str) -> Result<()> {
    use pqanon::dataplane::DataPlane;
    use pqanon::handshake::PeerPublic;
    use pqanon::tun::{AsyncTun, TunDevice};
    use pqanon::wire::Envelope;
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;

    let raw = std::fs::read_to_string(config)
        .map_err(|e| anyhow::anyhow!("reading config {config}: {e}"))?;
    let cfg: toml::Value = toml::from_str(&raw)?;
    let gstr = |sect: &str, key: &str| -> Option<String> {
        cfg.get(sect)
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };

    let server_addr =
        gstr("server", "address").ok_or_else(|| anyhow::anyhow!("config missing [server].address"))?;
    let server_pq_hex = gstr("server", "server_ml_dsa_pub")
        .ok_or_else(|| anyhow::anyhow!("config missing [server].server_ml_dsa_pub"))?;
    let server_ed_hex = gstr("server", "server_ed_pub")
        .ok_or_else(|| anyhow::anyhow!("config missing [server].server_ed_pub"))?;
    if server_pq_hex.starts_with("hex") || server_ed_hex.starts_with("hex") {
        anyhow::bail!(
            "fill [server].server_ml_dsa_pub / server_ed_pub with the server's real public keys \
             (run `pqanon keygen` on the server and copy its ml_dsa_pub / ed_pub)"
        );
    }
    let server_pub = PeerPublic::from_bytes(
        &hex::decode(server_pq_hex.trim())?,
        &hex::decode(server_ed_hex.trim())?,
    )?;

    let tun_name = gstr("client", "tun_device").unwrap_or_else(|| "pqanon-c0".into());
    let (tun_ip, tun_prefix) =
        parse_cidr(&gstr("client", "tun_address").unwrap_or_else(|| "10.77.0.2/24".into()))?;

    tracing::info!(%server_addr, route, "pqanon run");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let server_sa = tokio::net::lookup_host(&server_addr)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("cannot resolve {server_addr}"))?;
        let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        sock.connect(server_sa).await?;

        // --- PQANON-HS/1 handshake over UDP (plain-framed, pre-key) ---
        let id = Identity::generate();
        let conn: u64 = rand::random();
        let mut hs = ClientHandshake::new(id, server_pub, conn);
        sock.send(&hs.client_hello([0u8; 32])?.to_plain()).await?;

        let mut buf = vec![0u8; 65536];
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), sock.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for SERVER_HELLO"))??;
        hs.recv_server_hello(&Envelope::from_plain(&buf[..n])?)?;
        let (finish, est) = hs.client_finish()?;
        sock.send(&finish.to_plain()).await?;
        tracing::info!(conn_id = format!("{:#018x}", est.conn_id), "handshake OK");

        // --- data plane: TUN <-> tunnel ---
        let dp = Arc::new(Mutex::new(DataPlane::new(
            Session::new(est.conn_id, est.k_c2s, est.k_s2c, server_sa, true, 1400),
            Obfuscator::new(&est.ss_mix, 1),
        )));
        let dev = TunDevice::open(&tun_name)?;
        dev.configure_v4(tun_ip, tun_prefix)?;
        let tun = Arc::new(AsyncTun::new(dev)?);
        tracing::info!(device = %tun.name(), %tun_ip, "{}", pqanon::i18n::t("tunnel_up"));

        // TUN read -> seal + morph -> UDP send.
        let up = {
            let (tun, dp, sock) = (tun.clone(), dp.clone(), sock.clone());
            tokio::spawn(async move {
                let mut b = vec![0u8; 65536];
                loop {
                    let n = tun.recv(&mut b).await?;
                    if n == 0 {
                        break;
                    }
                    let wire = dp.lock().await.outbound(&b[..n])?;
                    sock.send(&wire).await?;
                }
                Ok::<(), anyhow::Error>(())
            })
        };
        // UDP recv -> demorph + open -> TUN write.
        let down = {
            let (tun, dp, sock) = (tun.clone(), dp.clone(), sock.clone());
            tokio::spawn(async move {
                let mut b = vec![0u8; 65536];
                loop {
                    let n = sock.recv(&mut b).await?;
                    if n == 0 {
                        break;
                    }
                    if let Some(pkt) = dp.lock().await.inbound(&b[..n])? {
                        tun.send(&pkt).await?;
                    }
                }
                Ok::<(), anyhow::Error>(())
            })
        };

        tokio::select! {
            r = up => r??,
            r = down => r??,
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run(_config: &str, _route: &str) -> Result<()> {
    anyhow::bail!("the tunnel runs on Linux (TUN device required)")
}

/// Parse `ip/prefix` (prefix defaults to 24).
#[cfg(target_os = "linux")]
fn parse_cidr(s: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "24"));
    Ok((ip.trim().parse()?, prefix.trim().parse()?))
}
