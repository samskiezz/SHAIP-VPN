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
    Keygen {
        /// Store the identity here (mode 0600) so it persists; if the file
        /// already exists, its public keys are printed and it is left unchanged.
        #[arg(long)]
        out: Option<String>,
    },
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
    /// List the plans (denominations) the mint sells.
    Plans {
        #[arg(short, long)]
        server: String,
    },
    /// Buy access anonymously: blind tokens and open an order to pay with crypto.
    Buy {
        #[arg(short, long)]
        server: String,
        #[arg(short, long)]
        plan: String,
        /// How many tokens to buy (each redeems for one access grant).
        #[arg(short, long, default_value_t = 1)]
        count: usize,
        /// Payment rail: monero, btcpay, or dev (default: the server's default).
        #[arg(long)]
        rail: Option<String>,
        #[arg(long)]
        store: Option<String>,
    },
    /// After paying, collect and unblind the tokens for an order.
    Collect {
        #[arg(short, long)]
        server: String,
        #[arg(short, long)]
        order: String,
        #[arg(long)]
        store: Option<String>,
    },
    /// Show the tokens and pending orders in the local wallet.
    Tokens {
        #[arg(long)]
        store: Option<String>,
    },
    /// Redeem a token for a VPN access grant (unlinkable to your payment).
    Redeem {
        #[arg(short, long)]
        server: String,
        #[arg(short, long)]
        plan: String,
        #[arg(long)]
        store: Option<String>,
    },
    /// Enroll this device from a pqanon://enroll link: verify it against the
    /// pinned enrollment-authority key, prove possession of this device's
    /// identity key, and store the device certificate the control plane issues.
    Enroll {
        /// The pqanon://enroll?t=… link (or the bare PQE1 token).
        link: String,
        /// Control-plane base URL.
        #[arg(short, long)]
        server: String,
        /// Pinned enrollment-authority public key (hex), shipped with the client.
        #[arg(long)]
        authority_key: String,
        /// Pinned device-CA public key (hex), shipped with the client.
        #[arg(long)]
        ca_key: String,
        /// This device's identity file (created 0600 if absent).
        #[arg(long)]
        identity: String,
        /// Label for this device in the account's device list.
        #[arg(long, default_value = "device")]
        name: String,
        /// Where to store the certificate (default: <identity>.cert).
        #[arg(long)]
        cert_out: Option<String>,
    },
    /// Connect with a client config and send ICMP echo requests through the
    /// tunnel (no TUN device needed): proves the server admits this client and
    /// that packets flow both ways.
    Probe {
        #[arg(short, long)]
        config: String,
        #[arg(long, default_value_t = 3)]
        count: u16,
        /// Per-step timeout (handshake confirmation, and each echo).
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
    /// Fetch the signed directory consensus, verify it against pinned authority
    /// keys, and list the nodes it admits (only bonded, unjailed nodes).
    Directory {
        /// The directory URL (…/api/directory).
        #[arg(long)]
        url: String,
        /// A pinned authority as NAME=HEXKEY (repeatable).
        #[arg(long = "authority", required = true)]
        authorities: Vec<String>,
    },
    /// Fetch the control plane's signed CRL, verify it against a pinned key,
    /// and list what it revokes.
    Crl {
        /// The CRL URL (…/api/crl).
        #[arg(long)]
        url: String,
        /// Pinned CRL public key (hex).
        #[arg(long)]
        pubkey: String,
        /// Reject a list older than this many seconds.
        #[arg(long, default_value_t = 600)]
        max_age: i64,
    },
}

fn wallet_path(store: Option<String>) -> std::path::PathBuf {
    store
        .map(std::path::PathBuf::from)
        .unwrap_or_else(pqanon::pay_client::default_wallet_path)
}

fn main() {
    // Print a clean one-line error (no Rust backtrace) for ordinary user
    // mistakes like an empty wallet or an unreachable server.
    if let Err(e) = cli_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn cli_main() -> Result<()> {
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
        Cmd::Keygen { out } => keygen(out.as_deref()),
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
        Cmd::Plans { server } => pqanon::pay_client::plans(&server),
        Cmd::Buy {
            server,
            plan,
            count,
            rail,
            store,
        } => pqanon::pay_client::buy(&server, &plan, count, rail.as_deref(), &wallet_path(store)),
        Cmd::Collect {
            server,
            order,
            store,
        } => pqanon::pay_client::collect(&server, &order, &wallet_path(store)),
        Cmd::Tokens { store } => pqanon::pay_client::list_tokens(&wallet_path(store)),
        Cmd::Redeem {
            server,
            plan,
            store,
        } => pqanon::pay_client::redeem(&server, &plan, &wallet_path(store)),
        Cmd::Enroll {
            link,
            server,
            authority_key,
            ca_key,
            identity,
            name,
            cert_out,
        } => enroll_cmd(&link, &server, &authority_key, &ca_key, &identity, &name, cert_out.as_deref()),
        Cmd::Crl { url, pubkey, max_age } => crl_cmd(&url, &pubkey, max_age),
        Cmd::Directory { url, authorities } => directory_cmd(&url, &authorities),
        Cmd::Probe {
            config,
            count,
            timeout_ms,
        } => probe(&config, count, timeout_ms),
    }
}

fn enroll_cmd(
    link: &str,
    server: &str,
    authority_key: &str,
    ca_key: &str,
    identity: &str,
    name: &str,
    cert_out: Option<&str>,
) -> Result<()> {
    use pqanon::enroll_client::{enroll, parse_pin};
    let authority = parse_pin(authority_key, "--authority-key")?;
    let ca = parse_pin(ca_key, "--ca-key")?;
    let done = enroll(
        link,
        server,
        &authority,
        &ca,
        std::path::Path::new(identity),
        name,
        cert_out.map(std::path::Path::new),
    )?;
    println!(
        "Enrolled device {} for account {}",
        hex::encode(done.cert.device_id),
        done.cert.account
    );
    println!("certificate: {} (valid until unix {})", done.cert_path.display(), done.cert.expires_at);
    Ok(())
}

fn directory_cmd(url: &str, authorities: &[String]) -> Result<()> {
    use std::io::Read;
    let mut registry = std::collections::BTreeMap::new();
    for a in authorities {
        let (name, key) = a
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--authority must be NAME=HEXKEY, got {a:?}"))?;
        registry.insert(name.to_string(), pqanon::enroll_client::parse_pin(key, "--authority key")?);
    }
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|e| anyhow::anyhow!("GET {url}: {e}"))?;
    let mut body = Vec::new();
    resp.into_reader().take(8 << 20).read_to_end(&mut body)?;
    let consensus = pqanon::directory::parse(&body).map_err(|e| anyhow::anyhow!("{e}"))?;
    let now = pqanon::crl::format_rfc3339_utc(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64,
    );
    let valid = pqanon::directory::verify(&consensus, &registry, &now)
        .map_err(|e| anyhow::anyhow!("directory rejected: {e}"))?;
    println!(
        "directory verified: {} node(s), {valid}/{} authority signature(s), valid until {}",
        consensus.nodes.len(),
        consensus.threshold,
        consensus.valid_until
    );
    for n in &consensus.nodes {
        println!(
            "node {} addr {} role {} region {} capacity {} Mbit/s ed25519 {}",
            n.name, n.address, n.role, n.region, n.capacity_mbps, n.ed25519_hex
        );
    }
    Ok(())
}

fn crl_cmd(url: &str, pubkey: &str, max_age: i64) -> Result<()> {
    let pinned = pqanon::enroll_client::parse_pin(pubkey, "--pubkey")?;
    let crl = pqanon::crl::fetch(url, &pinned, max_age)?;
    println!("CRL verified (issued at unix {})", crl.issued_at);
    let mut devices: Vec<String> = crl.revoked_devices.iter().map(hex::encode).collect();
    devices.sort();
    for d in &devices {
        println!("revoked device {d}");
    }
    let mut ids: Vec<&String> = crl.revoked_identities.iter().collect();
    ids.sort();
    for i in ids {
        println!("revoked identity {i}");
    }
    println!("{} revoked device(s), {} revoked identit(ies)", devices.len(), crl.revoked_identities.len());
    Ok(())
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

fn keygen(out: Option<&str>) -> Result<()> {
    let id = match out {
        Some(path) => {
            let (id, created) = pqanon::keystore::load_or_create_identity(std::path::Path::new(path))?;
            if !created {
                eprintln!("{path} already exists; showing its public keys (unchanged)");
            }
            id
        }
        None => Identity::generate(),
    };
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

/// The client-config fields (`examples/client.toml`) that `run` and `probe`
/// share.
struct ClientToml {
    tunnel: pqanon::client::ClientConfig,
    tun_device: String,
    tun_address: Option<String>,
}

fn load_client_toml(path: &str, timeout: std::time::Duration) -> Result<ClientToml> {
    use pqanon::handshake::PeerPublic;

    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
    let cfg: toml::Value = toml::from_str(&raw)?;
    let gstr = |sect: &str, key: &str| -> Option<String> {
        cfg.get(sect)
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };

    let server =
        gstr("server", "address").ok_or_else(|| anyhow::anyhow!("config missing [server].address"))?;
    let server_pq_hex = gstr("server", "server_ml_dsa_pub")
        .ok_or_else(|| anyhow::anyhow!("config missing [server].server_ml_dsa_pub"))?;
    let server_ed_hex = gstr("server", "server_ed_pub")
        .ok_or_else(|| anyhow::anyhow!("config missing [server].server_ed_pub"))?;
    if server_pq_hex.starts_with("hex") || server_ed_hex.starts_with("hex") {
        anyhow::bail!(
            "fill [server].server_ml_dsa_pub / server_ed_pub with the server's real public keys \
             (run `pqanond --identity <file> --print-public` on the server)"
        );
    }
    let server_pub = PeerPublic::from_bytes(
        &hex::decode(server_pq_hex.trim())?,
        &hex::decode(server_ed_hex.trim())?,
    )?;

    // A persistent identity lets a server allow-list this client; without one a
    // fresh identity is generated per run (fine only for open demo servers).
    let identity = match gstr("client", "identity") {
        Some(p) => pqanon::keystore::load_or_create_identity(std::path::Path::new(&p))?.0,
        None => {
            tracing::warn!("no [client].identity: using a throwaway identity for this run");
            Identity::generate()
        }
    };
    // Device certificate from `pqanon enroll`, for device-bound servers.
    let device_cert = match gstr("client", "device_cert") {
        Some(p) => Some(
            std::fs::read_to_string(&p)
                .map_err(|e| anyhow::anyhow!("reading [client].device_cert {p}: {e}"))?
                .trim()
                .to_string(),
        ),
        None => None,
    };

    Ok(ClientToml {
        tunnel: pqanon::client::ClientConfig {
            server,
            server_pub,
            identity,
            device_cert,
            handshake_timeout: timeout,
        },
        tun_device: gstr("client", "tun_device").unwrap_or_else(|| "pqanon-c0".into()),
        tun_address: gstr("client", "tun_address"),
    })
}

/// Start the tunnel: connect through the shared `pqanon::client` facade, then
/// pump packets between a TUN device and the tunnel.
#[cfg(target_os = "linux")]
fn run(config: &str, route: &str) -> Result<()> {
    use pqanon::client::Tunnel;
    use pqanon::tun::{AsyncTun, TunDevice};
    use std::sync::Arc;

    let cfg = load_client_toml(config, std::time::Duration::from_secs(10))?;
    tracing::info!(server = %cfg.tunnel.server, route, "pqanon run");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let tunnel = Arc::new(Tunnel::connect(cfg.tunnel).await?);
        let info = tunnel.info();
        tracing::info!(
            conn_id = format!("{:#018x}", tunnel.conn_id()),
            "handshake OK; the server confirmed the session"
        );

        // The server routes return traffic by the address it assigned, so use
        // that one; fall back to the configured address for servers that
        // assign none (echo mode).
        let (tun_ip, tun_prefix) = match info.assigned_v4 {
            Some(ip) => {
                if let Some(configured) = cfg.tun_address.as_deref() {
                    if parse_cidr(configured).ok().map(|(a, _)| a) != Some(ip) {
                        tracing::warn!(%configured, assigned = %ip, "using the server-assigned tunnel address");
                    }
                }
                (ip, if info.prefix_len == 0 { 24 } else { info.prefix_len })
            }
            None => parse_cidr(cfg.tun_address.as_deref().unwrap_or("10.77.0.2/24"))?,
        };
        let dev = TunDevice::open(&cfg.tun_device)?;
        dev.configure_v4(tun_ip, tun_prefix)?;
        let tun = Arc::new(AsyncTun::new(dev)?);
        tracing::info!(device = %tun.name(), %tun_ip, "{}", pqanon::i18n::t("tunnel_up"));

        let up = tokio::spawn(pump_up(tun.clone(), tunnel.clone()));
        let down = tokio::spawn(pump_down(tun, tunnel));
        tokio::select! {
            r = up => r??,
            r = down => r??,
        }
        Ok::<_, anyhow::Error>(())
    })?;
    Ok(())
}

/// TUN → tunnel.
#[cfg(target_os = "linux")]
async fn pump_up(
    tun: std::sync::Arc<pqanon::tun::AsyncTun>,
    tunnel: std::sync::Arc<pqanon::client::Tunnel>,
) -> Result<()> {
    let mut b = vec![0u8; 65536];
    loop {
        let n = tun.recv(&mut b).await?;
        if n == 0 {
            return Ok(());
        }
        tunnel.send(&b[..n]).await?;
    }
}

/// Tunnel → TUN.
#[cfg(target_os = "linux")]
async fn pump_down(
    tun: std::sync::Arc<pqanon::tun::AsyncTun>,
    tunnel: std::sync::Arc<pqanon::client::Tunnel>,
) -> Result<()> {
    loop {
        let pkt = tunnel.recv().await?;
        tun.send(&pkt).await?;
    }
}

/// Connect and send ICMP echo requests through the tunnel to the server's
/// tunnel address. A TUN-mode server's kernel answers with a real echo reply;
/// an echo-mode server returns the request verbatim. No TUN device is needed.
fn probe(config: &str, count: u16, timeout_ms: u64) -> Result<()> {
    use pqanon::client::Tunnel;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    let wait = Duration::from_millis(timeout_ms);
    let cfg = load_client_toml(config, wait)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let tunnel = Tunnel::connect(cfg.tunnel).await?;
        let info = tunnel.info();
        println!(
            "connected: conn_id {:#018x}, server {}, assigned {}",
            tunnel.conn_id(),
            hex::encode(tunnel.server_identity()),
            info.assigned_v4
                .map(|a| a.to_string())
                .unwrap_or_else(|| "none (echo-mode server)".into())
        );
        let src = info.assigned_v4.unwrap_or(Ipv4Addr::new(10, 77, 0, 2));
        let dst = info.gateway_v4.unwrap_or(Ipv4Addr::new(10, 77, 0, 1));
        let id: u16 = rand::random();
        let mut answered = 0u16;
        for seq in 1..=count {
            let req = pqanon::icmp::echo_request(src, dst, id, seq, b"pqanon probe");
            let started = Instant::now();
            tunnel.send(&req).await?;
            let answer = tokio::time::timeout(wait, async {
                loop {
                    let pkt = tunnel.recv().await?;
                    if pkt == req {
                        return Ok::<_, anyhow::Error>("echoed by the server");
                    }
                    if pqanon::icmp::parse_echo_reply(&pkt) == Some((dst, id, seq)) {
                        return Ok("ICMP echo reply from the server's kernel");
                    }
                }
            })
            .await;
            match answer {
                Ok(Ok(how)) => {
                    answered += 1;
                    println!("seq={seq}: {how} in {:.1} ms", started.elapsed().as_secs_f64() * 1e3);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => println!("seq={seq}: no answer within {timeout_ms} ms"),
            }
        }
        let s = tunnel.stats();
        println!(
            "stats: sent {} packets / {} B, received {} packets / {} B, dropped {}",
            s.packets_sent, s.bytes_sent, s.packets_received, s.bytes_received, s.packets_dropped
        );
        anyhow::ensure!(answered == count, "probe FAILED: {answered}/{count} answered");
        println!("probe OK: {answered}/{count} answered through the tunnel");
        Ok(())
    })
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
