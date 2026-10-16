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
    /// Start the VPN from a config file: every IPv4 packet and DNS lookup goes
    /// through the tunnel, IPv6 is blocked (the tunnel carries IPv4 only), and
    /// the session is kept alive, rekeyed, and re-established on failure
    /// (Linux; needs CAP_NET_ADMIN). Stop with Ctrl-C or `pqanon disconnect`.
    Run {
        #[arg(short, long)]
        config: String,
        /// Only route the tunnel subnet; leave all other traffic and DNS alone.
        #[arg(long)]
        split_tunnel: bool,
        /// Reject all traffic outside the tunnel, and keep doing so if this
        /// process dies, until it reconnects or `pqanon down` runs.
        #[arg(long)]
        kill_switch: bool,
        /// Keep the system resolver instead of the server's (lookups to a
        /// LAN resolver then go around the tunnel).
        #[arg(long)]
        keep_dns: bool,
        /// Do not block IPv6. The tunnel carries IPv4 only, so IPv6 traffic
        /// then bypasses it.
        #[arg(long)]
        allow_ipv6_leak: bool,
        /// Keepalive ping interval, seconds.
        #[arg(long, default_value_t = 10)]
        keepalive_secs: u64,
        /// Reconnect after this many seconds without an answer from the server.
        #[arg(long, default_value_t = 35)]
        dead_secs: u64,
        /// Replace the session with a fresh handshake this often, seconds.
        #[arg(long, default_value_t = 1200)]
        rekey_secs: u64,
        /// Routing mode. Only `fast` (straight to the server) exists today.
        #[arg(short, long, default_value = "fast")]
        route: String,
    },
    /// Show the state of a running `pqanon run`.
    Status,
    /// Stop a running `pqanon run` (it closes the session and restores
    /// routes, DNS and firewall).
    Disconnect,
    /// Undo what a `pqanon run` that crashed left behind: the kill switch,
    /// the resolv.conf rewrite, the host route.
    Down,
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
        /// Platform label for the account's device list: only iPhone, iPad,
        /// Android, Windows, Linux or Mac is sent (anything else is sent as
        /// "device"). Default: this machine's platform.
        #[arg(long)]
        name: Option<String>,
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
        Cmd::Run {
            config,
            split_tunnel,
            kill_switch,
            keep_dns,
            allow_ipv6_leak,
            keepalive_secs,
            dead_secs,
            rekey_secs,
            route,
        } => run(RunOpts {
            config,
            split_tunnel,
            kill_switch,
            keep_dns,
            allow_ipv6_leak,
            keepalive: std::time::Duration::from_secs(keepalive_secs.max(1)),
            dead_after: std::time::Duration::from_secs(dead_secs.max(3)),
            rekey_after: std::time::Duration::from_secs(rekey_secs.max(30)),
            route,
        }),
        Cmd::Status => status_cmd(),
        Cmd::Disconnect => disconnect_cmd(),
        Cmd::Down => down_cmd(),
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
        } => {
            let name = name.as_deref().unwrap_or(pqanon::enroll_client::this_platform());
            enroll_cmd(&link, &server, &authority_key, &ca_key, &identity, name, cert_out.as_deref())
        }
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
    println!("Enrolled device {}", hex::encode(done.cert.device_id));
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
    let wire = obf_tx.morph(&sealed)?;
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

/// `pqanon run` options.
struct RunOpts {
    config: String,
    split_tunnel: bool,
    kill_switch: bool,
    keep_dns: bool,
    allow_ipv6_leak: bool,
    keepalive: std::time::Duration,
    dead_after: std::time::Duration,
    rekey_after: std::time::Duration,
    route: String,
}

/// The VPN client: connect (and stay connected) through the supervisor, bring
/// up the TUN device with the server's parameters, route traffic and DNS into
/// it, pump packets both ways, and undo everything on exit.
#[cfg(target_os = "linux")]
fn run(o: RunOpts) -> Result<()> {
    use pqanon::netcfg::{FullTunnel, FullTunnelOpts};
    use pqanon::supervisor::{ManagedTunnel, SupervisorConfig};
    use pqanon::tun::{AsyncTun, TunDevice};
    use std::sync::{Arc, OnceLock};

    if o.route != "fast" {
        anyhow::bail!(
            "--route {}: only `fast` is available. The mix (anon) path is not wired into the data \
             plane yet, so nothing would be routed through mixes.",
            o.route
        );
    }
    let cfg = load_client_toml(&o.config, std::time::Duration::from_secs(10))?;
    // Reconnect and rekey handshakes run on worker threads; ML-DSA-65 signing
    // wants more than the default 2 MiB of stack.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 << 20)
        .build()?;
    rt.block_on(async move {
        // A run that crashed may have left DNS rewritten or a host route; a
        // kill switch it left stays closed until this run replaces it.
        for done in pqanon::netcfg::cleanup_after_crash(o.kill_switch)? {
            tracing::info!("recovered from a previous run: {done}");
        }
        let server_addr = tokio::net::lookup_host(&cfg.tunnel.server)
            .await
            .map_err(|e| anyhow::anyhow!("resolving {}: {e}", cfg.tunnel.server))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("{} did not resolve", cfg.tunnel.server))?;

        let net: Arc<OnceLock<FullTunnel>> = Arc::new(OnceLock::new());
        let mut sup = SupervisorConfig::new(pqanon::client::ClientConfig {
            server: server_addr.to_string(),
            ..cfg.tunnel
        });
        sup.keepalive = o.keepalive;
        sup.dead_after = o.dead_after;
        sup.rekey_after = o.rekey_after;
        let hook_net = net.clone();
        sup.before_connect = Some(Arc::new(move || {
            if let Some(ft) = hook_net.get() {
                ft.refresh_host_route();
            }
        }));
        let link = Arc::new(ManagedTunnel::start(sup).await.map_err(|e| {
            if o.kill_switch {
                e.context("first connection failed (if a kill switch from an earlier run is blocking it, run `pqanon down`)")
            } else {
                e
            }
        })?);
        let info = link.status().info;

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
        dev.set_mtu(info.effective_mtu())?;
        let tun = Arc::new(AsyncTun::new(dev)?);

        let full = !o.split_tunnel;
        let dns = if full && !o.keep_dns { info.dns_v4 } else { None };
        if full && !o.keep_dns && dns.is_none() {
            tracing::warn!("the server pushed no resolver: lookups use the system resolver, which may sit outside the tunnel");
        }
        let ft = FullTunnel::up(FullTunnelOpts {
            tun: tun.name().to_string(),
            server: server_addr,
            redirect_default: full,
            dns,
            block_ipv6: full && !o.allow_ipv6_leak,
            kill_switch: o.kill_switch,
        })?;
        let _ = net.set(ft);
        tracing::info!(
            device = %tun.name(), address = %format!("{tun_ip}/{tun_prefix}"), mtu = info.effective_mtu(),
            "{}", pqanon::i18n::t("tunnel_up")
        );
        println!(
            "connected: {tun_ip}/{tun_prefix} on {} via {server_addr}; {}; DNS {}; IPv6 {}; kill switch {}",
            tun.name(),
            if full { "all IPv4 traffic routed through the tunnel" } else { "split tunnel (tunnel subnet only)" },
            dns.map(|d| format!("{d} (through the tunnel)")).unwrap_or_else(|| "unchanged".into()),
            if full && !o.allow_ipv6_leak { "blocked" } else { "NOT blocked" },
            if o.kill_switch { "on" } else { "off" },
        );

        let up = tokio::spawn(pump_up(tun.clone(), link.clone()));
        let down = tokio::spawn(pump_down(tun.clone(), link.clone()));
        let watch = tokio::spawn(watch_link(link.clone(), tun.clone(), net.clone(), tun_prefix));
        let status = tokio::spawn(write_status(link.clone(), server_addr, tun.name().to_string()));
        let outcome = tokio::select! {
            r = up => r.map_err(anyhow::Error::from).and_then(|r| r),
            r = down => r.map_err(anyhow::Error::from).and_then(|r| r),
            _ = shutdown_signal() => Ok(()),
        };
        watch.abort();
        status.abort();
        link.stop().await; // tells the server: Close
        let _ = std::fs::remove_file(status_path());
        if let Some(ft) = Arc::try_unwrap(net).ok().and_then(|n| n.into_inner()) {
            ft.down(); // routes, DNS and firewall (kill switch included) restored
        }
        let st = link.status();
        println!(
            "disconnected: sent {} packets / {} B, received {} packets / {} B, {} reconnect(s), {} rekey(s)",
            st.stats.packets_sent, st.stats.bytes_sent, st.stats.packets_received, st.stats.bytes_received,
            st.reconnects, st.rekeys
        );
        outcome
    })
}

/// Log link transitions, and re-address the TUN device if the server ever
/// assigns a different address after a reconnect (e.g. it lost its leases).
#[cfg(target_os = "linux")]
async fn watch_link(
    link: std::sync::Arc<pqanon::supervisor::ManagedTunnel>,
    tun: std::sync::Arc<pqanon::tun::AsyncTun>,
    net: std::sync::Arc<std::sync::OnceLock<pqanon::netcfg::FullTunnel>>,
    prefix: u8,
) {
    use pqanon::supervisor::LinkState;
    let mut changes = link.changes();
    let mut state = LinkState::Connected;
    let mut addr = link.status().info.assigned_v4;
    while changes.changed().await.is_ok() {
        let st = link.status();
        if st.state != state {
            match st.state {
                LinkState::Connected => println!("tunnel up again (reconnect #{})", st.reconnects),
                LinkState::Reconnecting => println!(
                    "tunnel down: {}; reconnecting. Traffic stays inside the tunnel interface meanwhile (dropped, not sent around it)",
                    st.last_error.as_deref().unwrap_or("unknown")
                ),
                LinkState::Stopped => return,
            }
            state = st.state;
        }
        let reassigned = st.info.assigned_v4.filter(|a| st.state == LinkState::Connected && Some(*a) != addr);
        if let Some(new) = reassigned {
            match tun.device().configure_v4(new, prefix) {
                Ok(()) => {
                    println!("the server assigned a new tunnel address: {new}");
                    if let Some(ft) = net.get() {
                        ft.reassert_routes();
                    }
                    addr = Some(new);
                }
                Err(e) => tracing::error!(error = %e, "could not apply the new tunnel address"),
            }
        }
    }
}

fn status_path() -> std::path::PathBuf {
    std::env::var_os("PQANON_STATUS_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/pqanon.status"))
}

/// Keep a small status file current for `pqanon status` / `disconnect`.
#[cfg(target_os = "linux")]
async fn write_status(
    link: std::sync::Arc<pqanon::supervisor::ManagedTunnel>,
    server: std::net::SocketAddr,
    device: String,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
    loop {
        tick.tick().await;
        let st = link.status();
        let i = st.info;
        let since = st
            .up_since
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|| "-".into());
        let text = format!(
            "pid={}\nstate={:?}\nserver={server}\nserver_identity={}\ndevice={device}\ntunnel_address={}\ndns={}\nmtu={}\n\
             rtt_ms={}\nup_since_unix={since}\npackets_sent={}\nbytes_sent={}\npackets_received={}\nbytes_received={}\n\
             dropped_offline={}\nreconnects={}\nrekeys={}\nlast_error={}\n",
            std::process::id(),
            st.state,
            hex::encode(st.server_identity),
            i.assigned_v4.map(|a| format!("{a}/{}", i.prefix_len)).unwrap_or_else(|| "-".into()),
            i.dns_v4.map(|d| d.to_string()).unwrap_or_else(|| "-".into()),
            i.effective_mtu(),
            st.rtt.map(|r| format!("{:.1}", r.as_secs_f64() * 1e3)).unwrap_or_else(|| "-".into()),
            st.stats.packets_sent,
            st.stats.bytes_sent,
            st.stats.packets_received,
            st.stats.bytes_received,
            st.dropped_offline,
            st.reconnects,
            st.rekeys,
            st.last_error.as_deref().unwrap_or("-"),
        );
        let _ = pqanon::secure_write::write_private(&status_path(), text.as_bytes());
    }
}

fn status_cmd() -> Result<()> {
    match std::fs::read_to_string(status_path()) {
        Ok(text) => {
            print!("{text}");
            Ok(())
        }
        // The file is 0600: which server you use is nobody else's business on
        // a shared machine.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            anyhow::bail!("the tunnel status is readable by root only: run `sudo pqanon status`")
        }
        Err(_) => {
            println!("state=NotRunning");
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
fn disconnect_cmd() -> Result<()> {
    let text = std::fs::read_to_string(status_path()).map_err(|_| anyhow::anyhow!("no running `pqanon run` (no status file)"))?;
    let pid: i32 = text
        .lines()
        .find_map(|l| l.strip_prefix("pid="))
        .and_then(|p| p.trim().parse().ok())
        .ok_or_else(|| anyhow::anyhow!("status file has no pid"))?;
    // SAFETY: kill(2) with a pid read from our own status file and SIGTERM.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        anyhow::bail!("could not signal pid {pid}: {}", std::io::Error::last_os_error());
    }
    println!("asked pqanon (pid {pid}) to disconnect");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn disconnect_cmd() -> Result<()> {
    anyhow::bail!("disconnect is Linux only")
}

#[cfg(target_os = "linux")]
fn down_cmd() -> Result<()> {
    let done = pqanon::netcfg::cleanup_after_crash(false)?;
    if done.is_empty() {
        println!("nothing to undo");
    }
    for d in done {
        println!("{d}");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn down_cmd() -> Result<()> {
    anyhow::bail!("down is Linux only")
}

#[cfg(target_os = "linux")]
async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// TUN → tunnel.
#[cfg(target_os = "linux")]
async fn pump_up(
    tun: std::sync::Arc<pqanon::tun::AsyncTun>,
    link: std::sync::Arc<pqanon::supervisor::ManagedTunnel>,
) -> Result<()> {
    let mut b = vec![0u8; 65536];
    loop {
        let n = tun.recv(&mut b).await?;
        if n > 0 {
            link.send(&b[..n]).await;
        }
    }
}

/// Tunnel → TUN.
#[cfg(target_os = "linux")]
async fn pump_down(
    tun: std::sync::Arc<pqanon::tun::AsyncTun>,
    link: std::sync::Arc<pqanon::supervisor::ManagedTunnel>,
) -> Result<()> {
    loop {
        let pkt = link.recv().await?;
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
fn run(_o: RunOpts) -> Result<()> {
    anyhow::bail!("the tunnel runs on Linux (TUN device required)")
}

/// Parse `ip/prefix` (prefix defaults to 24).
#[cfg(target_os = "linux")]
fn parse_cidr(s: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "24"));
    Ok((ip.trim().parse()?, prefix.trim().parse()?))
}
