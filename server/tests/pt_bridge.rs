//! End-to-end proof that the SHAIP tunnel runs over the SHAIP-PT/1 pluggable
//! transport: a real `shaipd` behind a TLS bridge, with the client reaching it
//! through a local PT proxy. The path is
//!
//!   Tunnel --UDP--> pt_client proxy --TLS--> bridge --UDP--> shaipd (echo)
//!
//! and back. To the network between the proxy and the bridge this is an
//! ordinary TLS flow, not a UDP VPN, yet the tunnel handshakes and carries data
//! byte-identically.

use shaip::client::{ClientConfig, Tunnel};
use shaip::handshake::{Identity, PeerPublic};
use shaip::pt;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

struct Daemon {
    child: Child,
    addr: SocketAddr,
    pins: PeerPublic,
    dir: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            for c in it.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn field<'a>(out: &'a str, key: &str) -> &'a str {
    out.lines()
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().trim_matches('"'))
        })
        .unwrap_or_else(|| panic!("missing {key}"))
}

fn hexd(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn start_shaipd() -> Daemon {
    let dir = std::env::temp_dir().join(format!("shaipd-pt-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let id = dir.join("srv.id");
    let bin = env!("CARGO_BIN_EXE_shaipd");

    let out = Command::new(bin)
        .args(["--identity", id.to_str().unwrap(), "--print-public"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let printed = String::from_utf8(out.stdout).unwrap();
    let pins = PeerPublic::from_bytes(
        &hexd(field(&printed, "server_ml_dsa_pub")),
        &hexd(field(&printed, "server_ed_pub")),
    )
    .unwrap();

    let mut child = Command::new(bin)
        .args(["--identity", id.to_str().unwrap(), "--listen", "127.0.0.1:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let addr = loop {
        let line = strip_ansi(&lines.next().expect("shaipd exited early").unwrap());
        if !line.contains("shaipd listening") {
            continue;
        }
        if let Some(rest) = line.split("port=").nth(1) {
            break format!("127.0.0.1:{}", rest.split_whitespace().next().unwrap())
                .parse()
                .unwrap();
        }
    };
    std::thread::spawn(move || for _ in lines {});
    Daemon { child, addr, pins, dir }
}

#[tokio::test]
async fn tunnel_runs_over_the_tls_pluggable_transport() {
    let d = start_shaipd();

    // A self-signed bridge certificate for "bridge.local".
    let ck = rcgen::generate_simple_self_signed(vec!["bridge.local".to_string()]).unwrap();
    let cert_der = CertificateDer::from(ck.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(ck.key_pair.serialize_der()).unwrap();
    let server_cfg = pt::server_config(vec![cert_der.clone()], key_der).unwrap();
    let client_cfg = pt::client_config(vec![cert_der]).unwrap();

    // Bridge: accept TLS, relay each connection to the shaipd UDP address.
    let bridge_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge_addr = bridge_listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_cfg);
    let upstream = d.addr;
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match bridge_listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = pt::accept(&acceptor, tcp).await {
                    let _ = pt::bridge_connection(tls, upstream).await;
                }
            });
        }
    });

    // Client-side PT proxy: a local UDP socket the tunnel will dial, relayed over
    // TLS to the bridge.
    let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = local.local_addr().unwrap();
    {
        let local = local.clone();
        let client_cfg = client_cfg.clone();
        tokio::spawn(async move {
            let _ = pt::pt_client(local, bridge_addr, "bridge.local", client_cfg).await;
        });
    }

    // The SHAIP tunnel connects to the local proxy as if it were the server.
    let cfg = ClientConfig {
        server: proxy_addr.to_string(),
        server_pub: d.pins.clone(),
        identity: Identity::generate(),
        device_cert: None,
        handshake_timeout: Duration::from_secs(8),
        shaping: None,
    };
    let t = tokio::time::timeout(Duration::from_secs(10), Tunnel::connect(cfg))
        .await
        .expect("handshake over PT did not time out")
        .expect("tunnel connects over the TLS pluggable transport");
    assert_eq!(t.server_identity(), d.pins.identity_id(), "reached the pinned server through the bridge");

    // Data round-trips byte-identically through the TLS carrier.
    for i in 0..6u8 {
        let pkt: Vec<u8> = (0..(40 + i as usize * 120)).map(|b| (b as u8) ^ i).collect();
        t.send(&pkt).await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(3), t.recv())
            .await
            .expect("echo over PT")
            .unwrap();
        assert_eq!(back, pkt, "packet {i} must survive the PT carrier byte-identical");
    }
    let s = t.stats();
    assert_eq!((s.packets_sent, s.packets_received), (6, 6));
}
