//! The `shaip::client` facade against the real `shaipd` binary over loopback
//! UDP: confirmed sessions, packets both ways, concurrent send/recv, a wrong
//! server pin refused, and a device-bound server refusing a client with no
//! device certificate.

use shaip::client::{ClientConfig, Tunnel};
use shaip::handshake::{Identity, PeerPublic};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

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
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Start shaipd with a persistent identity and extra args; return its
/// listening address and the pins a client needs.
fn start(extra: &[&str]) -> Daemon {
    let dir = std::env::temp_dir().join(format!("shaipd-lb-{}-{}", std::process::id(), rand::random::<u32>()));
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
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Read until the daemon reports its port, then keep draining stderr so its
    // logging can never block on a full pipe.
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    // The log redacts every address (the daemon's own included) but not the
    // port.
    let addr = loop {
        let line = strip_ansi(&lines.next().expect("shaipd exited early").unwrap());
        if !line.contains("shaipd listening") {
            continue;
        }
        if let Some(rest) = line.split("port=").nth(1) {
            break format!("127.0.0.1:{}", rest.split_whitespace().next().unwrap()).parse().unwrap();
        }
    };
    std::thread::spawn(move || for _ in lines {});
    Daemon { child, addr, pins, dir }
}

fn config(d: &Daemon, pins: PeerPublic, timeout: Duration) -> ClientConfig {
    ClientConfig {
        server: d.addr.to_string(),
        server_pub: pins,
        identity: Identity::generate(),
        device_cert: None,
        handshake_timeout: timeout,
    }
}

#[tokio::test]
async fn confirmed_session_carries_packets_both_ways() {
    let d = start(&[]);
    let t = Tunnel::connect(config(&d, d.pins.clone(), Duration::from_secs(5)))
        .await
        .expect("connect");
    assert_eq!(t.server_identity(), d.pins.identity_id(), "connected to the pinned server");
    assert_eq!(t.info().assigned_v4, None, "echo mode assigns no tunnel address");

    for i in 0..5u8 {
        let pkt: Vec<u8> = (0..(40 + i as usize * 100)).map(|b| b as u8 ^ i).collect();
        t.send(&pkt).await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(2), t.recv()).await.unwrap().unwrap();
        assert_eq!(back, pkt, "packet {i} must come back byte-identical");
    }
    let s = t.stats();
    assert_eq!((s.packets_sent, s.packets_received, s.packets_dropped), (5, 5, 0));
    assert_eq!(s.bytes_sent, s.bytes_received);
}

#[tokio::test]
async fn send_and_recv_run_concurrently() {
    let d = start(&[]);
    let t = Arc::new(Tunnel::connect(config(&d, d.pins.clone(), Duration::from_secs(5))).await.unwrap());
    const N: usize = 200;
    let sender = {
        let t = t.clone();
        tokio::spawn(async move {
            for i in 0..N {
                t.send(&(i as u32).to_be_bytes()).await.unwrap();
                if i % 20 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        })
    };
    let mut seen = std::collections::HashSet::new();
    while seen.len() < N {
        let pkt = tokio::time::timeout(Duration::from_secs(5), t.recv()).await.expect("echo").unwrap();
        seen.insert(u32::from_be_bytes(pkt.try_into().unwrap()));
    }
    sender.await.unwrap();
    assert_eq!(seen.len(), N);
}

#[tokio::test]
async fn a_different_servers_pins_are_refused() {
    let d = start(&[]);
    // Valid keys, but another server's: the hello is sealed under that
    // server's boot key, so this server can't open it and stays silent. (Were
    // it answered, the SERVER_HELLO signatures would fail the pin check; see
    // handshake.rs.)
    let other = Identity::generate().public();
    let err = Tunnel::connect(config(&d, other, Duration::from_secs(3)))
        .await
        .err()
        .expect("must refuse")
        .to_string();
    assert!(err.contains("no SERVER_HELLO") && err.contains("not that server's"), "{err}");
}

#[tokio::test]
async fn device_bound_server_does_not_confirm_a_client_without_a_certificate() {
    let ca = Identity::generate().public().ed_bytes(); // any valid Ed25519 key
    let ca_hex: String = ca.iter().map(|b| format!("{b:02x}")).collect();
    let d = start(&["--device-ca", &ca_hex]);
    let err = Tunnel::connect(config(&d, d.pins.clone(), Duration::from_millis(1500)))
        .await
        .err()
        .expect("must not be admitted")
        .to_string();
    assert!(err.contains("did not confirm the session"), "{err}");
}
