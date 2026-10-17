//! End-to-end proof of SHAIP-MP/1 redundant multipath: the tunnel runs through a
//! multipath proxy over two paths, one of which silently drops everything (a
//! stand-in for a dead/lossy link). Because each datagram is duplicated across
//! paths and the server's replay window drops the copy, the tunnel handshakes and
//! carries data with zero failover delay despite the dead path.

use shaip::client::{ClientConfig, Tunnel};
use shaip::handshake::{Identity, PeerPublic};
use shaip::multipath;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

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
    let dir = std::env::temp_dir().join(format!("shaipd-mp-{}-{}", std::process::id(), rand::random::<u32>()));
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
async fn tunnel_survives_a_dead_path_via_redundant_multipath() {
    let d = start_shaipd();

    // A "sink" path: a bound UDP socket nothing ever reads from, so datagrams
    // sent to it are silently absorbed (a dead/dropping link).
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sink_addr = sink.local_addr().unwrap();

    // The multipath proxy the SHAIP client dials, duplicating over both paths.
    // The dead path is listed FIRST, so without redundancy it would be chosen and
    // the handshake would stall; redundancy=2 sends on both and the live path wins.
    let local = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = local.local_addr().unwrap();
    {
        let local = local.clone();
        let upstreams = vec![sink_addr, d.addr];
        tokio::spawn(async move {
            let _ = multipath::mp_client(local, upstreams, 2).await;
        });
    }

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
        .expect("handshake over multipath did not time out")
        .expect("tunnel connects despite a dead path");
    assert_eq!(t.server_identity(), d.pins.identity_id());

    for i in 0..6u8 {
        let pkt: Vec<u8> = (0..(40 + i as usize * 120)).map(|b| (b as u8) ^ i).collect();
        t.send(&pkt).await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(3), t.recv())
            .await
            .expect("echo over multipath")
            .unwrap();
        assert_eq!(back, pkt, "packet {i} must round-trip despite the dead path");
    }
    // Keep the sink alive to the end so it keeps absorbing its copies.
    drop(sink);
}
