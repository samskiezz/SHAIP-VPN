//! The reconnecting client (`pqanon::supervisor::ManagedTunnel`) against the
//! real `pqanond` binary: keepalive RTT, a graceful server restart (the server
//! sends Close), a crash, a hang that only unanswered keepalives reveal, and a
//! scheduled rekey — with packets flowing again after each.

use pqanon::client::ClientConfig;
use pqanon::handshake::{Identity, PeerPublic};
use pqanon::supervisor::{LinkState, ManagedTunnel, SupervisorConfig};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon {
    child: Child,
}

impl Daemon {
    /// Start pqanond (echo mode) with `identity` on `listen`; returns once it
    /// is listening, with the bound address.
    fn start(identity: &Path, listen: &str) -> (Daemon, SocketAddr) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_pqanond"))
            .args(["--identity", identity.to_str().unwrap(), "--listen", listen])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The log redacts every address (the daemon's own included) but not
        // the port, so the address is the one we asked for, with that port.
        let host = listen.rsplit_once(':').unwrap().0;
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let addr = loop {
            let line = strip_ansi(&lines.next().expect("pqanond exited early").unwrap());
            if !line.contains("pqanond listening") {
                continue;
            }
            if let Some(rest) = line.split("port=").nth(1) {
                break format!("{host}:{}", rest.split_whitespace().next().unwrap()).parse().unwrap();
            }
        };
        std::thread::spawn(move || for _ in lines {});
        (Daemon { child }, addr)
    }

    /// SIGTERM: the daemon tells its clients Close, then exits.
    fn stop_gracefully(mut self) {
        let _ = Command::new("kill").args(["-TERM", &self.child.id().to_string()]).status();
        let _ = self.child.wait();
    }

    /// SIGKILL: no Close. On loopback the kernel then answers the client's
    /// next packet with ICMP port-unreachable, which the client acts on.
    fn crash(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// SIGSTOP / SIGCONT: the socket stays bound but nothing answers and no
    /// ICMP comes back — a hung server or a path that silently drops packets.
    /// Only unanswered keepalives can reveal it.
    fn freeze(&self, frozen: bool) {
        let sig = if frozen { "-STOP" } else { "-CONT" };
        let _ = Command::new("kill").args([sig, &self.child.id().to_string()]).status();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

fn pins(identity: &Path) -> PeerPublic {
    let out = Command::new(env!("CARGO_BIN_EXE_pqanond"))
        .args(["--identity", identity.to_str().unwrap(), "--print-public"])
        .output()
        .unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let field = |k: &str| -> Vec<u8> {
        let v = text
            .lines()
            .find_map(|l| l.split_once('=').filter(|(a, _)| a.trim() == k).map(|(_, b)| b.trim().trim_matches('"').to_string()))
            .unwrap();
        (0..v.len()).step_by(2).map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap()).collect()
    };
    PeerPublic::from_bytes(&field("server_ml_dsa_pub"), &field("server_ed_pub")).unwrap()
}

/// Wait until `cond` holds for the link's status.
async fn wait_until(link: &ManagedTunnel, what: &str, limit: Duration, cond: impl Fn(&pqanon::supervisor::Status) -> bool) {
    let start = Instant::now();
    while !cond(&link.status()) {
        assert!(start.elapsed() < limit, "timed out waiting for: {what} (status {:?})", link.status());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One packet out, the same packet back (pqanond in echo mode).
async fn echo(link: &ManagedTunnel, tag: u8) {
    let pkt = vec![tag; 300];
    // A reconnect can race the first packet; retry a few times.
    for _ in 0..20 {
        link.send(&pkt).await;
        if let Ok(Ok(back)) = tokio::time::timeout(Duration::from_millis(500), link.recv()).await {
            if back == pkt {
                return;
            }
        }
    }
    panic!("no echo for packet {tag}");
}

async fn scenario(dir: PathBuf) {
    let id = dir.join("srv.id");
    let server_pub = pins(&id);
    let (d, addr) = Daemon::start(&id, "127.0.0.1:0");
    let listen = addr.to_string();

    let mut cfg = SupervisorConfig::new(ClientConfig {
        server: listen.clone(),
        server_pub,
        identity: Identity::generate(),
        device_cert: None,
        handshake_timeout: Duration::from_secs(2),
    });
    cfg.keepalive = Duration::from_millis(300);
    cfg.dead_after = Duration::from_millis(1500);
    cfg.backoff_base = Duration::from_millis(100);
    cfg.backoff_max = Duration::from_millis(400);
    cfg.rekey_after = Duration::from_secs(3600);
    let link = ManagedTunnel::start(cfg.clone()).await.expect("first connect");
    assert_eq!(link.status().state, LinkState::Connected);
    echo(&link, 1).await;
    wait_until(&link, "a keepalive RTT sample", Duration::from_secs(3), |s| s.rtt.is_some()).await;

    // 1. Graceful restart: the server's Close makes the client reconnect at
    //    once, without waiting for the dead-peer timer.
    d.stop_gracefully();
    wait_until(&link, "the Close to be noticed", Duration::from_millis(1000), |s| s.state == LinkState::Reconnecting).await;
    let (d, _) = Daemon::start(&id, &listen);
    wait_until(&link, "reconnect after a restart", Duration::from_secs(10), |s| s.state == LinkState::Connected).await;
    assert_eq!(link.status().reconnects, 1);
    echo(&link, 2).await;

    // 2. Crash: no Close, but the port goes away.
    d.crash();
    wait_until(&link, "the crash to be noticed", Duration::from_secs(5), |s| s.state == LinkState::Reconnecting).await;
    let (d, _) = Daemon::start(&id, &listen);
    wait_until(&link, "reconnect after a crash", Duration::from_secs(10), |s| s.state == LinkState::Connected).await;
    assert_eq!(link.status().reconnects, 2);
    echo(&link, 3).await;

    // 3. Hang: the server stops answering without a trace; the dead-peer
    //    timer (1.5 s here) must catch it, and the link must come back once
    //    the server answers again.
    d.freeze(true);
    let t = Instant::now();
    wait_until(&link, "the hung server to be noticed", Duration::from_secs(6), |s| s.state == LinkState::Reconnecting).await;
    let noticed = t.elapsed();
    assert!(noticed >= Duration::from_millis(1200), "noticed after {noticed:?}: must be the dead-peer timer");
    d.freeze(false);
    wait_until(&link, "reconnect after a hang", Duration::from_secs(10), |s| s.state == LinkState::Connected).await;
    assert_eq!(link.status().reconnects, 3);
    echo(&link, 4).await;
    link.stop().await;
    assert_eq!(link.status().state, LinkState::Stopped);
    drop(d);

    // 3. Rekey: a fresh handshake replaces the session while traffic flows.
    cfg.rekey_after = Duration::from_millis(1200);
    let (_d, _) = Daemon::start(&id, &listen);
    let link = ManagedTunnel::start(cfg).await.expect("connect");
    echo(&link, 5).await;
    wait_until(&link, "a rekey", Duration::from_secs(6), |s| s.rekeys >= 1).await;
    echo(&link, 6).await;
    let s = link.status();
    assert_eq!(s.state, LinkState::Connected);
    assert_eq!(s.reconnects, 0, "a rekey is not a reconnect");
    assert!(s.stats.packets_received >= 2, "counters span sessions: {:?}", s.stats);
    link.stop().await;
}

#[test]
fn the_link_survives_restarts_crashes_and_rekeys() {
    let dir = std::env::temp_dir().join(format!("pqanon-sup-{}-{}", std::process::id(), rand::random::<u32>()));
    std::fs::create_dir_all(&dir).unwrap();
    let d2 = dir.clone();
    // ML-DSA-65 handshakes want more stack than a default test thread has.
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(16 << 20)
                .enable_all()
                .build()
                .unwrap()
                .block_on(scenario(d2));
        })
        .unwrap()
        .join()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
