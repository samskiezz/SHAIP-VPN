//! `pqanon::client` — the connection facade every front end shares: the CLI's
//! TUN loop (`pqanon run`), `pqanon probe`, and native apps through the C ABI
//! in `pqanon-ffi`.
//!
//! [`Tunnel::connect`] runs the PQANON-HS/1 handshake over UDP and returns only
//! once the server has **confirmed** the session with a sealed ACK. That ACK
//! proves the server derived the same keys *and admitted this client*. A
//! device-bound server silently drops an unenrolled or revoked device, which
//! therefore fails here with a clear error instead of getting a tunnel that goes
//! nowhere. The ACK also carries the tunnel address the server assigned, the
//! DNS resolver to use inside the tunnel, and the interface MTU.
//!
//! Handshake messages are retransmitted with backoff until answered (the
//! server answers a repeated message from its cache, so a retransmit never
//! forks the handshake). Once up, a [`Tunnel`] answers keepalive pings and
//! measures round-trip time from its own (see [`crate::ctl`]); keeping a tunnel
//! alive across failures and rekeys is [`crate::supervisor`]'s job.
//!
//! A tunnel moves whole IP packets ([`Tunnel::send`] / [`Tunnel::recv`]). How
//! packets reach the OS — a Linux TUN device, an iOS `NEPacketTunnelFlow`, an
//! Android `VpnService` descriptor — is the front end's job, which is exactly
//! the seam a native shell plugs into.

use crate::ctl::{self, Keepalive};
use crate::dataplane::DataPlane;
use crate::handshake::{ClientHandshake, Identity, PeerPublic};
use crate::obf::{BootKey, Obfuscator, Reassembly, AMPLIFICATION_LIMIT, BOOT_DATAGRAM};
use crate::transport::{Session, REKEY_AFTER_SEQ};
use crate::wire::{Envelope, MsgType};
use anyhow::{anyhow, bail, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Congestion-control MTU hint for sealed payloads.
pub const MTU: usize = 1400;

/// The largest inner IP packet whose sealed and morphed datagram still crosses
/// a 1500-byte path unfragmented. The morph pads a sealed datagram up to the
/// next size in [`crate::obf::PADDING_TABLE`] plus at most
/// [`crate::obf::SIZE_JITTER`] (15) bytes, so the biggest bucket that fits is
/// 1408 (1408 + 15 = 1423 bytes of UDP payload, under both IPv4's 1472 and
/// IPv6's 1452), less the 38-byte envelope overhead.
pub const TUNNEL_MTU: u16 = 1370;

const RECV_BUF: usize = 65_536;
/// First handshake retransmission; doubles up to [`HS_RETRANSMIT_MAX`].
const HS_RETRANSMIT_FIRST: Duration = Duration::from_millis(1000);
const HS_RETRANSMIT_MAX: Duration = Duration::from_millis(4000);
/// CLIENT_HELLO is padded to this many handshake datagrams, so the server's
/// reply (SERVER_HELLO carries an ML-DSA-65 signature and fills five) stays
/// within [`AMPLIFICATION_LIMIT`] times what the client sent.
pub const CLIENT_HELLO_DATAGRAMS: usize = 2;
const _: () = assert!(AMPLIFICATION_LIMIT * CLIENT_HELLO_DATAGRAMS * BOOT_DATAGRAM >= 5 * BOOT_DATAGRAM);

/// What [`Tunnel::connect`] needs.
#[derive(Clone)]
pub struct ClientConfig {
    /// `host:port` of the pqanond UDP listener.
    pub server: String,
    /// The server's pinned public identity (`pqanond --print-public`).
    pub server_pub: PeerPublic,
    /// This client's long-term identity.
    pub identity: Identity,
    /// Device certificate for device-bound servers (from `pqanon enroll`).
    pub device_cert: Option<String>,
    /// How long to wait for the handshake and the server's confirmation.
    pub handshake_timeout: Duration,
}

/// What the server tells the client when it confirms the session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionInfo {
    /// The tunnel address the server assigned this client (TUN mode).
    pub assigned_v4: Option<Ipv4Addr>,
    /// Prefix length of the tunnel subnet.
    pub prefix_len: u8,
    /// The server's own tunnel address, i.e. the client's gateway (TUN mode).
    pub gateway_v4: Option<Ipv4Addr>,
    /// The resolver to use while connected; it is reached through the tunnel.
    pub dns_v4: Option<Ipv4Addr>,
    /// MTU for the client's tunnel interface (0: not stated, use [`TUNNEL_MTU`]).
    pub mtu: u16,
    /// The server answers keepalive pings (every v2 server does), so a silent
    /// session can be declared dead and replaced.
    pub keepalive: bool,
}

const ACK_MAGIC_V1: &[u8] = b"PQANON-ACK-V1";
const ACK_MAGIC_V2: &[u8] = b"PQANON-ACK-V2";
const ACK_FLAG_KEEPALIVE: u8 = 0x01;

impl SessionInfo {
    /// v2: `magic || assigned v4 || prefix len || gateway v4 || dns v4 || mtu
    /// (u16 BE) || flags`; 0.0.0.0 means none.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = ACK_MAGIC_V2.to_vec();
        let ip = |a: Option<Ipv4Addr>| a.unwrap_or(Ipv4Addr::UNSPECIFIED).octets();
        b.extend_from_slice(&ip(self.assigned_v4));
        b.push(self.prefix_len);
        b.extend_from_slice(&ip(self.gateway_v4));
        b.extend_from_slice(&ip(self.dns_v4));
        b.extend_from_slice(&self.mtu.to_be_bytes());
        b.push(if self.keepalive { ACK_FLAG_KEEPALIVE } else { 0 });
        b
    }

    /// Decode a v2 ACK, or a v1 ACK from an older server (no DNS, no MTU, no
    /// keepalive answers).
    pub fn decode(b: &[u8]) -> Result<Self> {
        let addr = |o: &[u8]| {
            let a = Ipv4Addr::new(o[0], o[1], o[2], o[3]);
            (!a.is_unspecified()).then_some(a)
        };
        if let Some(rest) = b.strip_prefix(ACK_MAGIC_V2) {
            if rest.len() != 16 {
                bail!("session ACK has the wrong length");
            }
            return Ok(SessionInfo {
                assigned_v4: addr(&rest[0..4]),
                prefix_len: rest[4],
                gateway_v4: addr(&rest[5..9]),
                dns_v4: addr(&rest[9..13]),
                mtu: u16::from_be_bytes([rest[13], rest[14]]),
                keepalive: rest[15] & ACK_FLAG_KEEPALIVE != 0,
            });
        }
        let rest = b
            .strip_prefix(ACK_MAGIC_V1)
            .ok_or_else(|| anyhow!("session ACK has the wrong magic"))?;
        if rest.len() != 9 {
            bail!("session ACK has the wrong length");
        }
        Ok(SessionInfo {
            assigned_v4: addr(&rest[0..4]),
            prefix_len: rest[4],
            gateway_v4: addr(&rest[5..9]),
            ..SessionInfo::default()
        })
    }

    /// The MTU to configure on the tunnel interface.
    pub fn effective_mtu(&self) -> u16 {
        if self.mtu == 0 {
            TUNNEL_MTU
        } else {
            self.mtu.min(TUNNEL_MTU)
        }
    }
}

/// Traffic counters for a tunnel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TunnelStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    /// Datagrams that did not open (replays, tampering, or not this session).
    pub packets_dropped: u64,
}

impl std::ops::Add for TunnelStats {
    type Output = TunnelStats;
    fn add(self, o: TunnelStats) -> TunnelStats {
        TunnelStats {
            packets_sent: self.packets_sent + o.packets_sent,
            bytes_sent: self.bytes_sent + o.bytes_sent,
            packets_received: self.packets_received + o.packets_received,
            bytes_received: self.bytes_received + o.bytes_received,
            packets_dropped: self.packets_dropped + o.packets_dropped,
        }
    }
}

#[derive(Default)]
struct Counters {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    packets_dropped: AtomicU64,
}

/// The server ended the session (it sent `Close`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionClosed;

impl std::fmt::Display for SessionClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the server closed the session")
    }
}

impl std::error::Error for SessionClosed {}

/// An established, server-confirmed PQANON session over UDP.
///
/// `send` and `recv` take `&self`, so one task (or thread) can send while
/// another receives — the shape of every TUN or packet-flow loop.
pub struct Tunnel {
    sock: UdpSocket,
    dp: std::sync::Mutex<DataPlane>,
    recv_buf: tokio::sync::Mutex<Vec<u8>>,
    conn_id: u64,
    server_id: [u8; 16],
    server_addr: SocketAddr,
    info: SessionInfo,
    counters: Counters,
    created: Instant,
    /// Milliseconds after `created` of the last authenticated inbound packet.
    last_rx_ms: AtomicU64,
    /// Highest sequence number the server has used (it rekeys on our side).
    rx_seq_max: AtomicU32,
    /// The outstanding keepalive ping: nonce and when it was sent.
    ping: std::sync::Mutex<Option<(u64, Instant)>>,
    /// Smoothed keepalive RTT in microseconds; 0 until the first PONG.
    srtt_us: AtomicU64,
}

/// What a server sends back to a CLIENT_HELLO over the boot layer.
enum HelloReply {
    ServerHello(Envelope),
    /// A retry cookie: the server's table is full and wants address validation.
    Retry(Vec<u8>),
}

impl Tunnel {
    /// Handshake with the server and wait for it to confirm the session.
    pub async fn connect(cfg: ClientConfig) -> Result<Tunnel> {
        let server = tokio::net::lookup_host(&cfg.server)
            .await
            .with_context(|| format!("resolving {}", cfg.server))?
            .next()
            .ok_or_else(|| anyhow!("{} did not resolve", cfg.server))?;
        let bind: SocketAddr = if server.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(server).await?;
        let deadline = Instant::now() + cfg.handshake_timeout;
        let mut buf = vec![0u8; RECV_BUF];

        // PQANON-HS/1 over the OBF/2 boot layer: each message is split into
        // small datagrams sealed under a key from the server's pinned public
        // keys. The server is authenticated against those keys while
        // processing SERVER_HELLO.
        //
        // A server whose half-open table is full answers an unvalidated hello
        // with a RETRY carrying a cookie (crate::retry); we repeat the hello
        // with the cookie echoed, which proves we receive at this address. At
        // most one retry, so a server that only ever asks to retry can't loop
        // us. A fresh ClientHandshake is built for the cookied attempt (the
        // first one's ephemeral keys and transcript are discarded).
        let boot = BootKey::for_server(&cfg.server_pub);
        let mut cookie = [0u8; 32];
        let (mut hs, shello) = loop {
            let mut hs = ClientHandshake::new(cfg.identity.clone(), cfg.server_pub.clone(), rand::random());
            if let Some(cert) = &cfg.device_cert {
                hs.set_device_cert(cert.clone());
            }
            let hello = boot.seal_message(&hs.client_hello(cookie)?.to_plain(), CLIENT_HELLO_DATAGRAMS)?;
            let mut reassembly = Reassembly::new();
            let reply = exchange(&sock, &hello, &mut buf, deadline, |b| {
                let msg = reassembly.push(boot.open(b)?)?;
                let env = Envelope::from_plain(&msg).ok()?;
                match env.msg_type {
                    MsgType::ServerHello => Some(HelloReply::ServerHello(env)),
                    MsgType::Retry if env.payload.len() == 32 => Some(HelloReply::Retry(env.payload)),
                    _ => None,
                }
            })
            .await
            .map_err(|_| {
                anyhow!(
                    "no SERVER_HELLO from {server} within {:?}: the server is unreachable, or the server \
                     keys in this config are not that server's (a server stays silent to a handshake \
                     sealed for another server's keys)",
                    cfg.handshake_timeout
                )
            })?;
            match reply {
                HelloReply::ServerHello(env) => break (hs, env),
                HelloReply::Retry(c) if crate::retry::is_empty(&cookie) => {
                    cookie.copy_from_slice(&c); // retry once, with the cookie
                }
                HelloReply::Retry(_) => bail!("the server kept asking to retry the handshake"),
            }
        };
        hs.recv_server_hello(&shello)?;
        let (finish, est) = hs.client_finish()?;

        // Wait for the sealed ACK. A datagram that does not open is not from
        // this session (a stray reply or a probe answer) and is ignored.
        let mut dp = DataPlane::new(
            Session::new(est.conn_id, est.k_c2s, est.k_s2c, server, true, MTU),
            Obfuscator::new(&est.ss_mix, 1),
        );
        let finish = boot.seal_message(&finish.to_plain(), 1)?;
        let info = exchange(&sock, &finish, &mut buf, deadline, |b| {
            let env = dp.open(b).ok().filter(|e| e.msg_type == MsgType::Ack)?;
            Some(SessionInfo::decode(&env.payload))
        })
        .await
        .map_err(|_| {
            anyhow!(
                "the server did not confirm the session within {:?}: this client is not \
                 admitted (e.g. an unenrolled or revoked device) or the server is unreachable",
                cfg.handshake_timeout
            )
        })??;

        Ok(Tunnel {
            sock,
            dp: std::sync::Mutex::new(dp),
            recv_buf: tokio::sync::Mutex::new(buf),
            conn_id: est.conn_id,
            server_id: est.peer_id,
            server_addr: server,
            info,
            counters: Counters::default(),
            created: Instant::now(),
            last_rx_ms: AtomicU64::new(0),
            rx_seq_max: AtomicU32::new(0),
            ping: std::sync::Mutex::new(None),
            srtt_us: AtomicU64::new(0),
        })
    }

    /// Seal, morph, and send one IP packet.
    pub async fn send(&self, ip_packet: &[u8]) -> Result<()> {
        let wire = self.dp.lock().expect("dataplane lock").outbound(ip_packet)?;
        self.sock.send(&wire).await?;
        self.counters.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.counters.bytes_sent.fetch_add(ip_packet.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Receive the next IP packet. Keepalive and cover traffic are handled here
    /// and skipped; a datagram that does not open (replay, tampering, not this
    /// session) is dropped and counted. Fails with [`SessionClosed`] when the
    /// server ends the session.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut buf = self.recv_buf.lock().await;
        loop {
            let n = self.sock.recv(&mut buf).await?;
            // Bind the result first so the dataplane lock is released before
            // anything else happens.
            let opened = self.dp.lock().expect("dataplane lock").open(&buf[..n]);
            let env = match opened {
                Ok(env) => env,
                Err(_) => {
                    self.counters.packets_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            self.last_rx_ms.store(self.created.elapsed().as_millis() as u64, Ordering::Relaxed);
            self.rx_seq_max.fetch_max(env.seq, Ordering::Relaxed);
            match env.msg_type {
                MsgType::Data => {
                    self.counters.packets_received.fetch_add(1, Ordering::Relaxed);
                    self.counters.bytes_received.fetch_add(env.payload.len() as u64, Ordering::Relaxed);
                    return Ok(env.payload);
                }
                MsgType::Cover => match ctl::parse(&env.payload) {
                    Some(Keepalive::Pong(nonce)) => self.on_pong(nonce),
                    Some(Keepalive::Ping(nonce)) => {
                        let _ = self.send_control(MsgType::Cover, ctl::pong(nonce)).await;
                    }
                    None => {} // cover traffic
                },
                MsgType::Close => return Err(SessionClosed.into()),
                _ => {} // e.g. a duplicate ACK
            }
        }
    }

    /// Send a keepalive PING; the PONG is consumed by [`Tunnel::recv`], which
    /// must therefore be running.
    pub async fn ping(&self) -> Result<()> {
        let nonce: u64 = rand::random();
        *self.ping.lock().expect("ping lock") = Some((nonce, Instant::now()));
        self.send_control(MsgType::Cover, ctl::ping(nonce)).await
    }

    /// Tell the server this session is over (best effort; UDP).
    pub async fn close(&self) {
        let _ = self.send_control(MsgType::Close, Vec::new()).await;
    }

    async fn send_control(&self, msg_type: MsgType, payload: Vec<u8>) -> Result<()> {
        let wire = self.dp.lock().expect("dataplane lock").seal(msg_type, payload)?;
        self.sock.send(&wire).await?;
        Ok(())
    }

    fn on_pong(&self, nonce: u64) {
        let sent = {
            let mut p = self.ping.lock().expect("ping lock");
            match *p {
                Some((n, at)) if n == nonce => {
                    *p = None;
                    at
                }
                _ => return, // stale or unsolicited
            }
        };
        let sample = sent.elapsed().as_micros().max(1) as u64;
        let old = self.srtt_us.load(Ordering::Relaxed);
        let new = if old == 0 { sample } else { (old * 7 + sample) / 8 };
        self.srtt_us.store(new, Ordering::Relaxed);
    }

    /// Smoothed round-trip time of keepalive pings, once one has been answered.
    pub fn rtt(&self) -> Option<Duration> {
        match self.srtt_us.load(Ordering::Relaxed) {
            0 => None,
            us => Some(Duration::from_micros(us)),
        }
    }

    /// Time since the last authenticated packet from the server (or since the
    /// session was confirmed, if none has arrived yet).
    pub fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_rx_ms.load(Ordering::Relaxed));
        self.created.elapsed().saturating_sub(last)
    }

    /// How long ago the server confirmed this session.
    pub fn age(&self) -> Duration {
        self.created.elapsed()
    }

    /// Either direction is far enough along its sequence space that the
    /// session should be replaced by a fresh handshake.
    pub fn sequence_exhausting(&self) -> bool {
        let tx = self.dp.lock().expect("dataplane lock").tx_seq();
        tx >= REKEY_AFTER_SEQ || self.rx_seq_max.load(Ordering::Relaxed) >= REKEY_AFTER_SEQ
    }

    /// What the server told this client when it confirmed the session.
    pub fn info(&self) -> SessionInfo {
        self.info
    }

    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }

    /// The server's `identity_id` (it matched the pinned keys).
    pub fn server_identity(&self) -> [u8; 16] {
        self.server_id
    }

    /// The server's UDP address (the one the handshake resolved and used).
    pub fn server_addr(&self) -> SocketAddr {
        self.server_addr
    }

    pub fn stats(&self) -> TunnelStats {
        let c = &self.counters;
        TunnelStats {
            packets_sent: c.packets_sent.load(Ordering::Relaxed),
            bytes_sent: c.bytes_sent.load(Ordering::Relaxed),
            packets_received: c.packets_received.load(Ordering::Relaxed),
            bytes_received: c.bytes_received.load(Ordering::Relaxed),
            packets_dropped: c.packets_dropped.load(Ordering::Relaxed),
        }
    }
}

/// Send a handshake message's datagrams and wait until `accept` recognizes
/// what comes back, retransmitting them all with backoff (1 s, 2 s, 4 s, 4 s,
/// …) until `deadline`.
async fn exchange<T>(
    sock: &UdpSocket,
    datagrams: &[Vec<u8>],
    buf: &mut [u8],
    deadline: Instant,
    mut accept: impl FnMut(&[u8]) -> Option<T>,
) -> Result<T> {
    let mut wait = HS_RETRANSMIT_FIRST;
    loop {
        for d in datagrams {
            sock.send(d).await?;
        }
        let resend_at = (Instant::now() + wait).min(deadline);
        loop {
            let left = resend_at.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, sock.recv(buf)).await {
                Ok(Ok(n)) => {
                    if let Some(v) = accept(&buf[..n]) {
                        return Ok(v);
                    }
                }
                // ICMP port unreachable surfaces as an error on a connected
                // socket; the server may simply not be up yet, so keep trying.
                Ok(Err(_)) => tokio::time::sleep(left.min(Duration::from_millis(100))).await,
                Err(_) => break, // time to retransmit
            }
            if Instant::now() >= resend_at {
                break;
            }
        }
        if Instant::now() >= deadline {
            bail!("timed out");
        }
        wait = (wait * 2).min(HS_RETRANSMIT_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_info_round_trips() {
        for info in [
            SessionInfo::default(),
            SessionInfo {
                assigned_v4: Some(Ipv4Addr::new(10, 77, 0, 2)),
                prefix_len: 24,
                gateway_v4: Some(Ipv4Addr::new(10, 77, 0, 1)),
                dns_v4: Some(Ipv4Addr::new(10, 77, 0, 1)),
                mtu: TUNNEL_MTU,
                keepalive: true,
            },
        ] {
            assert_eq!(SessionInfo::decode(&info.encode()).unwrap(), info);
        }
        assert!(SessionInfo::decode(b"PQANON-ACK-V2").is_err());
        assert!(SessionInfo::decode(b"PQANON-ACK-V1").is_err());
        assert!(SessionInfo::decode(b"nonsense-wrong-magic-1234").is_err());
    }

    #[test]
    fn a_v1_ack_from_an_older_server_still_decodes() {
        let mut v1 = ACK_MAGIC_V1.to_vec();
        v1.extend_from_slice(&[10, 77, 0, 9, 24, 10, 77, 0, 1]);
        let info = SessionInfo::decode(&v1).unwrap();
        assert_eq!(info.assigned_v4, Some(Ipv4Addr::new(10, 77, 0, 9)));
        assert_eq!(info.gateway_v4, Some(Ipv4Addr::new(10, 77, 0, 1)));
        assert_eq!((info.dns_v4, info.mtu, info.keepalive), (None, 0, false));
        assert_eq!(info.effective_mtu(), TUNNEL_MTU);
    }

    /// A full-size tunnel packet must cross a 1500-byte path without IP
    /// fragmentation over IPv4 and IPv6; one byte more must not (otherwise the
    /// constant is needlessly small).
    #[test]
    fn tunnel_mtu_fits_a_1500_byte_path() {
        let obf = Obfuscator::new(&[7u8; 32], 1);
        let mut s = Session::new(1, [1u8; 32], [2u8; 32], "127.0.0.1:9".parse().unwrap(), true, MTU);
        let wire_len = |s: &mut Session, n: usize| obf.morph(&s.seal_data(MsgType::Data, vec![0u8; n]).unwrap()).unwrap().len();
        for _ in 0..200 {
            assert!(wire_len(&mut s, TUNNEL_MTU as usize) <= 1500 - 40 - 8, "fits IPv6 (and so IPv4)");
        }
        assert!(wire_len(&mut s, TUNNEL_MTU as usize + 1) > 1500 - 20 - 8, "the next byte jumps a bucket");
    }
}
