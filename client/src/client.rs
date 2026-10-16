//! `pqanon::client` — the connection facade every front end shares: the CLI's
//! TUN loop (`pqanon run`), `pqanon probe`, and native apps through the C ABI
//! in `pqanon-ffi`.
//!
//! [`Tunnel::connect`] runs the PQANON-HS/1 handshake over UDP and returns only
//! once the server has **confirmed** the session with a sealed ACK. That ACK
//! proves the server derived the same keys *and admitted this client*. A
//! device-bound server silently drops an unenrolled or revoked device, which
//! therefore fails here with a clear error instead of getting a tunnel that goes
//! nowhere. The ACK also carries the tunnel address the server assigned.
//!
//! A tunnel moves whole IP packets ([`Tunnel::send`] / [`Tunnel::recv`]). How
//! packets reach the OS — a Linux TUN device, an iOS `NEPacketTunnelFlow`, an
//! Android `VpnService` descriptor — is the front end's job, which is exactly
//! the seam a native shell plugs into.

use crate::dataplane::DataPlane;
use crate::handshake::{ClientHandshake, Identity, PeerPublic};
use crate::obf::Obfuscator;
use crate::transport::Session;
use crate::wire::{Envelope, MsgType};
use anyhow::{anyhow, bail, Context, Result};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Tunnel MTU for sealed payloads.
pub const MTU: usize = 1400;
const RECV_BUF: usize = 65_536;

/// What [`Tunnel::connect`] needs.
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
}

const ACK_MAGIC: &[u8] = b"PQANON-ACK-V1";

impl SessionInfo {
    /// `magic || assigned v4 || prefix len || gateway v4`; 0.0.0.0 means none.
    pub fn encode(&self) -> Vec<u8> {
        let mut b = ACK_MAGIC.to_vec();
        b.extend_from_slice(&self.assigned_v4.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
        b.push(self.prefix_len);
        b.extend_from_slice(&self.gateway_v4.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let rest = b
            .strip_prefix(ACK_MAGIC)
            .ok_or_else(|| anyhow!("session ACK has the wrong magic"))?;
        if rest.len() != 9 {
            bail!("session ACK has the wrong length");
        }
        let addr = |o: &[u8]| {
            let a = Ipv4Addr::new(o[0], o[1], o[2], o[3]);
            (!a.is_unspecified()).then_some(a)
        };
        Ok(SessionInfo {
            assigned_v4: addr(&rest[0..4]),
            prefix_len: rest[4],
            gateway_v4: addr(&rest[5..9]),
        })
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

#[derive(Default)]
struct Counters {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
    packets_dropped: AtomicU64,
}

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
    info: SessionInfo,
    counters: Counters,
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

        // PQANON-HS/1. The server is authenticated against its pinned keys
        // while processing SERVER_HELLO.
        let mut hs = ClientHandshake::new(cfg.identity, cfg.server_pub, rand::random());
        if let Some(cert) = cfg.device_cert {
            hs.set_device_cert(cert);
        }
        sock.send(&hs.client_hello([0u8; 32])?.to_plain()).await?;
        let n = recv_before(&sock, &mut buf, deadline)
            .await
            .map_err(|_| anyhow!("no SERVER_HELLO from {server} within {:?}", cfg.handshake_timeout))?;
        hs.recv_server_hello(&Envelope::from_plain(&buf[..n])?)?;
        let (finish, est) = hs.client_finish()?;
        sock.send(&finish.to_plain()).await?;

        // Wait for the sealed ACK. A datagram that does not open is not from
        // this session (a stray reply or a probe answer) and is ignored.
        let mut dp = DataPlane::new(
            Session::new(est.conn_id, est.k_c2s, est.k_s2c, server, true, MTU),
            Obfuscator::new(&est.ss_mix, 1),
        );
        let info = loop {
            let n = recv_before(&sock, &mut buf, deadline).await.map_err(|_| {
                anyhow!(
                    "the server did not confirm the session within {:?}: this client is not \
                     admitted (e.g. an unenrolled or revoked device) or the server is unreachable",
                    cfg.handshake_timeout
                )
            })?;
            if let Ok(env) = dp.open(&buf[..n]) {
                if env.msg_type == MsgType::Ack {
                    break SessionInfo::decode(&env.payload)?;
                }
            }
        };

        Ok(Tunnel {
            sock,
            dp: std::sync::Mutex::new(dp),
            recv_buf: tokio::sync::Mutex::new(buf),
            conn_id: est.conn_id,
            server_id: est.peer_id,
            info,
            counters: Counters::default(),
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

    /// Receive the next IP packet. Cover and control traffic is skipped, and a
    /// datagram that does not open (replay, tampering, not this session) is
    /// dropped and counted.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut buf = self.recv_buf.lock().await;
        loop {
            let n = self.sock.recv(&mut buf).await?;
            // Bind the result first so the dataplane lock is released before
            // anything else happens.
            let opened = self.dp.lock().expect("dataplane lock").inbound(&buf[..n]);
            match opened {
                Ok(Some(pkt)) => {
                    self.counters.packets_received.fetch_add(1, Ordering::Relaxed);
                    self.counters.bytes_received.fetch_add(pkt.len() as u64, Ordering::Relaxed);
                    return Ok(pkt);
                }
                Ok(None) => continue,
                Err(_) => {
                    self.counters.packets_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
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

async fn recv_before(sock: &UdpSocket, buf: &mut [u8], deadline: Instant) -> Result<usize> {
    let left = deadline.saturating_duration_since(Instant::now());
    Ok(tokio::time::timeout(left, sock.recv(buf)).await??)
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
            },
        ] {
            assert_eq!(SessionInfo::decode(&info.encode()).unwrap(), info);
        }
        assert!(SessionInfo::decode(b"PQANON-ACK-V1").is_err());
        assert!(SessionInfo::decode(b"nonsense-wrong-magic-1234").is_err());
    }
}
