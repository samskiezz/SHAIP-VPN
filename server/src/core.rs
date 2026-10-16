//! The tunnel server's session table: handshakes, sessions, address leases,
//! and the fate of every datagram and TUN packet. No sockets and no TUN here
//! (it returns what to send), so it is unit-tested with real handshakes;
//! `pqanond` is the I/O shell around it.
//!
//! Per session:
//! - **One session per client identity.** A new handshake from the same
//!   identity (a rekey, or the client moved networks) replaces the old
//!   session, and the client keeps its tunnel address.
//! - **Retransmissions are idempotent.** A repeated CLIENT_HELLO is answered
//!   with the cached SERVER_HELLO, a repeated CLIENT_FINISH with the cached
//!   ACK, so a lost datagram never forks the handshake.
//! - **Cryptokey routing.** In TUN mode a client may only send packets from
//!   its own tunnel address (anything else is spoofing and dropped), and by
//!   default may not reach other clients or private, link-local, multicast,
//!   or reserved destinations from the server's network.
//! - **Lifecycle.** PINGs are answered with PONGs; a session silent for the
//!   session timeout, or one that sends `Close`, is ended; half-open
//!   handshakes expire; on shutdown every client is told `Close`.

use crate::pool::Pool;
use pqanon::client::{SessionInfo, MTU, TUNNEL_MTU};
use pqanon::ctl::{self, Keepalive};
use pqanon::dataplane::DataPlane;
use pqanon::handshake::{DevicePolicy, Established, Identity, ServerHandshake};
use pqanon::metrics;
use pqanon::obf::Obfuscator;
use pqanon::transport::Session;
use pqanon::wire::{Envelope, MsgType};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// What answering a handshake needs: the server identity and, on a
/// device-bound daemon, the admission policy.
#[derive(Clone)]
pub struct Gate {
    pub identity: Identity,
    pub policy: Option<DevicePolicy>,
}

impl Gate {
    fn handshake(&self, conn_id: u64) -> ServerHandshake {
        match &self.policy {
            Some(p) => ServerHandshake::new_device_bound(self.identity.clone(), p.clone(), conn_id),
            None => ServerHandshake::new_open(self.identity.clone(), conn_id),
        }
    }
}

/// What happens to decrypted DATA.
pub enum Forwarding {
    /// Echoed back to the sender (no TUN): a demo and test mode.
    Echo,
    /// IP packets, validated and handed to the TUN device.
    Tun(TunPolicy),
}

/// TUN-mode parameters.
pub struct TunPolicy {
    /// This server's tunnel address and prefix (`--tun-addr`).
    pub gateway: Ipv4Addr,
    pub prefix: u8,
    /// Resolver pushed to clients (the forwarder on `gateway`), if any.
    pub dns: Option<Ipv4Addr>,
    /// Let clients reach each other's tunnel addresses.
    pub allow_client_to_client: bool,
    /// Let clients reach private / link-local / reserved destinations.
    pub allow_private_destinations: bool,
}

/// Timeouts and caps.
#[derive(Clone, Copy)]
pub struct Limits {
    pub handshake_timeout: Duration,
    pub session_timeout: Duration,
    pub lease_grace: Duration,
    pub max_pending: usize,
    /// How long a repeated CLIENT_FINISH is answered with the cached ACK.
    pub ack_resend_window: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            handshake_timeout: Duration::from_secs(10),
            session_timeout: Duration::from_secs(180),
            lease_grace: Duration::from_secs(600),
            max_pending: 1024,
            ack_resend_window: Duration::from_secs(30),
        }
    }
}

/// Something the I/O shell must do.
#[derive(Debug, PartialEq, Eq)]
pub enum Out {
    /// Send this datagram.
    Udp(Vec<u8>, SocketAddr),
    /// Write this IP packet to the TUN device.
    Tun(Vec<u8>),
}

/// Why a session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    Closed,
    TimedOut,
    Replaced,
}

struct Pending {
    hs: Box<ServerHandshake>,
    hello: Vec<u8>,
    server_hello: Vec<u8>,
    created: Instant,
}

struct Peer {
    dp: DataPlane,
    identity: [u8; 16],
    device: Option<[u8; 16]>,
    assigned: Option<Ipv4Addr>,
    hs_conn_id: u64,
    ack: Vec<u8>,
    created: Instant,
    last_rx: Instant,
}

/// Counts for logs and tests (the Prometheus metrics are updated alongside).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreStats {
    pub handshakes_ok: u64,
    pub handshakes_failed: u64,
    pub spoofed: u64,
    pub filtered: u64,
    pub keepalives: u64,
    pub decoys: u64,
    pub ended: u64,
}

pub struct Core {
    gate: Gate,
    fwd: Forwarding,
    limits: Limits,
    pool: Option<Pool>,
    pending: HashMap<SocketAddr, Pending>,
    peers: HashMap<SocketAddr, Peer>,
    by_identity: HashMap<[u8; 16], SocketAddr>,
    routes: HashMap<Ipv4Addr, SocketAddr>,
    stats: CoreStats,
}

fn hex16(b: [u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Destinations a client may not reach through the server unless allowed:
/// private, shared (CGNAT), loopback, link-local (incl. cloud metadata at
/// 169.254.169.254), multicast, and reserved space.
pub fn is_restricted_destination(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10
        || o[0] >= 240
}

impl Core {
    pub fn new(gate: Gate, fwd: Forwarding, limits: Limits) -> anyhow::Result<Core> {
        let pool = match &fwd {
            Forwarding::Tun(p) => Some(Pool::new(p.gateway, p.prefix)?),
            Forwarding::Echo => None,
        };
        Ok(Core {
            gate,
            fwd,
            limits,
            pool,
            pending: HashMap::new(),
            peers: HashMap::new(),
            by_identity: HashMap::new(),
            routes: HashMap::new(),
            stats: CoreStats::default(),
        })
    }

    pub fn stats(&self) -> CoreStats {
        self.stats
    }

    pub fn sessions(&self) -> usize {
        self.peers.len()
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// The tunnel address leased to a session at `addr`, if any.
    pub fn assigned(&self, addr: &SocketAddr) -> Option<Ipv4Addr> {
        self.peers.get(addr).and_then(|p| p.assigned)
    }

    fn update_gauges(&self) {
        metrics::SESSIONS_ACTIVE.set(self.peers.len() as u64);
        metrics::HANDSHAKES_PENDING.set(self.pending.len() as u64);
    }

    /// A datagram arrived from `src`.
    pub fn on_datagram(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Vec<Out> {
        let out = self.dispatch(src, pkt, now);
        self.update_gauges();
        out
    }

    fn dispatch(&mut self, src: SocketAddr, pkt: &[u8], now: Instant) -> Vec<Out> {
        if let Some(peer) = self.peers.get_mut(&src) {
            match peer.dp.open(pkt) {
                Ok(env) => {
                    peer.last_rx = now;
                    return self.on_session_message(src, env, now);
                }
                Err(_) => match Envelope::from_plain(pkt) {
                    // The ACK was lost and the client repeated CLIENT_FINISH.
                    Ok(env)
                        if env.msg_type == MsgType::ClientFinish
                            && env.conn_id == peer.hs_conn_id
                            && now.saturating_duration_since(peer.created) < self.limits.ack_resend_window =>
                    {
                        return vec![Out::Udp(peer.ack.clone(), src)];
                    }
                    // A new handshake from this address (the client restarted):
                    // handled below; the old session stays until it completes.
                    Ok(env) if matches!(env.msg_type, MsgType::ClientHello | MsgType::ClientFinish) => {}
                    // Garbage or a replay from a client's address: drop quietly.
                    _ => return Vec::new(),
                },
            }
        }
        let env = match Envelope::from_plain(pkt) {
            Ok(env) => env,
            Err(_) => {
                // Not our protocol: a scanner or DPI probe. Answer like an
                // HTTPS server would (§10.2) — but never with more bytes than
                // arrived, so a spoofed source cannot use us as an amplifier.
                let decoy = pqanon::tls_decoy::probe_response();
                if pkt.len() < decoy.len() {
                    return Vec::new();
                }
                self.stats.decoys += 1;
                return vec![Out::Udp(decoy, src)];
            }
        };
        match env.msg_type {
            MsgType::ClientHello => self.on_client_hello(src, pkt, env, now),
            MsgType::ClientFinish => self.on_client_finish(src, env, now),
            _ => Vec::new(),
        }
    }

    fn on_client_hello(&mut self, src: SocketAddr, raw: &[u8], env: Envelope, now: Instant) -> Vec<Out> {
        if let Some(p) = self.pending.get(&src) {
            if p.hello == raw {
                return vec![Out::Udp(p.server_hello.clone(), src)]; // a retransmission
            }
        }
        if self.pending.len() >= self.limits.max_pending && !self.pending.contains_key(&src) {
            tracing::warn!(%src, "too many half-open handshakes; dropping CLIENT_HELLO");
            return Vec::new();
        }
        let mut hs = self.gate.handshake(env.conn_id);
        let server_hello = match hs.recv_client_hello(&env, true).and_then(|_| hs.server_hello()) {
            Ok(sh) => sh.to_plain(),
            Err(e) => {
                self.stats.handshakes_failed += 1;
                metrics::HANDSHAKES_FAILED.inc();
                tracing::debug!(%src, error = %e, "CLIENT_HELLO rejected");
                return Vec::new();
            }
        };
        self.pending.insert(
            src,
            Pending {
                hs: Box::new(hs),
                hello: raw.to_vec(),
                server_hello: server_hello.clone(),
                created: now,
            },
        );
        tracing::debug!(%src, "CLIENT_HELLO ok; sent SERVER_HELLO");
        vec![Out::Udp(server_hello, src)]
    }

    fn on_client_finish(&mut self, src: SocketAddr, env: Envelope, now: Instant) -> Vec<Out> {
        let Some(mut p) = self.pending.remove(&src) else {
            return Vec::new();
        };
        let est: Established = match p.hs.recv_client_finish(&env) {
            Ok(e) => e,
            Err(e) => {
                self.stats.handshakes_failed += 1;
                metrics::HANDSHAKES_FAILED.inc();
                tracing::info!(%src, error = %e, "handshake refused");
                return Vec::new();
            }
        };
        // One session per identity; and a different identity may have been
        // using this address before.
        if let Some(old) = self.by_identity.get(&est.peer_id).copied() {
            self.end(old, Ended::Replaced, now);
        }
        if self.peers.contains_key(&src) {
            self.end(src, Ended::Replaced, now);
        }
        let assigned = match self.pool.as_mut() {
            Some(pool) => match pool.lease(est.peer_id) {
                Some(ip) => Some(ip),
                None => {
                    tracing::warn!(%src, "tunnel address pool exhausted; refusing the session");
                    return Vec::new();
                }
            },
            None => None,
        };
        let info = match &self.fwd {
            Forwarding::Tun(t) => SessionInfo {
                assigned_v4: assigned,
                prefix_len: t.prefix,
                gateway_v4: Some(t.gateway),
                dns_v4: t.dns,
                mtu: TUNNEL_MTU,
                keepalive: true,
            },
            Forwarding::Echo => SessionInfo {
                mtu: TUNNEL_MTU,
                keepalive: true,
                ..SessionInfo::default()
            },
        };
        let mut dp = DataPlane::new(
            Session::new(est.conn_id, est.k_c2s, est.k_s2c, src, false, MTU),
            Obfuscator::new(&est.ss_mix, 1),
        );
        // A sealed ACK proves we derived the same keys and admitted this client.
        let ack = match dp.seal(MsgType::Ack, info.encode()) {
            Ok(a) => a,
            Err(_) => return Vec::new(),
        };
        if let Some(ip) = assigned {
            self.routes.insert(ip, src);
        }
        self.by_identity.insert(est.peer_id, src);
        let device = est.device.as_ref().map(|d| d.device_id);
        self.peers.insert(
            src,
            Peer {
                dp,
                identity: est.peer_id,
                device,
                assigned,
                hs_conn_id: env.conn_id,
                ack: ack.clone(),
                created: now,
                last_rx: now,
            },
        );
        self.stats.handshakes_ok += 1;
        metrics::HANDSHAKES_OK.inc();
        metrics::SESSIONS_ESTABLISHED.inc();
        tracing::info!(%src, conn_id = format!("{:#018x}", est.conn_id), client = %hex16(est.peer_id),
            device = %device.map(hex16).unwrap_or_else(|| "-".into()), assigned = ?assigned, "session established");
        vec![Out::Udp(ack, src)]
    }

    fn on_session_message(&mut self, src: SocketAddr, env: Envelope, now: Instant) -> Vec<Out> {
        match env.msg_type {
            MsgType::Data => self.on_data(src, env.payload),
            MsgType::Cover => match ctl::parse(&env.payload) {
                Some(Keepalive::Ping(nonce)) => {
                    let Some(peer) = self.peers.get_mut(&src) else { return Vec::new() };
                    self.stats.keepalives += 1;
                    metrics::KEEPALIVES.inc();
                    match peer.dp.seal(MsgType::Cover, ctl::pong(nonce)) {
                        Ok(w) => vec![Out::Udp(w, src)],
                        Err(_) => Vec::new(),
                    }
                }
                _ => Vec::new(), // cover traffic
            },
            MsgType::Close => {
                self.end(src, Ended::Closed, now);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    fn on_data(&mut self, src: SocketAddr, payload: Vec<u8>) -> Vec<Out> {
        let Some(peer) = self.peers.get_mut(&src) else { return Vec::new() };
        metrics::DATA_PACKETS.inc();
        let policy = match &self.fwd {
            Forwarding::Echo => {
                return match peer.dp.seal(MsgType::Data, payload) {
                    Ok(w) => vec![Out::Udp(w, src)],
                    Err(_) => Vec::new(),
                };
            }
            Forwarding::Tun(t) => t,
        };
        // Cryptokey routing: the only source a client may use is its own.
        match pqanon::ipparse::source_ip(&payload) {
            Some(IpAddr::V4(s)) if Some(s) == peer.assigned => {}
            _ => {
                self.stats.spoofed += 1;
                metrics::PACKETS_SPOOFED.inc();
                return Vec::new();
            }
        }
        let Some(IpAddr::V4(dst)) = pqanon::ipparse::destination_ip(&payload) else {
            return Vec::new();
        };
        let in_tunnel = self.pool.as_ref().is_some_and(|p| p.contains(dst));
        let allowed = if dst == policy.gateway {
            true // the server itself (its DNS forwarder)
        } else if in_tunnel {
            policy.allow_client_to_client
        } else {
            policy.allow_private_destinations || !is_restricted_destination(dst)
        };
        if !allowed {
            self.stats.filtered += 1;
            metrics::PACKETS_FILTERED.inc();
            return Vec::new();
        }
        metrics::BYTES_FROM_CLIENTS.add(payload.len() as u64);
        vec![Out::Tun(payload)]
    }

    /// A packet read from the TUN device: route it to the session that owns
    /// its destination address.
    pub fn on_tun_packet(&mut self, pkt: &[u8]) -> Option<Out> {
        let Some(IpAddr::V4(dst)) = pqanon::ipparse::destination_ip(pkt) else {
            return None;
        };
        let addr = *self.routes.get(&dst)?;
        let peer = self.peers.get_mut(&addr)?;
        let wire = peer.dp.seal(MsgType::Data, pkt.to_vec()).ok()?;
        metrics::BYTES_TO_CLIENTS.add(pkt.len() as u64);
        Some(Out::Udp(wire, addr))
    }

    /// Expire half-open handshakes, silent sessions, and old leases.
    pub fn on_tick(&mut self, now: Instant) {
        let hs_timeout = self.limits.handshake_timeout;
        self.pending
            .retain(|_, p| now.saturating_duration_since(p.created) < hs_timeout);
        let silent: Vec<SocketAddr> = self
            .peers
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.last_rx) > self.limits.session_timeout)
            .map(|(a, _)| *a)
            .collect();
        for addr in silent {
            self.end(addr, Ended::TimedOut, now);
        }
        if let Some(pool) = self.pool.as_mut() {
            pool.expire(now, self.limits.lease_grace);
        }
        self.update_gauges();
    }

    fn end(&mut self, addr: SocketAddr, why: Ended, now: Instant) {
        let Some(p) = self.peers.remove(&addr) else { return };
        if self.by_identity.get(&p.identity) == Some(&addr) {
            self.by_identity.remove(&p.identity);
        }
        if let Some(ip) = p.assigned {
            if self.routes.get(&ip) == Some(&addr) {
                self.routes.remove(&ip);
            }
            // Released for the grace period, unless the same identity has just
            // taken it again (a replacement).
            if !self.by_identity.contains_key(&p.identity) {
                if let Some(pool) = self.pool.as_mut() {
                    pool.release(p.identity, now);
                }
            }
        }
        self.stats.ended += 1;
        metrics::SESSIONS_ENDED.inc();
        tracing::info!(%addr, client = %hex16(p.identity), device = %p.device.map(hex16).unwrap_or_else(|| "-".into()),
            reason = ?why, lasted_s = now.saturating_duration_since(p.created).as_secs(), "session ended");
    }

    /// Tell every client the server is going away, and forget them.
    pub fn shutdown(&mut self, now: Instant) -> Vec<Out> {
        let mut out = Vec::new();
        for (addr, peer) in self.peers.iter_mut() {
            if let Ok(w) = peer.dp.seal(MsgType::Close, Vec::new()) {
                out.push(Out::Udp(w, *addr));
            }
        }
        let addrs: Vec<SocketAddr> = self.peers.keys().copied().collect();
        for a in addrs {
            self.end(a, Ended::Closed, now);
        }
        self.update_gauges();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqanon::handshake::{ClientHandshake, PeerPublic};

    /// ML-DSA-65 needs more stack than the default test thread has.
    fn big_stack(f: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new().stack_size(64 << 20).spawn(f).unwrap().join().unwrap();
    }

    fn tun_core(server: &Identity) -> Core {
        Core::new(
            Gate { identity: server.clone(), policy: None },
            Forwarding::Tun(TunPolicy {
                gateway: Ipv4Addr::new(10, 77, 0, 1),
                prefix: 24,
                dns: Some(Ipv4Addr::new(10, 77, 0, 1)),
                allow_client_to_client: false,
                allow_private_destinations: false,
            }),
            Limits::default(),
        )
        .unwrap()
    }

    fn udp(out: &[Out]) -> &[u8] {
        match out {
            [Out::Udp(b, _)] => b,
            other => panic!("expected one datagram, got {other:?}"),
        }
    }

    /// Run a client handshake against `core` from `src`; returns the client's
    /// data plane and the session info the ACK carried.
    fn connect(core: &mut Core, server_pub: PeerPublic, client: Identity, src: SocketAddr) -> (DataPlane, SessionInfo) {
        let now = Instant::now();
        let mut hs = ClientHandshake::new(client, server_pub, rand::random());
        let hello = hs.client_hello([0u8; 32]).unwrap().to_plain();
        let out = core.on_datagram(src, &hello, now);
        // A retransmitted hello gets the very same SERVER_HELLO.
        assert_eq!(core.on_datagram(src, &hello, now), out);
        hs.recv_server_hello(&Envelope::from_plain(udp(&out)).unwrap()).unwrap();
        let (finish, est) = hs.client_finish().unwrap();
        let finish = finish.to_plain();
        let ack = core.on_datagram(src, &finish, now);
        // A retransmitted finish gets the cached ACK back.
        assert_eq!(core.on_datagram(src, &finish, now), ack);
        let mut dp = DataPlane::new(
            Session::new(est.conn_id, est.k_c2s, est.k_s2c, src, true, MTU),
            Obfuscator::new(&est.ss_mix, 1),
        );
        let env = dp.open(udp(&ack)).unwrap();
        assert_eq!(env.msg_type, MsgType::Ack);
        (dp, SessionInfo::decode(&env.payload).unwrap())
    }

    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn session_lifecycle_in_tun_mode() {
        big_stack(|| {
            let server = Identity::generate();
            let mut core = tun_core(&server);
            let alice = Identity::generate();
            let a_addr: SocketAddr = "198.51.100.1:40000".parse().unwrap();
            let (mut a, info) = connect(&mut core, server.public(), alice.clone(), a_addr);
            let a_ip = info.assigned_v4.expect("assigned");
            assert_eq!(info.gateway_v4, Some(Ipv4Addr::new(10, 77, 0, 1)));
            assert_eq!(info.dns_v4, Some(Ipv4Addr::new(10, 77, 0, 1)));
            assert!(info.keepalive);
            assert_eq!(info.mtu, TUNNEL_MTU);
            let now = Instant::now();

            // Outbound IP from the client's own address reaches the TUN device.
            let web = Ipv4Addr::new(93, 184, 215, 14);
            let pkt = ipv4(a_ip, web);
            let w = a.outbound(&pkt).unwrap();
            assert_eq!(core.on_datagram(a_addr, &w, now), vec![Out::Tun(pkt.clone())]);
            // Spoofed source: dropped.
            let w = a.outbound(&ipv4(Ipv4Addr::new(10, 77, 0, 99), web)).unwrap();
            assert!(core.on_datagram(a_addr, &w, now).is_empty());
            assert_eq!(core.stats().spoofed, 1);
            // Cloud metadata / private ranges: filtered.
            for dst in [Ipv4Addr::new(169, 254, 169, 254), Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 77, 0, 50)] {
                let w = a.outbound(&ipv4(a_ip, dst)).unwrap();
                assert!(core.on_datagram(a_addr, &w, now).is_empty(), "{dst} must be filtered");
            }
            assert_eq!(core.stats().filtered, 3);
            // The gateway (DNS forwarder) is reachable.
            let to_gw = ipv4(a_ip, Ipv4Addr::new(10, 77, 0, 1));
            let w = a.outbound(&to_gw).unwrap();
            assert_eq!(core.on_datagram(a_addr, &w, now), vec![Out::Tun(to_gw)]);

            // Return traffic from TUN is routed by destination to Alice.
            let reply = ipv4(web, a_ip);
            match core.on_tun_packet(&reply) {
                Some(Out::Udp(w, to)) => {
                    assert_eq!(to, a_addr);
                    assert_eq!(a.inbound(&w).unwrap(), Some(reply));
                }
                other => panic!("{other:?}"),
            }

            // Keepalive: PING → PONG with the same nonce.
            let ping = a.seal(MsgType::Cover, ctl::ping(42)).unwrap();
            let pong = core.on_datagram(a_addr, &ping, now);
            let env = a.open(udp(&pong)).unwrap();
            assert_eq!((env.msg_type, ctl::parse(&env.payload)), (MsgType::Cover, Some(Keepalive::Pong(42))));

            // Rekey: a new handshake from the same identity on a new port
            // replaces the session and keeps the address.
            let a2_addr: SocketAddr = "198.51.100.1:40001".parse().unwrap();
            let (_a2, info2) = connect(&mut core, server.public(), alice, a2_addr);
            assert_eq!(info2.assigned_v4, Some(a_ip), "same address after a rekey");
            assert_eq!(core.sessions(), 1);
            assert!(matches!(core.on_tun_packet(&ipv4(web, a_ip)), Some(Out::Udp(_, to)) if to == a2_addr));

            // Shutdown tells the client to go.
            let out = core.shutdown(Instant::now());
            assert_eq!(out.len(), 1);
            assert_eq!(core.sessions(), 0);
        });
    }

    #[test]
    fn silent_sessions_and_half_open_handshakes_expire() {
        big_stack(|| {
            let server = Identity::generate();
            let mut core = tun_core(&server);
            let addr: SocketAddr = "198.51.100.2:5000".parse().unwrap();
            let (mut c, _) = connect(&mut core, server.public(), Identity::generate(), addr);
            let t0 = Instant::now();
            // A half-open handshake from elsewhere.
            let mut hs = ClientHandshake::new(Identity::generate(), server.public(), 9);
            let hello = hs.client_hello([0u8; 32]).unwrap().to_plain();
            core.on_datagram("198.51.100.3:5000".parse().unwrap(), &hello, t0);
            assert_eq!(core.pending(), 1);
            core.on_tick(t0 + Duration::from_secs(11));
            assert_eq!(core.pending(), 0, "half-open handshake expired");
            assert_eq!(core.sessions(), 1, "the live session is kept");
            // The session goes silent past the timeout.
            core.on_tick(t0 + Duration::from_secs(181));
            assert_eq!(core.sessions(), 0);
            // Its datagrams now come from an unknown sender: they look like a
            // probe and get the decoy answer, never a tunnel reply.
            let w = c.outbound(&[0x45; 28]).unwrap();
            let out = core.on_datagram(addr, &w, t0);
            assert!(matches!(&out[..], [Out::Udp(_, to)] if *to == addr));
            assert_eq!(core.stats().decoys, 1);
            // A probe smaller than the decoy gets nothing (no amplification).
            assert!(core.on_datagram(addr, &[0x16, 0x03, 0x01], t0).is_empty());
            assert_eq!(core.stats().decoys, 1);
        });
    }

    #[test]
    fn echo_mode_echoes_and_assigns_nothing() {
        big_stack(|| {
            let server = Identity::generate();
            let mut core = Core::new(Gate { identity: server.clone(), policy: None }, Forwarding::Echo, Limits::default()).unwrap();
            let addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
            let (mut c, info) = connect(&mut core, server.public(), Identity::generate(), addr);
            assert_eq!(info.assigned_v4, None);
            let w = c.outbound(b"anything at all").unwrap();
            let back = core.on_datagram(addr, &w, Instant::now());
            assert_eq!(c.inbound(udp(&back)).unwrap(), Some(b"anything at all".to_vec()));
            // Close ends it.
            let close = c.seal(MsgType::Close, Vec::new()).unwrap();
            assert!(core.on_datagram(addr, &close, Instant::now()).is_empty());
            assert_eq!(core.sessions(), 0);
        });
    }

    #[test]
    fn restricted_destinations() {
        for ip in ["10.1.2.3", "172.16.0.1", "192.168.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "224.0.0.1", "240.0.0.1", "0.1.2.3", "255.255.255.255"] {
            assert!(is_restricted_destination(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "93.184.215.14", "100.128.0.1", "172.32.0.1"] {
            assert!(!is_restricted_destination(ip.parse().unwrap()), "{ip}");
        }
    }
}
