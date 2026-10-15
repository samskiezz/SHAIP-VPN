//! PQANON-UDP/1 — reliability, RTT estimation, and custom BBR-inspired
//! congestion control (§8).
//!
//! The pieces here are deterministic and unit-tested: the anti-replay receive
//! window, the RTT estimator, and the congestion controller. [`Transport`] wires
//! them to a UDP socket; the TUN read/write loop and ACK driver are assembled in
//! the daemon (see `main.rs` and §19).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::wire::{Envelope, MsgType};

/// Anti-replay / ordering window (§8.2) — a 64-packet sliding bitmap.
///
/// `top` is the highest sequence accepted; bit `i` of `bitmap` records that
/// `top - i` was already accepted (bit 0 = `top`).
#[derive(Debug, Default)]
pub struct RecvWindow {
    top: u32,
    bitmap: u64,
    initialized: bool,
}

impl RecvWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `seq` is fresh (not a duplicate, not outside the window).
    pub fn accept(&mut self, seq: u32) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.top = seq;
            self.bitmap = 1;
            return true;
        }
        if seq > self.top {
            let shift = seq - self.top;
            if shift >= 64 {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << shift) | 1;
            }
            self.top = seq;
            return true;
        }
        let diff = self.top - seq;
        if diff >= 64 {
            return false; // too old to disambiguate — reject
        }
        let bit = 1u64 << diff;
        if self.bitmap & bit != 0 {
            return false; // duplicate
        }
        self.bitmap |= bit;
        true
    }
}

/// Smoothed RTT estimator with the standard EWMA weights (α = 1/8, β = 1/4).
#[derive(Debug, Clone)]
pub struct RttEstimator {
    pub srtt: Duration,
    pub rttvar: Duration,
    seeded: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            srtt: Duration::from_millis(200),
            rttvar: Duration::from_millis(100),
            seeded: false,
        }
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, sample: Duration) {
        let s = sample.as_secs_f64();
        if !self.seeded {
            self.seeded = true;
            self.srtt = sample;
            self.rttvar = Duration::from_secs_f64(s / 2.0);
            return;
        }
        let srtt = self.srtt.as_secs_f64();
        let rttvar = self.rttvar.as_secs_f64();
        let new_rttvar = (1.0 - 0.25) * rttvar + 0.25 * (srtt - s).abs();
        let new_srtt = (1.0 - 0.125) * srtt + 0.125 * s;
        self.srtt = Duration::from_secs_f64(new_srtt);
        self.rttvar = Duration::from_secs_f64(new_rttvar);
    }

    /// Retransmission timeout: `srtt + 4·rttvar`, clamped to [50 ms, 2 s] (§8.2).
    pub fn rto(&self) -> Duration {
        let rto = self.srtt + 4 * self.rttvar;
        rto.clamp(Duration::from_millis(50), Duration::from_secs(2))
    }
}

/// Custom BBR-inspired congestion controller (§8.3).
#[derive(Debug, Clone)]
pub struct CongestionControl {
    pub cwnd: f64,
    pub pacing_rate: f64,
    pub rtt_min: Duration,
    pub bw_est: f64,
    pub in_loss_recovery: bool,
    pub stable_rtts: u32,
    mtu: f64,
}

impl CongestionControl {
    pub fn new(mtu: usize) -> Self {
        let mtu = mtu as f64;
        Self {
            cwnd: 16.0 * mtu,
            pacing_rate: 1_000_000.0,
            rtt_min: Duration::from_millis(100),
            bw_est: 1_000_000.0,
            in_loss_recovery: false,
            stable_rtts: 0,
            mtu,
        }
    }

    pub fn on_ack(&mut self, rtt: Duration, delivered_bytes: usize, interval: Duration) {
        if rtt < self.rtt_min {
            self.rtt_min = rtt;
        }
        let interval_s = interval.as_secs_f64().max(1e-6);
        let sample_bw = delivered_bytes as f64 / interval_s;
        if sample_bw > self.bw_est {
            self.bw_est = sample_bw;
            self.stable_rtts = 0;
        } else {
            self.stable_rtts = self.stable_rtts.saturating_add(1);
        }

        let two_bdp = self.bw_est * self.rtt_min.as_secs_f64() * 2.0;
        if !self.in_loss_recovery && self.cwnd < two_bdp {
            self.cwnd *= 1.25;
        }
        self.pacing_rate =
            (self.cwnd / self.rtt_min.as_secs_f64().max(1e-3)).min(self.bw_est * 1.25);
    }

    pub fn on_loss(&mut self) {
        self.cwnd = (self.cwnd * 0.7).max(2.0 * self.mtu);
        self.in_loss_recovery = true;
        self.stable_rtts = 0;
    }

    pub fn exit_recovery(&mut self) {
        self.in_loss_recovery = false;
    }
}

/// Per-session transport state.
pub struct Session {
    pub conn_id: u64,
    pub c2s_key: [u8; 32],
    pub s2c_key: [u8; 32],
    pub epoch: u16,
    pub next_seq: u32,
    pub recv: RecvWindow,
    pub rtt: RttEstimator,
    pub cc: CongestionControl,
    pub peer_addr: SocketAddr,
    /// `true` on the client (seals with c2s, opens with s2c); inverse on server.
    pub is_client: bool,
}

impl Session {
    pub fn new(
        conn_id: u64,
        c2s_key: [u8; 32],
        s2c_key: [u8; 32],
        peer_addr: SocketAddr,
        is_client: bool,
        mtu: usize,
    ) -> Self {
        Self {
            conn_id,
            c2s_key,
            s2c_key,
            epoch: 1,
            next_seq: 0,
            recv: RecvWindow::new(),
            rtt: RttEstimator::new(),
            cc: CongestionControl::new(mtu),
            peer_addr,
            is_client,
        }
    }

    fn tx_key(&self) -> [u8; 32] {
        if self.is_client {
            self.c2s_key
        } else {
            self.s2c_key
        }
    }

    fn rx_key(&self) -> [u8; 32] {
        if self.is_client {
            self.s2c_key
        } else {
            self.c2s_key
        }
    }

    /// Seal an application payload as the next DATA packet (pre-obfuscation).
    pub fn seal_data(&mut self, msg_type: MsgType, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.next_seq = self.next_seq.wrapping_add(1);
        let env = Envelope {
            msg_type,
            epoch: self.epoch,
            conn_id: self.conn_id,
            seq: self.next_seq,
            payload,
        };
        env.seal(&self.tx_key())
    }

    /// Open an inbound DATA packet and enforce the replay window.
    pub fn open_data(&mut self, packet: &[u8]) -> anyhow::Result<Envelope> {
        let env = Envelope::open(packet, &self.rx_key())?;
        if !self.recv.accept(env.seq) {
            anyhow::bail!("replayed or out-of-window seq {}", env.seq);
        }
        Ok(env)
    }
}

/// UDP transport, demultiplexing by `conn_id`.
pub struct Transport {
    socket: Arc<UdpSocket>,
    sessions: Arc<Mutex<HashMap<u64, Session>>>,
}

impl Transport {
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        Ok(Self {
            socket,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn register(&self, session: Session) {
        let mut s = self.sessions.lock().await;
        s.insert(session.conn_id, session);
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    pub fn sessions(&self) -> Arc<Mutex<HashMap<u64, Session>>> {
        self.sessions.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_basics() {
        let mut w = RecvWindow::new();
        assert!(w.accept(1)); // first
        assert!(w.accept(2));
        assert!(!w.accept(2)); // duplicate
        assert!(w.accept(5)); // jump forward
        assert!(w.accept(3)); // in-window reorder
        assert!(w.accept(4));
        assert!(!w.accept(3)); // duplicate after reorder
    }

    #[test]
    fn replay_window_rejects_ancient() {
        let mut w = RecvWindow::new();
        assert!(w.accept(1000));
        assert!(!w.accept(100)); // far outside the 64-window
        assert!(w.accept(1001));
    }

    #[test]
    fn rtt_estimator_converges() {
        let mut r = RttEstimator::new();
        for _ in 0..50 {
            r.update(Duration::from_millis(80));
        }
        let srtt_ms = r.srtt.as_millis();
        assert!((75..=85).contains(&srtt_ms), "srtt={srtt_ms}ms");
        assert!(r.rto() >= Duration::from_millis(50));
    }

    #[test]
    fn congestion_backoff_and_growth() {
        let mut cc = CongestionControl::new(1400);
        let start = cc.cwnd;
        cc.on_ack(Duration::from_millis(50), 64_000, Duration::from_millis(50));
        assert!(cc.cwnd > start, "cwnd should grow while below 2·BDP");
        let before_loss = cc.cwnd;
        cc.on_loss();
        assert!(cc.cwnd < before_loss);
        assert!(cc.cwnd >= 2.0 * 1400.0);
        assert!(cc.in_loss_recovery);
    }

    #[test]
    fn session_seal_open_directional() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut client = Session::new(7, [1u8; 32], [2u8; 32], addr, true, 1400);
        let mut server = Session::new(7, [1u8; 32], [2u8; 32], addr, false, 1400);
        let wire = client.seal_data(MsgType::Data, b"ping".to_vec()).unwrap();
        let env = server.open_data(&wire).unwrap();
        assert_eq!(env.payload, b"ping");
        // Replay is rejected.
        assert!(server.open_data(&wire).is_err());
    }
}
