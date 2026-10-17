//! SHAIP-UDP/1 — reliability, RTT estimation, and custom BBR-inspired
//! congestion control (§8).
//!
//! The pieces here are deterministic and unit-tested: the anti-replay receive
//! window, the RTT estimator, and the congestion controller. [`Transport`] wires
//! them to a UDP socket; the TUN read/write loop and ACK driver are assembled in
//! the daemon (see `main.rs` and §19).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
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

/// BBR pacing-gain cycle (PROBE_BW): one phase per RTT. The 1.25 phase probes
/// for more bandwidth, the 0.75 phase drains any queue it built, and the six
/// 1.0 phases cruise — the modern BBR steady-state behavior.
const PACING_GAIN_CYCLE: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// cwnd is held at twice the bandwidth-delay product.
const CWND_GAIN: f64 = 2.0;
/// Delivery-rate samples kept for the windowed-max bandwidth filter (~10 RTTs).
const BW_WINDOW: usize = 10;
/// The min-RTT estimate is re-based if no lower sample arrives within this
/// window (BBR ProbeRTT), so the controller tracks path changes instead of
/// latching onto one early minimum forever.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);

/// Custom BBR-inspired congestion controller (§8.3): a windowed max-bandwidth
/// filter, a windowed min-RTT filter, a pacing-gain cycle, and explicit
/// sub-millisecond pacing (the inter-packet gap is derived continuously from
/// the pacing rate, not a fixed millisecond tick).
#[derive(Debug, Clone)]
pub struct CongestionControl {
    pub cwnd: f64,
    pub pacing_rate: f64,
    pub rtt_min: Duration,
    pub bw_est: f64,
    pub in_loss_recovery: bool,
    pub stable_rtts: u32,
    mtu: f64,
    rtt_min_stamp: Instant,
    bw_window: [f64; BW_WINDOW],
    bw_idx: usize,
    gain_phase: usize,
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
            rtt_min_stamp: Instant::now(),
            bw_window: [0.0; BW_WINDOW],
            bw_idx: 0,
            gain_phase: 0,
        }
    }

    /// Process an ACK: update the min-RTT and bandwidth filters, advance the
    /// pacing-gain cycle, and recompute cwnd and the pacing rate.
    pub fn on_ack(&mut self, rtt: Duration, delivered_bytes: usize, interval: Duration) {
        let now = Instant::now();

        // Windowed min-RTT: take any lower sample; re-base a stale minimum.
        if rtt < self.rtt_min || now.duration_since(self.rtt_min_stamp) > MIN_RTT_WINDOW {
            self.rtt_min = rtt;
            self.rtt_min_stamp = now;
        }

        // Delivery-rate sample into the windowed-max bandwidth filter, so a
        // single slow ACK can't collapse the bottleneck estimate.
        let interval_s = interval.as_secs_f64().max(1e-6);
        let sample_bw = delivered_bytes as f64 / interval_s;
        self.bw_window[self.bw_idx] = sample_bw;
        self.bw_idx = (self.bw_idx + 1) % BW_WINDOW;
        let windowed_max = self
            .bw_window
            .iter()
            .copied()
            .fold(0.0_f64, f64::max)
            .max(sample_bw);
        if windowed_max > self.bw_est {
            self.stable_rtts = 0;
        } else {
            self.stable_rtts = self.stable_rtts.saturating_add(1);
        }
        self.bw_est = windowed_max;

        // Advance the gain cycle (≈ one phase per RTT in steady state).
        self.gain_phase = (self.gain_phase + 1) % PACING_GAIN_CYCLE.len();
        let gain = if self.in_loss_recovery {
            1.0
        } else {
            PACING_GAIN_CYCLE[self.gain_phase]
        };

        // cwnd targets 2·BDP; grow toward it (loss handles the cuts).
        let bdp = self.bw_est * self.rtt_min.as_secs_f64();
        let target_cwnd = (CWND_GAIN * bdp).max(4.0 * self.mtu);
        if !self.in_loss_recovery && self.cwnd < target_cwnd {
            self.cwnd = (self.cwnd * 1.25).min(target_cwnd);
        }

        // Pace at gain · bottleneck bandwidth (bytes/sec), at least one packet/s.
        self.pacing_rate = (gain * self.bw_est).max(self.mtu);
    }

    pub fn on_loss(&mut self) {
        self.cwnd = (self.cwnd * 0.7).max(2.0 * self.mtu);
        self.in_loss_recovery = true;
        self.stable_rtts = 0;
    }

    pub fn exit_recovery(&mut self) {
        self.in_loss_recovery = false;
    }

    /// Time to wait before sending `bytes`, at the current pacing rate. The gap
    /// is exactly `bytes / pacing_rate` at nanosecond resolution — so at line
    /// rate it is well under a millisecond, not a coarse fixed tick.
    pub fn next_send_interval(&self, bytes: usize) -> Duration {
        let rate = self.pacing_rate.max(1.0);
        Duration::from_secs_f64(bytes as f64 / rate)
    }

    #[cfg(test)]
    fn mark_min_rtt_stale(&mut self) {
        self.rtt_min_stamp = Instant::now()
            .checked_sub(MIN_RTT_WINDOW + Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
    }
}

/// The last sequence number a session key may seal (with headroom below
/// `u32::MAX`). Past it, [`Session::seal_data`] fails instead of wrapping, so a
/// ChaCha20-Poly1305 nonce can never repeat under one key.
pub const REJECT_AFTER_SEQ: u32 = u32::MAX - (1 << 16);

/// Clients start a new handshake once either direction passes this many
/// packets, far ahead of [`REJECT_AFTER_SEQ`].
pub const REKEY_AFTER_SEQ: u32 = 1 << 30;

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
    ///
    /// The AEAD nonce is `epoch || seq`, so a sequence number must never be
    /// used twice under one key. Once `seq` reaches [`REJECT_AFTER_SEQ`] this
    /// session refuses to seal anything more; a fresh handshake (new keys) is
    /// the only way on. Clients rekey long before, at [`REKEY_AFTER_SEQ`].
    pub fn seal_data(&mut self, msg_type: MsgType, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        if self.next_seq >= REJECT_AFTER_SEQ {
            anyhow::bail!("session key exhausted after {} packets; a new handshake is required", self.next_seq);
        }
        self.next_seq += 1;
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
    fn pacing_interval_is_sub_millisecond_at_line_rate() {
        let mut cc = CongestionControl::new(1400);
        // Drive the bottleneck-bandwidth estimate up to ~30 MB/s.
        for _ in 0..12 {
            cc.on_ack(
                Duration::from_millis(20),
                300_000,
                Duration::from_millis(10),
            );
        }
        // A 1400-byte packet now paces in tens of microseconds — sub-ms, which
        // is the whole point: pacing granularity follows the rate, not a tick.
        let gap = cc.next_send_interval(1400);
        assert!(
            gap < Duration::from_millis(1),
            "pacing gap {gap:?} must be sub-millisecond at line rate"
        );
        assert!(gap > Duration::ZERO);
    }

    #[test]
    fn min_rtt_filter_rebaselines_when_stale() {
        let mut cc = CongestionControl::new(1400);
        cc.on_ack(Duration::from_millis(10), 10_000, Duration::from_millis(10));
        assert_eq!(cc.rtt_min, Duration::from_millis(10));
        // A larger RTT does not raise the min within the window.
        cc.on_ack(Duration::from_millis(40), 10_000, Duration::from_millis(10));
        assert_eq!(cc.rtt_min, Duration::from_millis(10));
        // Once the min is stale, the next sample re-bases it even though larger.
        cc.mark_min_rtt_stale();
        cc.on_ack(Duration::from_millis(40), 10_000, Duration::from_millis(10));
        assert_eq!(cc.rtt_min, Duration::from_millis(40));
    }

    #[test]
    fn bandwidth_filter_retains_windowed_max() {
        let mut cc = CongestionControl::new(1400);
        cc.on_ack(Duration::from_millis(20), 200_000, Duration::from_millis(10)); // 20 MB/s
        let high = cc.bw_est;
        assert!(high >= 20_000_000.0 - 1.0);
        // A single slow ACK must not collapse the bottleneck estimate.
        cc.on_ack(Duration::from_millis(20), 1_000, Duration::from_millis(10)); // 0.1 MB/s
        assert!(
            cc.bw_est >= high - 1.0,
            "windowed max should retain the high sample, got {}",
            cc.bw_est
        );
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

    #[test]
    fn sequence_never_wraps_into_a_reused_nonce() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let mut client = Session::new(7, [1u8; 32], [2u8; 32], addr, true, 1400);
        let mut server = Session::new(7, [1u8; 32], [2u8; 32], addr, false, 1400);
        // Jump to the end of the key's life.
        client.next_seq = REJECT_AFTER_SEQ - 1;
        let last = client.seal_data(MsgType::Data, b"last".to_vec()).unwrap();
        assert_eq!(server.open_data(&last).unwrap().seq, REJECT_AFTER_SEQ);
        // The next seal must fail rather than wrap to seq 0/1 (a repeated nonce).
        let err = client.seal_data(MsgType::Data, b"one more".to_vec()).unwrap_err();
        assert!(err.to_string().contains("new handshake"), "{err}");
        assert_eq!(client.next_seq, REJECT_AFTER_SEQ, "state unchanged by the refused seal");
        const { assert!(REKEY_AFTER_SEQ < REJECT_AFTER_SEQ) };
    }
}
