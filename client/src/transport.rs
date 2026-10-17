//! SHAIP-UDP/1 — reliability, RTT estimation, and custom BBR-inspired
//! congestion control (§8).
//!
//! The pieces here are deterministic and unit-tested: the anti-replay receive
//! window, the RTT estimator, and the congestion controller. [`Transport`] wires
//! them to a UDP socket; the TUN read/write loop and ACK driver are assembled in
//! the daemon (see `main.rs` and §19).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::wire::{Envelope, MsgType};

// SHAIP-SHAPE/1 (traffic-analysis defence) is built on the real Maybenot
// framework. Maybenot targets rand 0.9, pulled in here as `rand09` alongside the
// crate's rand 0.8; `enum-map` matches Maybenot's version so machine States can
// be constructed programmatically against its Event enum.
use enum_map::enum_map;
use maybenot::action::{Action as MbAction, Timer as MbTimer};
use maybenot::dist::{Dist, DistType};
use maybenot::event::Event as MbEvent;
use maybenot::state::{State as MbState, Trans};
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand09::rngs::StdRng;
use rand09::SeedableRng;

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

// ===========================================================================
// SHAIP-SHAPE/1 — client-side traffic-analysis defence (Maybenot integration)
// ===========================================================================
//
// Even though every datagram is sealed and OBF/2 length-shaped, the *timing* of
// outgoing packets still leaks a pattern (a web page load, a voice call, a file
// transfer each have a recognizable shape). SHAIP-SHAPE/1 hides that pattern by
// running the real Maybenot framework: probabilistic state machines that decide
// when to inject padding (cover) packets and when to briefly hold real packets,
// reshaping the client's send timing.
//
// Maybenot returns *actions* and leaves the integrator to run the timers and
// feed back the resulting *events* (see the framework docs). [`TrafficShaper`]
// below is that integrator: it owns one Maybenot [`Framework`] plus the
// per-machine action/internal timers and the framework-scoped blocking window.
// It is pure and synchronous — every method takes `now` explicitly — so it is
// fully deterministic and unit-tested here. The async I/O (actually writing a
// cover packet, holding a real packet while blocked) lives in
// [`crate::client::Tunnel`], which drives this with the reporters below and
// [`poll`](TrafficShaper::poll).
//
// This defends the client→server (upstream) timing only. Downstream shaping is
// the server's job and is not yet wired; this is stated honestly in the docs so
// the defence is never overclaimed.

/// Which built-in traffic-shaping defence to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapePreset {
    /// No shaping: packets are sent exactly when the application sends them.
    Off,
    /// Low-overhead gap-filling padding (≤ ~50% padding), no blocking.
    Light,
    /// More padding plus occasional brief blocking to break up bursts (adds a
    /// few ms of latency at times).
    Medium,
}

impl ShapePreset {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "none" | "" => Some(Self::Off),
            "light" => Some(Self::Light),
            "medium" => Some(Self::Medium),
            _ => None,
        }
    }
}

/// A reusable description of a shaping defence: the Maybenot machines plus the
/// framework-wide overhead caps. Cloneable, so one spec can drive every session
/// a link opens — each new session builds its own fresh [`TrafficShaper`]
/// runtime from it.
#[derive(Clone)]
pub struct ShapeSpec {
    pub machines: Vec<Machine>,
    /// Cap on total padding as a fraction of normal packets (framework-wide),
    /// in `[0.0, 1.0]`.
    pub max_padding_frac: f64,
    /// Cap on total blocking time as a fraction of elapsed time (framework-wide),
    /// in `[0.0, 1.0]`.
    pub max_blocking_frac: f64,
}

impl ShapeSpec {
    /// Build the machines and caps for a built-in preset. `Off` yields `None`.
    pub fn preset(p: ShapePreset) -> Option<Self> {
        match p {
            ShapePreset::Off => None,
            ShapePreset::Light => Some(Self {
                machines: vec![padding_machine(5_000.0, 50_000.0, 100)],
                max_padding_frac: 0.5,
                max_blocking_frac: 0.0,
            }),
            ShapePreset::Medium => Some(Self {
                machines: vec![
                    padding_machine(2_000.0, 20_000.0, 200),
                    jitter_block_machine(),
                ],
                max_padding_frac: 1.0,
                max_blocking_frac: 0.5,
            }),
        }
    }

    /// Build a spec from operator-supplied serialized Maybenot machines (the
    /// base64 strings `Machine::serialize` / the maybenot tooling produce) and
    /// explicit caps. This is how a tuned, classifier-specific defence is
    /// deployed without code changes.
    pub fn from_serialized(
        machines: &[String],
        max_padding_frac: f64,
        max_blocking_frac: f64,
    ) -> anyhow::Result<Self> {
        let mut ms = Vec::with_capacity(machines.len());
        for s in machines {
            ms.push(
                Machine::from_str(s)
                    .map_err(|e| anyhow::anyhow!("invalid shaping machine: {e}"))?,
            );
        }
        Ok(Self {
            machines: ms,
            max_padding_frac,
            max_blocking_frac,
        })
    }
}

/// A gap-filling padding machine. When a normal packet is sent it enters a
/// padding state that keeps one padding packet scheduled (timeout sampled
/// uniformly in `[low_us, high_us]`) and reschedules on every normal or padding
/// packet — so quiet gaps inside an active flow are filled, and padding tapers
/// off once the flow goes idle. `allowed` is the free padding budget before the
/// framework's `max_padding_frac` cap takes over.
fn padding_machine(low_us: f64, high_us: f64, allowed: u64) -> Machine {
    let boot = MbState::new(enum_map! {
        MbEvent::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut pad = MbState::new(enum_map! {
        MbEvent::NormalSent => vec![Trans(1, 1.0)],
        MbEvent::PaddingSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    pad.action = Some(MbAction::SendPadding {
        bypass: false,
        replace: false,
        timeout: Dist::new(DistType::Uniform { low: low_us, high: high_us }, 0.0, 0.0),
        limit: None,
    });
    // Per-machine max_padding_frac 1.0: let the framework-wide cap govern.
    Machine::new(allowed, 1.0, 0, 0.0, vec![boot, pad]).expect("valid padding machine")
}

/// An occasional blocking machine. A short while after a normal packet is sent
/// it blocks outgoing traffic for a few milliseconds, so real packets are held
/// and then released in a small burst — breaking up fine-grained inter-packet
/// timing. It re-arms after each blocking window. `allowed_blocked_microsec`
/// gives a free budget before the framework's `max_blocking_frac` cap applies.
fn jitter_block_machine() -> Machine {
    let boot = MbState::new(enum_map! {
        MbEvent::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    let mut block = MbState::new(enum_map! {
        MbEvent::BlockingEnd => vec![Trans(1, 1.0)],
        MbEvent::NormalSent => vec![Trans(1, 1.0)],
        _ => vec![],
    });
    block.action = Some(MbAction::BlockOutgoing {
        bypass: false,
        replace: false,
        timeout: Dist::new(DistType::Uniform { low: 10_000.0, high: 60_000.0 }, 0.0, 0.0),
        duration: Dist::new(DistType::Uniform { low: 2_000.0, high: 8_000.0 }, 0.0, 0.0),
        limit: None,
    });
    Machine::new(0, 0.0, 200_000, 1.0, vec![boot, block]).expect("valid block machine")
}

/// What one machine's action timer, once it fires, tells the shaper to do.
#[derive(Clone, Copy)]
enum ScheduledAction {
    None,
    Padding { bypass: bool },
    Block { duration: Duration, bypass: bool, replace: bool },
}

/// The result of advancing the shaper — what the I/O layer must do now.
pub struct ShaperPoll {
    /// Emit this many padding (cover) packets now.
    pub send_padding: u32,
    /// A blocking window ended during this poll: flush any packets queued while
    /// blocked.
    pub blocking_ended: bool,
    /// When to poll again (the soonest pending timer), if any.
    pub wakeup: Option<Instant>,
}

/// SHAIP-SHAPE/1 — the client-side traffic-analysis defence. See the module
/// section header above.
pub struct TrafficShaper {
    fw: Framework<Vec<Machine>, StdRng, Instant>,
    n: usize,
    /// Per-machine action timer (padding / begin-blocking), and what it does.
    action_at: Vec<Option<Instant>>,
    action_kind: Vec<ScheduledAction>,
    /// Per-machine internal timer (fires `TimerEnd`).
    internal_at: Vec<Option<Instant>>,
    /// Framework-scoped blocking window.
    block_until: Option<Instant>,
    block_bypassable: bool,
    /// Honest counters for metrics (no customer data — just totals).
    padding_emitted: u64,
    blocking_windows: u64,
}

enum Due {
    Action(usize),
    Internal(usize),
}

impl TrafficShaper {
    /// Build a shaper for a defence spec, starting its clock at `now`.
    pub fn new(spec: &ShapeSpec, now: Instant) -> anyhow::Result<Self> {
        let machines = spec.machines.clone();
        let n = machines.len();
        // A seedable, Send RNG (ChaCha-based) so the shaper can live behind a
        // mutex shared across the send/recv/driver tasks.
        let rng = StdRng::from_os_rng();
        let fw = Framework::new(machines, spec.max_padding_frac, spec.max_blocking_frac, now, rng)
            .map_err(|e| anyhow::anyhow!("maybenot framework: {e}"))?;
        Ok(Self {
            fw,
            n,
            action_at: vec![None; n],
            action_kind: vec![ScheduledAction::None; n],
            internal_at: vec![None; n],
            block_until: None,
            block_bypassable: false,
            padding_emitted: 0,
            blocking_windows: 0,
        })
    }

    /// Total padding packets this shaper has told the I/O layer to emit.
    pub fn padding_emitted(&self) -> u64 {
        self.padding_emitted
    }

    /// Total blocking windows opened.
    pub fn blocking_windows(&self) -> u64 {
        self.blocking_windows
    }

    // --- event reporters, called by the I/O layer ---

    /// A real (non-padding) packet was queued to send.
    pub fn on_normal_sent(&mut self, now: Instant) {
        self.trigger(vec![TriggerEvent::NormalSent], now);
    }

    /// A packet (any kind) was actually written to the network.
    pub fn on_tunnel_sent(&mut self, now: Instant) {
        self.trigger(vec![TriggerEvent::TunnelSent], now);
    }

    /// A real (non-padding) packet was received.
    pub fn on_normal_recv(&mut self, now: Instant) {
        self.trigger(vec![TriggerEvent::TunnelRecv, TriggerEvent::NormalRecv], now);
    }

    /// A padding packet was received.
    pub fn on_padding_recv(&mut self, now: Instant) {
        self.trigger(vec![TriggerEvent::TunnelRecv, TriggerEvent::PaddingRecv], now);
    }

    /// Is outgoing real traffic currently blocked (so the caller must queue it)?
    pub fn blocking(&self, now: Instant) -> bool {
        self.block_until.map(|u| now < u).unwrap_or(false)
    }

    /// Feed events into the framework and apply the resulting actions to the
    /// timers. Any immediate feedback events (a `TimerBegin` from `UpdateTimer`)
    /// are fed back in a bounded loop so machines settle within one call.
    fn trigger(&mut self, events: Vec<TriggerEvent>, now: Instant) {
        let mut pending = events;
        let mut guard = 0;
        while !pending.is_empty() && guard < 256 {
            guard += 1;
            // Collect the borrowed actions before mutating self's timers.
            let mut actions: Vec<TriggerAction<Instant>> = Vec::new();
            for a in self.fw.trigger_events(&pending, now) {
                actions.push(a.clone());
            }
            pending.clear();
            for a in actions {
                if let Some(ev) = self.apply(a, now) {
                    pending.push(ev);
                }
            }
        }
    }

    /// Apply one action to the timers. Returns a feedback event to re-feed
    /// immediately (only `UpdateTimer` has one: `TimerBegin`); padding/blocking
    /// feedback (`PaddingSent`/`BlockingBegin`) fires later, from [`poll`], when
    /// the action timer actually expires.
    fn apply(&mut self, a: TriggerAction<Instant>, now: Instant) -> Option<TriggerEvent> {
        match a {
            TriggerAction::Cancel { machine, timer } => {
                let i = machine.into_raw();
                match timer {
                    MbTimer::Action => {
                        self.action_at[i] = None;
                        self.action_kind[i] = ScheduledAction::None;
                    }
                    MbTimer::Internal => self.internal_at[i] = None,
                    MbTimer::All => {
                        self.action_at[i] = None;
                        self.action_kind[i] = ScheduledAction::None;
                        self.internal_at[i] = None;
                    }
                }
                None
            }
            TriggerAction::SendPadding { timeout, bypass, replace: _, machine } => {
                let i = machine.into_raw();
                self.action_at[i] = Some(now + timeout);
                self.action_kind[i] = ScheduledAction::Padding { bypass };
                None
            }
            TriggerAction::BlockOutgoing { timeout, duration, bypass, replace, machine } => {
                let i = machine.into_raw();
                self.action_at[i] = Some(now + timeout);
                self.action_kind[i] = ScheduledAction::Block { duration, bypass, replace };
                None
            }
            TriggerAction::UpdateTimer { duration, replace, machine } => {
                let i = machine.into_raw();
                let target = now + duration;
                // replace=false keeps the longest of remaining/specified.
                self.internal_at[i] = Some(match (self.internal_at[i], replace) {
                    (Some(cur), false) => cur.max(target),
                    _ => target,
                });
                Some(TriggerEvent::TimerBegin { machine })
            }
        }
    }

    /// Advance all timers that are due at `now`, performing their effects
    /// (counting padding to emit, opening/closing blocking windows) and feeding
    /// the resulting events back into the framework. Returns what the I/O layer
    /// must do now and when to poll next.
    pub fn poll(&mut self, now: Instant) -> ShaperPoll {
        let mut send_padding = 0u32;
        let mut blocking_ended = false;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 4096 {
                break; // safety net against a pathological machine
            }

            // 1. Framework-scoped blocking window expiry.
            if let Some(until) = self.block_until {
                if now >= until {
                    self.block_until = None;
                    self.block_bypassable = false;
                    blocking_ended = true;
                    self.trigger(vec![TriggerEvent::BlockingEnd], now);
                    continue;
                }
            }

            // 2. Earliest due action/internal timer across machines.
            let mut best: Option<(Instant, Due)> = None;
            for i in 0..self.n {
                if let Some(at) = self.action_at[i] {
                    if at <= now && best.as_ref().map(|(t, _)| at < *t).unwrap_or(true) {
                        best = Some((at, Due::Action(i)));
                    }
                }
                if let Some(at) = self.internal_at[i] {
                    if at <= now && best.as_ref().map(|(t, _)| at < *t).unwrap_or(true) {
                        best = Some((at, Due::Internal(i)));
                    }
                }
            }
            let Some((_, due)) = best else { break };

            match due {
                Due::Action(i) => {
                    let kind = self.action_kind[i];
                    self.action_at[i] = None;
                    self.action_kind[i] = ScheduledAction::None;
                    match kind {
                        ScheduledAction::Padding { bypass } => {
                            if self.can_emit_padding(bypass, now) {
                                send_padding += 1;
                                self.padding_emitted += 1;
                            }
                            // PaddingSent is reported regardless (spec), so the
                            // machine advances and accounting stays correct.
                            self.trigger(
                                vec![TriggerEvent::PaddingSent { machine: MachineId::from_raw(i) }],
                                now,
                            );
                        }
                        ScheduledAction::Block { duration, bypass, replace } => {
                            let target = now + duration;
                            let was_blocking =
                                self.block_until.map(|u| now < u).unwrap_or(false);
                            self.block_until = Some(match (self.block_until, replace) {
                                (Some(cur), false) => cur.max(target), // longest
                                _ => target,                           // replace / fresh
                            });
                            self.block_bypassable = bypass;
                            if !was_blocking {
                                self.blocking_windows += 1;
                            }
                            self.trigger(
                                vec![TriggerEvent::BlockingBegin { machine: MachineId::from_raw(i) }],
                                now,
                            );
                        }
                        ScheduledAction::None => {}
                    }
                }
                Due::Internal(i) => {
                    self.internal_at[i] = None;
                    self.trigger(
                        vec![TriggerEvent::TimerEnd { machine: MachineId::from_raw(i) }],
                        now,
                    );
                }
            }
        }

        // Next wakeup: the soonest remaining timer or the blocking expiry.
        let mut wakeup: Option<Instant> = self.block_until;
        for i in 0..self.n {
            for at in [self.action_at[i], self.internal_at[i]].into_iter().flatten() {
                wakeup = Some(wakeup.map(|w| w.min(at)).unwrap_or(at));
            }
        }
        ShaperPoll { send_padding, blocking_ended, wakeup }
    }

    /// Whether a padding packet may physically go out now. During a blocking
    /// window it may only if the blocking is bypassable and the padding has the
    /// bypass flag; otherwise it is dropped (conservatively: less padding, never
    /// a leak), while `PaddingSent` is still reported so accounting is correct.
    fn can_emit_padding(&self, bypass: bool, now: Instant) -> bool {
        match self.block_until {
            Some(until) if now < until => self.block_bypassable && bypass,
            _ => true,
        }
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

    // --- SHAIP-SHAPE/1 traffic-analysis defence -----------------------------

    #[test]
    fn shape_preset_parsing() {
        assert_eq!(ShapePreset::parse("off"), Some(ShapePreset::Off));
        assert_eq!(ShapePreset::parse("none"), Some(ShapePreset::Off));
        assert_eq!(ShapePreset::parse(""), Some(ShapePreset::Off));
        assert_eq!(ShapePreset::parse("Light"), Some(ShapePreset::Light));
        assert_eq!(ShapePreset::parse(" MEDIUM "), Some(ShapePreset::Medium));
        assert_eq!(ShapePreset::parse("bogus"), None);
        assert!(ShapeSpec::preset(ShapePreset::Off).is_none());
        assert!(ShapeSpec::preset(ShapePreset::Light).is_some());
        assert!(ShapeSpec::preset(ShapePreset::Medium).is_some());
    }

    #[test]
    fn shape_light_emits_bounded_padding() {
        let spec = ShapeSpec::preset(ShapePreset::Light).unwrap();
        let t0 = Instant::now();
        let mut sh = TrafficShaper::new(&spec, t0).unwrap();
        // One real packet starts the flow; then it goes idle.
        sh.on_normal_sent(t0);
        let mut total = 0u32;
        let mut t = t0;
        for _ in 0..2_000 {
            t += Duration::from_millis(5); // 10 s of simulated time
            total += sh.poll(t).send_padding;
        }
        assert!(total >= 1, "light shaping must emit some padding after a send");
        // Bounded by the free budget (100) plus the fraction cap; never runaway.
        assert!(total <= 130, "padding must stay bounded, got {total}");
        assert_eq!(u64::from(total), sh.padding_emitted());
    }

    #[test]
    fn shape_padding_fraction_is_capped_under_load() {
        // Drive a steady stream of normal packets and confirm padding does not
        // exceed roughly budget + max_padding_frac * normals (+ slack).
        let spec = ShapeSpec::preset(ShapePreset::Light).unwrap(); // frac 0.5, budget 100
        let t0 = Instant::now();
        let mut sh = TrafficShaper::new(&spec, t0).unwrap();
        let mut t = t0;
        let mut normals = 0u64;
        for _ in 0..4_000 {
            t += Duration::from_millis(5); // 20 s
                                           // ~20 normal packets/second.
            if normals < 400 {
                sh.on_normal_sent(t);
                normals += 1;
            }
            sh.poll(t);
        }
        // Maybenot caps padding as a fraction of *total* packets:
        // padding / (padding + normal) < max_padding_frac. With the light
        // preset's 0.5 cap (and the small free budget long since spent at this
        // volume), the realized fraction must sit at or just under 0.5.
        let padding = sh.padding_emitted();
        let frac = padding as f64 / (padding + normals) as f64;
        assert!(
            frac <= 0.5 + 0.05,
            "padding fraction {frac:.3} exceeded the 0.5 cap (padding {padding}, normals {normals})"
        );
        assert!(padding > 0, "shaping should have emitted padding under load");
    }

    #[test]
    fn shape_medium_blocks_and_releases() {
        let spec = ShapeSpec::preset(ShapePreset::Medium).unwrap();
        let t0 = Instant::now();
        let mut sh = TrafficShaper::new(&spec, t0).unwrap();
        sh.on_normal_sent(t0);
        let mut saw_end = false;
        let mut t = t0;
        for _ in 0..4_000 {
            t += Duration::from_millis(5); // 20 s
            if sh.poll(t).blocking_ended {
                saw_end = true;
            }
        }
        assert!(sh.blocking_windows() >= 1, "medium shaping must open a blocking window");
        assert!(saw_end, "and must report the window ending so the queue is flushed");
    }

    #[test]
    fn shape_from_serialized_roundtrips_and_rejects_garbage() {
        let m = padding_machine(5_000.0, 5_000.0, 10);
        let serialized = m.serialize();
        let spec = ShapeSpec::from_serialized(&[serialized], 0.3, 0.0).unwrap();
        assert_eq!(spec.machines.len(), 1);
        TrafficShaper::new(&spec, Instant::now()).unwrap();
        assert!(ShapeSpec::from_serialized(&["not-a-machine".to_string()], 0.1, 0.0).is_err());
    }

    #[test]
    fn shape_off_equivalent_empty_spec_is_inert() {
        // A spec with no machines produces no actions at all.
        let spec = ShapeSpec { machines: vec![], max_padding_frac: 0.0, max_blocking_frac: 0.0 };
        let t0 = Instant::now();
        let mut sh = TrafficShaper::new(&spec, t0).unwrap();
        sh.on_normal_sent(t0);
        let mut t = t0;
        for _ in 0..200 {
            t += Duration::from_millis(5);
            let p = sh.poll(t);
            assert_eq!(p.send_padding, 0);
            assert!(!sh.blocking(t));
        }
        assert_eq!(sh.padding_emitted(), 0);
    }
}
