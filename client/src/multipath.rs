//! SHAIP-MP/1 — multipath scheduling and reassembly for the tunnel.
//!
//! A phone often has two ways to the internet at once (Wi-Fi and cellular); a
//! server often has more than one address. Multipath lets one tunnel ride over
//! several network paths at the same time: for resilience (a path dies and the
//! flow keeps going over the other) and, when wanted, for throughput (spread the
//! load) or latency (duplicate a few packets on the fastest paths).
//!
//! This is the transport-agnostic core of that: a [`PathScheduler`] that tracks
//! each path's health and picks where to send, and a [`Reorderer`] that puts the
//! single logical stream back in order after packets arrive out of order across
//! paths with different latencies. Both are pure and deterministic — every method
//! takes `now` explicitly — so they are fully unit-tested here. The live wiring
//! (one UDP socket per path, binding paths to interfaces, migrating on failure)
//! is layered on top; it sits beneath [`crate::supervisor::ManagedTunnel`] so the
//! rest of the stack is unaware there is more than one path.
//!
//! This is a native scheduler over SHAIP's own transport rather than a second
//! QUIC stack (`tquic`): SHAIP already has reliability, pacing and BBR-style
//! congestion control, so multipath here is path *selection and reassembly*, not
//! a competing transport. A full multipath-QUIC carrier remains an option if full
//! QUIC semantics are ever wanted.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Identifies one network path (e.g. Wi-Fi vs cellular, or two server addresses).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathId(pub u32);

/// Health of one path: a smoothed RTT and a smoothed loss fraction, plus whether
/// it is currently usable.
#[derive(Clone, Copy, Debug)]
struct PathStats {
    srtt: Duration,
    loss: f64, // EWMA in [0,1]
    up: bool,
    last_sent: Option<Instant>,
}

impl Default for PathStats {
    fn default() -> Self {
        Self {
            srtt: Duration::from_millis(100),
            loss: 0.0,
            up: true,
            last_sent: None,
        }
    }
}

/// How to choose among healthy paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Send on the single healthy path with the best score (lowest latency,
    /// adjusted for loss). Resilient and simple.
    LowestLatency,
    /// Spread sends across healthy paths in proportion to their quality (higher
    /// quality → chosen more often). Aggregates throughput.
    Proportional,
}

/// Tracks the paths of one tunnel and decides where each packet goes.
pub struct PathScheduler {
    paths: BTreeMap<PathId, PathStats>,
    rr: u64, // round-robin cursor for Proportional
}

impl PathScheduler {
    pub fn new() -> Self {
        Self {
            paths: BTreeMap::new(),
            rr: 0,
        }
    }

    pub fn add_path(&mut self, id: PathId) {
        self.paths.entry(id).or_default();
    }

    pub fn remove_path(&mut self, id: PathId) {
        self.paths.remove(&id);
    }

    pub fn set_up(&mut self, id: PathId, up: bool) {
        if let Some(p) = self.paths.get_mut(&id) {
            p.up = up;
        }
    }

    /// Record a round-trip sample for a path (EWMA, α = 1/8).
    pub fn on_rtt(&mut self, id: PathId, rtt: Duration) {
        if let Some(p) = self.paths.get_mut(&id) {
            let s = p.srtt.as_secs_f64();
            let r = rtt.as_secs_f64();
            p.srtt = Duration::from_secs_f64(s * 0.875 + r * 0.125);
            // A delivered packet nudges the loss estimate down.
            p.loss = (p.loss * 0.95).max(0.0);
            p.up = true;
        }
    }

    /// Record a loss on a path (EWMA toward 1.0). Enough loss marks it down.
    pub fn on_loss(&mut self, id: PathId) {
        if let Some(p) = self.paths.get_mut(&id) {
            p.loss = (p.loss * 0.95 + 0.05).min(1.0);
            if p.loss > 0.6 {
                p.up = false; // too lossy to rely on; scheduler will avoid it
            }
        }
    }

    /// A lower score is a better path: latency inflated by its loss.
    fn score(p: &PathStats) -> f64 {
        p.srtt.as_secs_f64() * (1.0 + 4.0 * p.loss)
    }

    fn healthy(&self) -> Vec<(PathId, f64)> {
        self.paths
            .iter()
            .filter(|(_, p)| p.up)
            .map(|(id, p)| (*id, Self::score(p)))
            .collect()
    }

    /// Choose a path for the next packet under `policy`. `None` only when every
    /// path is down (the caller then holds or drops, as it would offline).
    pub fn select(&mut self, policy: Policy, now: Instant) -> Option<PathId> {
        let healthy = self.healthy();
        if healthy.is_empty() {
            return None;
        }
        let chosen = match policy {
            Policy::LowestLatency => {
                healthy
                    .iter()
                    .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(id, _)| *id)
                    .unwrap()
            }
            Policy::Proportional => {
                // Weight each path by inverse score; pick via a cursor so the
                // long-run share matches the weights (deterministic, testable).
                let weights: Vec<(PathId, f64)> =
                    healthy.iter().map(|(id, s)| (*id, 1.0 / s.max(1e-9))).collect();
                let total: f64 = weights.iter().map(|(_, w)| w).sum();
                // Map the cursor into [0,total) at a fixed granularity.
                let step = total / 1000.0;
                let point = (self.rr as f64 * step) % total;
                self.rr = self.rr.wrapping_add(1);
                let mut acc = 0.0;
                let mut pick = weights[0].0;
                for (id, w) in &weights {
                    acc += w;
                    if point < acc {
                        pick = *id;
                        break;
                    }
                }
                pick
            }
        };
        if let Some(p) = self.paths.get_mut(&chosen) {
            p.last_sent = Some(now);
        }
        Some(chosen)
    }

    /// The best few healthy paths, for duplicating a packet under loss (e.g. to
    /// cut tail latency on a critical datagram). Returns up to `k` path ids,
    /// best first.
    pub fn select_redundant(&self, k: usize) -> Vec<PathId> {
        let mut h = self.healthy();
        h.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        h.into_iter().take(k).map(|(id, _)| id).collect()
    }

    /// Whether any path is currently usable.
    pub fn any_up(&self) -> bool {
        self.paths.values().any(|p| p.up)
    }
}

impl Default for PathScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Reassembles one in-order stream from packets that arrived out of order across
/// paths. Each packet carries a monotonic sequence number; the reorderer releases
/// the longest in-order run it has, and — so a lost packet on one path can't stall
/// the stream forever — skips a gap that stays unfilled past a timeout.
pub struct Reorderer {
    next: u64,
    buffer: BTreeMap<u64, Vec<u8>>,
    gap_since: Option<Instant>,
    gap_timeout: Duration,
    /// Highest sequence seen, to size the gap wait and drop ancient duplicates.
    highest: u64,
}

impl Reorderer {
    /// `gap_timeout` bounds head-of-line blocking: a missing packet is given up
    /// on after this long and the stream advances past it.
    pub fn new(gap_timeout: Duration) -> Self {
        Self {
            next: 0,
            buffer: BTreeMap::new(),
            gap_since: None,
            gap_timeout,
            highest: 0,
        }
    }

    /// Accept a packet; return any packets that are now deliverable, in order.
    pub fn push(&mut self, seq: u64, payload: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
        if seq < self.next {
            return Vec::new(); // already delivered (a cross-path duplicate)
        }
        self.highest = self.highest.max(seq);
        self.buffer.entry(seq).or_insert(payload);
        self.drain(now)
    }

    /// Release packets past a gap that has been open too long, then any run that
    /// has since become contiguous. Call it on a timer when no packet arrives.
    pub fn poll(&mut self, now: Instant) -> Vec<Vec<u8>> {
        if self.buffer.is_empty() {
            self.gap_since = None;
            return Vec::new();
        }
        if let Some(since) = self.gap_since {
            if now.duration_since(since) >= self.gap_timeout {
                // Give up on the missing packet: jump to the next buffered seq.
                if let Some((&first, _)) = self.buffer.iter().next() {
                    self.next = first;
                    self.gap_since = None;
                }
            }
        }
        self.drain(now)
    }

    /// Deliver the contiguous run starting at `next`, updating the gap clock.
    fn drain(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(payload) = self.buffer.remove(&self.next) {
            out.push(payload);
            self.next += 1;
        }
        // After draining, is there still a gap (buffered packets ahead of next)?
        if self.buffer.is_empty() {
            self.gap_since = None;
        } else if self.gap_since.is_none() {
            self.gap_since = Some(now);
        }
        out
    }

    /// Packets held waiting for an earlier one.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn scheduler_prefers_the_better_path_and_fails_over() {
        let mut s = PathScheduler::new();
        let (wifi, cell) = (PathId(1), PathId(2));
        s.add_path(wifi);
        s.add_path(cell);
        // Wi-Fi is faster.
        for _ in 0..10 {
            s.on_rtt(wifi, Duration::from_millis(20));
            s.on_rtt(cell, Duration::from_millis(80));
        }
        assert_eq!(s.select(Policy::LowestLatency, t0()), Some(wifi), "pick the faster path");

        // Wi-Fi starts losing badly → it is marked down and traffic fails over.
        for _ in 0..40 {
            s.on_loss(wifi);
        }
        assert_eq!(
            s.select(Policy::LowestLatency, t0()),
            Some(cell),
            "fail over to cellular when Wi-Fi degrades"
        );
    }

    #[test]
    fn all_paths_down_selects_nothing() {
        let mut s = PathScheduler::new();
        s.add_path(PathId(1));
        s.set_up(PathId(1), false);
        assert_eq!(s.select(Policy::LowestLatency, t0()), None);
        assert!(!s.any_up());
    }

    #[test]
    fn proportional_spreads_but_favors_quality() {
        let mut s = PathScheduler::new();
        let (fast, slow) = (PathId(1), PathId(2));
        s.add_path(fast);
        s.add_path(slow);
        for _ in 0..10 {
            s.on_rtt(fast, Duration::from_millis(20));
            s.on_rtt(slow, Duration::from_millis(60));
        }
        let mut n_fast = 0;
        let now = t0();
        for _ in 0..1000 {
            if s.select(Policy::Proportional, now) == Some(fast) {
                n_fast += 1;
            }
        }
        // Both paths are used, and the faster one more (≈3:1 by inverse-latency).
        assert!(n_fast > 550 && n_fast < 900, "fast path share was {n_fast}/1000");
    }

    #[test]
    fn redundant_returns_best_first() {
        let mut s = PathScheduler::new();
        for (i, rtt) in [(1u32, 50u64), (2, 20), (3, 90)] {
            let id = PathId(i);
            s.add_path(id);
            for _ in 0..10 {
                s.on_rtt(id, Duration::from_millis(rtt));
            }
        }
        let top2 = s.select_redundant(2);
        assert_eq!(top2, vec![PathId(2), PathId(1)], "best two paths, fastest first");
    }

    #[test]
    fn reorderer_delivers_in_order_despite_cross_path_shuffle() {
        let mut r = Reorderer::new(Duration::from_millis(100));
        let now = t0();
        // Arrive out of order: 0, 2, 1, 3 (as two paths would interleave).
        assert_eq!(r.push(0, vec![0], now), vec![vec![0]]);
        assert_eq!(r.push(2, vec![2], now), Vec::<Vec<u8>>::new()); // held, waiting for 1
        assert_eq!(r.buffered(), 1);
        assert_eq!(r.push(1, vec![1], now), vec![vec![1], vec![2]]); // 1 fills the gap, 2 follows
        assert_eq!(r.push(3, vec![3], now), vec![vec![3]]);
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn reorderer_drops_cross_path_duplicates() {
        let mut r = Reorderer::new(Duration::from_millis(100));
        let now = t0();
        assert_eq!(r.push(0, vec![0], now), vec![vec![0]]);
        // The same packet arrives again on the other path.
        assert_eq!(r.push(0, vec![0], now), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn reorderer_skips_a_timed_out_gap() {
        let mut r = Reorderer::new(Duration::from_millis(50));
        let start = t0();
        // Packet 0 is lost; 1 and 2 arrive and must wait for 0.
        assert_eq!(r.push(1, vec![1], start), Vec::<Vec<u8>>::new());
        assert_eq!(r.push(2, vec![2], start), Vec::<Vec<u8>>::new());
        assert_eq!(r.buffered(), 2);
        // Before the timeout: still blocked.
        let early = start + Duration::from_millis(10);
        assert_eq!(r.poll(early), Vec::<Vec<u8>>::new());
        // After the timeout: give up on 0, release 1 and 2 in order.
        let late = start + Duration::from_millis(60);
        assert_eq!(r.poll(late), vec![vec![1], vec![2]]);
        assert_eq!(r.buffered(), 0);
    }
}
