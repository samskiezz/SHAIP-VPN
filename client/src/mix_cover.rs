//! Poisson arrival sampling for mix-layer cover traffic (§10.4).
//!
//! Cover traffic at a mix node is **globally scheduled**: the node emits cover
//! cells as one Poisson process at a network-wide target rate, decoupled from
//! how many clients it is serving or how active they are. A per-client cover
//! rate would leak the client count and activity in the aggregate; a single
//! global process does not — the observable emission rate is constant whether
//! one client or a thousand are connected, and whether they are idle or busy.

use rand::Rng;

/// Milliseconds until the next cover cell, for a target rate (cells/sec).
pub fn next_arrival_ms(rate_cells_per_sec: f64) -> u64 {
    if rate_cells_per_sec <= 0.0 {
        return 1000;
    }
    let u: f64 = rand::thread_rng().gen_range(f64::MIN_POSITIVE..1.0);
    ((-u.ln() / rate_cells_per_sec) * 1000.0) as u64
}

/// A node-wide cover-traffic scheduler. It drives a single Poisson emission
/// process at `target_rate` cells/sec, independent of client count or activity.
///
/// The daemon advances it with [`tick`](GlobalCoverScheduler::tick) on a fixed
/// timer; each call returns how many cover cells to emit in the elapsed slice.
pub struct GlobalCoverScheduler {
    target_rate: f64,
    clock_ms: u64,
    next_due_ms: u64,
}

impl GlobalCoverScheduler {
    /// Create a scheduler emitting at `target_rate` cells/sec network-wide.
    pub fn new(target_rate: f64) -> Self {
        let next_due_ms = next_arrival_ms(target_rate).max(1);
        Self {
            target_rate,
            clock_ms: 0,
            next_due_ms,
        }
    }

    /// Advance the clock by `elapsed_ms` and return how many cover cells are due
    /// now. The count depends only on elapsed time and the global rate — never
    /// on client state — so the aggregate emission is indistinguishable from an
    /// idle node's.
    pub fn tick(&mut self, elapsed_ms: u64) -> u32 {
        self.clock_ms = self.clock_ms.saturating_add(elapsed_ms);
        let mut emit = 0u32;
        while self.clock_ms >= self.next_due_ms {
            emit = emit.saturating_add(1);
            self.next_due_ms = self
                .next_due_ms
                .saturating_add(next_arrival_ms(self.target_rate).max(1));
        }
        emit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_matches_rate() {
        let n = 20_000u64;
        let total: u64 = (0..n).map(|_| next_arrival_ms(2.0)).sum();
        let mean = total as f64 / n as f64;
        // Expected mean interval = 500 ms; allow generous slack.
        assert!((400.0..600.0).contains(&mean), "mean was {mean}");
    }

    #[test]
    fn global_schedule_matches_target_rate() {
        // Emit at 50 cells/sec for 60 simulated seconds, advancing 10 ms a tick.
        let mut sched = GlobalCoverScheduler::new(50.0);
        let mut emitted = 0u64;
        for _ in 0..6_000 {
            emitted += sched.tick(10) as u64;
        }
        // Expect ~3000 cells; the Poisson process is loose, so allow slack.
        assert!(
            (2_400..3_600).contains(&emitted),
            "global cover emitted {emitted}, expected ~3000"
        );
    }

    #[test]
    fn global_schedule_is_independent_of_tick_granularity() {
        // The same wall-clock span yields a comparable count whether advanced in
        // coarse or fine slices — emission tracks time, not call frequency.
        let mut coarse = GlobalCoverScheduler::new(20.0);
        let mut fine = GlobalCoverScheduler::new(20.0);
        let mut c = 0u64;
        let mut f = 0u64;
        for _ in 0..600 {
            c += coarse.tick(100) as u64; // 60 s in 100 ms steps
        }
        for _ in 0..6_000 {
            f += fine.tick(10) as u64; // 60 s in 10 ms steps
        }
        // Both target ~1200 cells over 60 s; neither should be wildly off.
        assert!((800..1_600).contains(&c), "coarse emitted {c}");
        assert!((800..1_600).contains(&f), "fine emitted {f}");
    }
}
