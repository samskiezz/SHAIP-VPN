//! Pacing budget: converts a target rate into bytes-allowed-per-tick.

use std::time::{Duration, Instant};

pub struct PacingBudget {
    rate_bps: f64,
    tick: Duration,
    accumulated: f64,
    last: Instant,
}

impl PacingBudget {
    pub fn new(rate_bps: f64, tick_ms: u64) -> Self {
        let tick = Duration::from_millis(tick_ms);
        Self { rate_bps, tick, accumulated: rate_bps * tick.as_secs_f64(), last: Instant::now() }
    }
    pub fn set_rate(&mut self, rate_bps: f64) { self.rate_bps = rate_bps.max(0.0); }
    /// Max bytes allowed since the last call (one `max_packet` at a time).
    pub fn take(&mut self, max_packet: usize) -> usize {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.accumulated += self.rate_bps * dt;
        let cap = (self.rate_bps * self.tick.as_secs_f64() * 2.0).max(max_packet as f64);
        if self.accumulated > cap {
            self.accumulated = cap;
        }
        if self.accumulated < max_packet as f64 {
            return 0;
        }
        self.accumulated -= max_packet as f64;
        max_packet
    }
    pub fn pending(&self) -> f64 { self.accumulated }
}
