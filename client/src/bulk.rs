//! Bulk-transfer detector: flags sustained high-rate flows so the client can
//! widen cwnd and suppress competing probe traffic.

use std::time::{Duration, Instant};

pub struct BulkDetector {
    window_start: Instant,
    window_bytes: u64,
    window: Duration,
    threshold_bps: u64,
    confirmed: bool,
}

impl BulkDetector {
    pub fn new(threshold_bps: u64) -> Self {
        Self {
            window_start: Instant::now(),
            window_bytes: 0,
            window: Duration::from_secs(1),
            threshold_bps,
            confirmed: false,
        }
    }
    pub fn record(&mut self, bytes: u64) {
        let now = Instant::now();
        if now.duration_since(self.window_start) > self.window {
            let elapsed = now.duration_since(self.window_start).as_secs_f64();
            let rate = (self.window_bytes as f64 / elapsed) as u64;
            self.confirmed = rate > self.threshold_bps;
            self.window_start = now;
            self.window_bytes = 0;
        }
        self.window_bytes += bytes;
    }
    pub fn is_bulk(&self) -> bool { self.confirmed }
}
