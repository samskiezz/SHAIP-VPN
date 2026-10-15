//! Session idle detector: drives keepalive probing and eviction.

use std::time::{Duration, Instant};

pub struct IdleDetector {
    last_activity: Instant,
    idle_threshold: Duration,
    probe_threshold: Duration,
}

impl IdleDetector {
    pub fn new(idle_secs: u64, probe_secs: u64) -> Self {
        Self {
            last_activity: Instant::now(),
            idle_threshold: Duration::from_secs(idle_secs),
            probe_threshold: Duration::from_secs(probe_secs),
        }
    }
    pub fn touch(&mut self) { self.last_activity = Instant::now(); }
    pub fn is_idle(&self) -> bool {
        Instant::now().duration_since(self.last_activity) > self.idle_threshold
    }
    pub fn should_probe(&self) -> bool {
        let idle = Instant::now().duration_since(self.last_activity);
        idle > self.probe_threshold && idle <= self.idle_threshold
    }
    pub fn idle_for(&self) -> Duration {
        Instant::now().duration_since(self.last_activity)
    }
}
