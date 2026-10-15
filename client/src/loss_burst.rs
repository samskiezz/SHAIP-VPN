//! Loss-burst detector over a sliding time window.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

pub struct LossBurstDetector {
    recent: VecDeque<(Instant, bool)>,
    window: Duration,
    burst_threshold: usize,
}

impl LossBurstDetector {
    pub fn new(window_secs: u64, burst_threshold: usize) -> Self {
        Self { recent: VecDeque::new(), window: Duration::from_secs(window_secs), burst_threshold }
    }
    pub fn record(&mut self, loss: bool) {
        let now = Instant::now();
        self.recent.push_back((now, loss));
        self.recent.retain(|(t, _)| now.duration_since(*t) <= self.window);
    }
    pub fn in_burst(&self) -> bool {
        self.recent.iter().filter(|(_, l)| *l).count() >= self.burst_threshold
    }
    pub fn loss_rate(&self) -> f64 {
        if self.recent.is_empty() {
            return 0.0;
        }
        self.recent.iter().filter(|(_, l)| *l).count() as f64 / self.recent.len() as f64
    }
}
