//! Per-identity bandwidth quota over a rolling period (server-side).

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct Quota {
    pub bytes_per_period: u64,
    pub period: Duration,
}

pub struct QuotaTracker {
    quota: Quota,
    usage: HashMap<String, (u64, Instant)>,
}

impl QuotaTracker {
    pub fn new(quota: Quota) -> Self {
        Self { quota, usage: HashMap::new() }
    }

    /// Record usage; returns remaining bytes in the current period.
    pub fn record(&mut self, identity: &str, bytes: u64) -> u64 {
        let now = Instant::now();
        let entry = self.usage.entry(identity.into()).or_insert((0, now));
        if now.duration_since(entry.1) > self.quota.period {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(bytes);
        self.quota.bytes_per_period.saturating_sub(entry.0)
    }

    pub fn remaining(&self, identity: &str) -> u64 {
        let now = Instant::now();
        match self.usage.get(identity) {
            Some((used, start)) if now.duration_since(*start) <= self.quota.period => {
                self.quota.bytes_per_period.saturating_sub(*used)
            }
            _ => self.quota.bytes_per_period,
        }
    }

    pub fn exceeded(&self, identity: &str) -> bool {
        self.remaining(identity) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tracks_usage() {
        let mut t = QuotaTracker::new(Quota { bytes_per_period: 1000, period: Duration::from_secs(3600) });
        assert_eq!(t.remaining("a"), 1000);
        assert_eq!(t.record("a", 400), 600);
        assert!(!t.exceeded("a"));
        t.record("a", 700);
        assert!(t.exceeded("a"));
    }
}
