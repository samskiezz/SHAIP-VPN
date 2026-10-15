//! Session QoS classes (interactive / bulk / best-effort).

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Interactive,
    Bulk,
    BestEffort,
}

#[derive(Debug, Clone, Copy)]
pub struct QosParams {
    pub max_latency: Duration,
    pub pacing_cap_bps: u64,
    pub priority: u8,
}

impl QosParams {
    pub fn for_class(c: Class) -> Self {
        match c {
            Class::Interactive => QosParams { max_latency: Duration::from_millis(50), pacing_cap_bps: 10_000_000, priority: 0 },
            Class::Bulk => QosParams { max_latency: Duration::from_secs(2), pacing_cap_bps: 100_000_000, priority: 10 },
            Class::BestEffort => QosParams { max_latency: Duration::from_secs(5), pacing_cap_bps: 50_000_000, priority: 20 },
        }
    }
}

/// Small payloads + low gaps = interactive; large payloads = bulk.
pub fn classify(avg_payload: usize, avg_gap_ms: u64) -> Class {
    if avg_payload < 256 && avg_gap_ms < 200 {
        Class::Interactive
    } else if avg_payload > 1000 {
        Class::Bulk
    } else {
        Class::BestEffort
    }
}
