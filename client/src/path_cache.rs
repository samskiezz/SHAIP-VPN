//! Per-destination path characteristics cache (RTT, MTU, loss).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub struct PathChars {
    pub rtt: Duration,
    pub mtu: u16,
    pub loss_rate: f64,
    pub last_update: Instant,
}

pub struct PathCache {
    entries: HashMap<IpAddr, PathChars>,
    ttl: Duration,
}

impl PathCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self { entries: HashMap::new(), ttl: Duration::from_secs(ttl_secs) }
    }
    pub fn get(&self, dst: IpAddr) -> Option<PathChars> {
        let e = self.entries.get(&dst)?;
        if Instant::now().duration_since(e.last_update) > self.ttl {
            return None;
        }
        Some(*e)
    }
    pub fn update_rtt(&mut self, dst: IpAddr, rtt: Duration) {
        let e = self.entries.entry(dst).or_insert(PathChars {
            rtt, mtu: 1400, loss_rate: 0.0, last_update: Instant::now(),
        });
        e.rtt = e.rtt.mul_f64(0.875) + rtt.mul_f64(0.125);
        e.last_update = Instant::now();
    }
    pub fn update_mtu(&mut self, dst: IpAddr, mtu: u16) {
        let e = self.entries.entry(dst).or_insert(PathChars {
            rtt: Duration::from_millis(100), mtu, loss_rate: 0.0, last_update: Instant::now(),
        });
        e.mtu = mtu;
        e.last_update = Instant::now();
    }
}
