//! Per-IP connection rate limiter (sliding 1-second window).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct ConnRate {
    window: Duration,
    max_per_window: usize,
    events: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

impl ConnRate {
    pub fn new(max_per_sec: usize) -> Self {
        Self {
            window: Duration::from_secs(1),
            max_per_window: max_per_sec,
            events: Mutex::new(HashMap::new()),
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut m = self.events.lock().unwrap();
        let q = m.entry(ip).or_default();
        while let Some(front) = q.front() {
            if now.duration_since(*front) > self.window {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() >= self.max_per_window {
            return false;
        }
        q.push_back(now);
        true
    }
}
