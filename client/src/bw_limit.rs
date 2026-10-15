//! Token-bucket bandwidth limiter for a server (per-direction).

use std::time::Instant;

pub struct ServerBwLimit {
    bytes_per_sec_in: f64,
    bytes_per_sec_out: f64,
    in_tokens: f64,
    out_tokens: f64,
    last: Instant,
}

impl ServerBwLimit {
    pub fn new(mbps_in: u64, mbps_out: u64) -> Self {
        let bin = (mbps_in * 125_000) as f64;
        let bout = (mbps_out * 125_000) as f64;
        Self { bytes_per_sec_in: bin, bytes_per_sec_out: bout, in_tokens: bin, out_tokens: bout, last: Instant::now() }
    }
    fn refill(&mut self) {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.in_tokens = (self.in_tokens + self.bytes_per_sec_in * dt).min(self.bytes_per_sec_in);
        self.out_tokens = (self.out_tokens + self.bytes_per_sec_out * dt).min(self.bytes_per_sec_out);
    }
    pub fn allow_in(&mut self, bytes: u64) -> bool {
        self.refill();
        if self.in_tokens >= bytes as f64 { self.in_tokens -= bytes as f64; true } else { false }
    }
    pub fn allow_out(&mut self, bytes: u64) -> bool {
        self.refill();
        if self.out_tokens >= bytes as f64 { self.out_tokens -= bytes as f64; true } else { false }
    }
}
