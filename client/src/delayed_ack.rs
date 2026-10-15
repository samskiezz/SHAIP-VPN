//! Delayed-ACK policy (§8.2): ACK immediately after N packets or when the
//! max delay elapses, whichever comes first.

use std::time::{Duration, Instant};

pub struct DelayedAck {
    last_recv: Option<Instant>,
    pending: u32,
    max_delay: Duration,
    ack_every: u32,
}

impl DelayedAck {
    pub fn new(max_delay_ms: u64, ack_every: u32) -> Self {
        Self {
            last_recv: None,
            pending: 0,
            max_delay: Duration::from_millis(max_delay_ms),
            ack_every,
        }
    }

    /// Call on each received packet. Returns true if an ACK should be sent now.
    pub fn on_receive(&mut self) -> bool {
        let now = Instant::now();
        self.pending += 1;
        let force = self.pending >= self.ack_every;
        let expired = self
            .last_recv
            .map(|t| now.duration_since(t) >= self.max_delay)
            .unwrap_or(false);
        if force || expired {
            self.pending = 0;
            self.last_recv = Some(now);
            true
        } else {
            if self.last_recv.is_none() {
                self.last_recv = Some(now);
            }
            false
        }
    }

    pub fn flush(&mut self) {
        self.pending = 0;
        self.last_recv = Some(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acks_every_n() {
        let mut d = DelayedAck::new(100, 2);
        assert!(!d.on_receive());
        assert!(d.on_receive()); // 2nd packet forces ACK
    }
}
