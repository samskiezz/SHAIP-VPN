//! Exponential backoff with jitter for client reconnection.

use std::time::Duration;

pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
    jitter_frac: f64,
}

impl Backoff {
    pub fn new(base_ms: u64, max_ms: u64) -> Self {
        Self {
            base: Duration::from_millis(base_ms),
            max: Duration::from_millis(max_ms),
            attempt: 0,
            jitter_frac: 0.2,
        }
    }

    /// Next backoff delay (named `next_delay`, not `next`, to avoid the
    /// `Iterator::next` lint).
    pub fn next_delay(&mut self) -> Duration {
        self.attempt = self.attempt.saturating_add(1);
        let exp = 2u32.saturating_pow(self.attempt.saturating_sub(1).min(10));
        let capped = self.base.saturating_mul(exp).min(self.max);
        let jitter =
            (capped.as_millis() as f64 * self.jitter_frac * rand::random::<f64>()) as u64;
        capped + Duration::from_millis(jitter)
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_within_bounds() {
        let mut b = Backoff::new(100, 3000);
        for _ in 0..20 {
            let d = b.next_delay();
            assert!(d >= Duration::from_millis(100));
            assert!(d <= Duration::from_millis(3600)); // cap + max 20% jitter
        }
        b.reset();
        assert!(b.next_delay() <= Duration::from_millis(120));
    }
}
