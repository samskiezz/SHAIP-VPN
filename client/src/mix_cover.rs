//! Poisson arrival sampling for mix-layer cover traffic (§10.4).

use rand::Rng;

/// Milliseconds until the next cover cell, for a target rate (cells/sec).
pub fn next_arrival_ms(rate_cells_per_sec: f64) -> u64 {
    if rate_cells_per_sec <= 0.0 {
        return 1000;
    }
    let u: f64 = rand::thread_rng().gen_range(f64::MIN_POSITIVE..1.0);
    ((-u.ln() / rate_cells_per_sec) * 1000.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mean_matches_rate() {
        let n = 20_000u64;
        let total: u64 = (0..n).map(|_| next_arrival_ms(2.0)).sum();
        let mean = total as f64 / n as f64;
        // Expected mean interval = 500 ms; allow generous slack.
        assert!((400.0..600.0).contains(&mean), "mean was {mean}");
    }
}
