//! Per-hop delay sampling for the mixnet (§10.3): exponential distribution,
//! capped at 10x the mean.

use rand::Rng;

pub fn sample_exponential_ms(mean_ms: u64) -> u64 {
    if mean_ms == 0 {
        return 0;
    }
    let u: f64 = rand::thread_rng().gen_range(f64::MIN_POSITIVE..1.0);
    let sample = -u.ln() * mean_ms as f64;
    sample.min(mean_ms as f64 * 10.0) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_and_nonzero_mean() {
        for _ in 0..1000 {
            let d = sample_exponential_ms(50);
            assert!(d <= 500);
        }
        assert_eq!(sample_exponential_ms(0), 0);
    }
}
