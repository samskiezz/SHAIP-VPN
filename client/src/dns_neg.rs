//! Negative caching (RFC 2308): cache NXDOMAIN / NODATA for a short TTL.

use std::time::Duration;

pub fn negative_cache_ttl(response: &[u8]) -> Option<Duration> {
    if response.len() < 12 {
        return None;
    }
    let rcode = response[3] & 0x0F;
    if rcode != 3 {
        // Not NXDOMAIN; check for NOERROR with zero answers (NODATA).
        let ancount = u16::from_be_bytes([response[6], response[7]]);
        if !(rcode == 0 && ancount == 0) {
            return None;
        }
    }
    Some(Duration::from_secs(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nxdomain_is_cached() {
        let mut r = vec![0u8; 12];
        r[3] = 0x03; // NXDOMAIN
        assert!(negative_cache_ttl(&r).is_some());
    }

    #[test]
    fn positive_answer_not_negative_cached() {
        let mut r = vec![0u8; 12];
        r[7] = 1; // ancount = 1
        assert!(negative_cache_ttl(&r).is_none());
    }
}
