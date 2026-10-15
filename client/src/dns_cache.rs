//! DNS response cache with TTL (backlog item — the tunnel's local resolver).
//! Key = query bytes minus the 2-byte transaction ID; the cached response's
//! ID is rewritten to match the caller on each hit.

use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct DnsCache {
    entries: HashMap<Vec<u8>, CacheEntry>,
    max_entries: usize,
}

struct CacheEntry {
    response: Vec<u8>,
    expires: Instant,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    fn key(query: &[u8]) -> Vec<u8> {
        if query.len() < 2 {
            return query.to_vec();
        }
        query[2..].to_vec()
    }

    pub fn get(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        let k = Self::key(query);
        let now = Instant::now();
        if let Some(e) = self.entries.get(&k) {
            if now < e.expires {
                let mut resp = e.response.clone();
                if resp.len() >= 2 && query.len() >= 2 {
                    resp[0] = query[0];
                    resp[1] = query[1];
                }
                return Some(resp);
            }
            self.entries.remove(&k);
        }
        None
    }

    pub fn put(&mut self, query: &[u8], response: &[u8], ttl: Duration) {
        if self.entries.len() >= self.max_entries {
            if let Some(k) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.expires)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(
            Self::key(query),
            CacheEntry {
                response: response.to_vec(),
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Extract the minimum answer TTL (capped at 1 h); 60 s if unknown.
    pub fn min_ttl_from_response(response: &[u8]) -> Duration {
        if response.len() < 12 {
            return Duration::from_secs(60);
        }
        let ancount = u16::from_be_bytes([response[6], response[7]]) as usize;
        if ancount == 0 {
            return Duration::from_secs(60);
        }
        let mut off = 12;
        let qd = u16::from_be_bytes([response[4], response[5]]) as usize;
        for _ in 0..qd {
            off = skip_name(response, off);
            off += 4;
            if off >= response.len() {
                return Duration::from_secs(60);
            }
        }
        let ttl_off = skip_name(response, off) + 4;
        if ttl_off + 4 <= response.len() {
            let secs = u32::from_be_bytes(response[ttl_off..ttl_off + 4].try_into().unwrap());
            Duration::from_secs(secs.min(3600) as u64)
        } else {
            Duration::from_secs(60)
        }
    }
}

fn skip_name(buf: &[u8], mut off: usize) -> usize {
    while off < buf.len() {
        let len = buf[off] as usize;
        if len == 0 {
            return off + 1;
        }
        if len & 0xC0 == 0xC0 {
            return off + 2;
        }
        off += 1 + len;
    }
    off
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_rewrites_id() {
        let mut c = DnsCache::new(16);
        let query = vec![0x12, 0x34, 0x01, 0x00];
        let mut resp = vec![0x12, 0x34, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        resp.extend_from_slice(&[0u8; 4]);
        c.put(&query, &resp, Duration::from_secs(60));
        let mut new_query = query.clone();
        new_query[0] = 0xAB;
        new_query[1] = 0xCD;
        let got = c.get(&new_query).unwrap();
        assert_eq!(got[0], 0xAB);
        assert_eq!(got[1], 0xCD);
    }

    #[test]
    fn expired_entries_drop() {
        let mut c = DnsCache::new(16);
        c.put(&[0, 1, 2], &[0, 1, 9], Duration::from_millis(0));
        assert!(c.get(&[0, 1, 2]).is_none());
    }
}
