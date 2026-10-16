//! Stateless retry cookies — address validation before expensive work (§10).
//!
//! A spoofed-source flood is cheap for the attacker and, without this, costly
//! for the server: every CLIENT_HELLO it accepts triggers an ML-KEM
//! encapsulation and two signatures over SERVER_HELLO. A retry cookie makes the
//! server prove the sender can *receive* at its claimed address before it does
//! any of that, the way QUIC's Retry (RFC 9000 §8.1.2) and DTLS 1.3's
//! HelloRetryRequest cookie (RFC 9147 §5.1) do.
//!
//! When its half-open table is full, the server answers an unvalidated
//! CLIENT_HELLO with a RETRY carrying a cookie instead of doing the handshake.
//! The cookie is `ts(8) || HMAC-SHA256(secret, addr || ts)[..24]`: the server
//! keeps **no per-client state**, only one process-wide secret. A client that
//! truly holds the address receives the RETRY and repeats its hello with the
//! cookie echoed; a spoofed source never sees it, so it can never get past the
//! gate and never costs the server a signature.
//!
//! The cookie binds to the UDP source address and a short lifetime, nothing
//! else. It is an anti-DoS gate, not a secret: a holder of their own cookie
//! gains nothing but admission from their own address.

use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

/// Bytes of the HMAC carried in a cookie (the rest of SHA-256 is dropped to fit
/// the 8-byte timestamp into the 32-byte cookie field).
const MAC_LEN: usize = 24;
/// Total cookie size, matching the CLIENT_HELLO cookie field.
pub const COOKIE_LEN: usize = 32;

/// Issues and verifies retry cookies against one process-wide secret.
pub struct RetryCookies {
    secret: [u8; 32],
    /// Monotonic reference; cookie timestamps are seconds since this.
    created: Instant,
    lifetime: Duration,
}

impl Default for RetryCookies {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryCookies {
    /// A fresh random secret. A restart invalidates outstanding cookies; a
    /// client simply gets a new RETRY and tries again.
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self {
            secret,
            created: Instant::now(),
            lifetime: Duration::from_secs(60),
        }
    }

    fn seconds(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.created).as_secs()
    }

    fn mac(&self, addr: &SocketAddr, ts: u64) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("HMAC takes any key length");
        match addr.ip() {
            std::net::IpAddr::V4(a) => mac.update(&a.octets()),
            std::net::IpAddr::V6(a) => mac.update(&a.octets()),
        }
        mac.update(&addr.port().to_be_bytes());
        mac.update(&ts.to_be_bytes());
        mac.finalize().into_bytes().into()
    }

    /// A cookie for `addr`, valid for [`RetryCookies::lifetime`].
    pub fn issue(&self, addr: &SocketAddr, now: Instant) -> [u8; COOKIE_LEN] {
        let ts = self.seconds(now);
        let mac = self.mac(addr, ts);
        let mut cookie = [0u8; COOKIE_LEN];
        cookie[..8].copy_from_slice(&ts.to_be_bytes());
        cookie[8..].copy_from_slice(&mac[..MAC_LEN]);
        cookie
    }

    /// True if `cookie` is one this server issued to `addr` and not expired.
    pub fn verify(&self, addr: &SocketAddr, cookie: &[u8; COOKIE_LEN], now: Instant) -> bool {
        let ts = u64::from_be_bytes(cookie[..8].try_into().unwrap());
        // Reject a future timestamp (a restart moved `created` forward) or a
        // stale one.
        let age = self.seconds(now);
        if ts > age || age - ts > self.lifetime.as_secs() {
            return false;
        }
        ct_eq(&self.mac(addr, ts)[..MAC_LEN], &cookie[8..])
    }
}

/// A zero cookie means "none sent" — a client's first hello carries it.
pub fn is_empty(cookie: &[u8; COOKIE_LEN]) -> bool {
    cookie.iter().all(|&b| b == 0)
}

/// Constant-time equality, so a verifier reveals nothing through timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_cookie_verifies_for_its_own_address() {
        let c = RetryCookies::new();
        let now = Instant::now();
        let a = addr("198.51.100.4:40000");
        let cookie = c.issue(&a, now);
        assert!(!is_empty(&cookie));
        assert!(c.verify(&a, &cookie, now));
        assert!(c.verify(&a, &cookie, now + Duration::from_secs(30)));
    }

    #[test]
    fn a_cookie_is_bound_to_the_address() {
        let c = RetryCookies::new();
        let now = Instant::now();
        let cookie = c.issue(&addr("198.51.100.4:40000"), now);
        assert!(!c.verify(&addr("198.51.100.4:40001"), &cookie, now), "different port");
        assert!(!c.verify(&addr("203.0.113.9:40000"), &cookie, now), "different ip");
    }

    #[test]
    fn a_cookie_expires() {
        let c = RetryCookies::new();
        let now = Instant::now();
        let a = addr("198.51.100.4:40000");
        let cookie = c.issue(&a, now);
        assert!(!c.verify(&a, &cookie, now + Duration::from_secs(61)));
    }

    #[test]
    fn another_servers_secret_does_not_verify() {
        let now = Instant::now();
        let a = addr("198.51.100.4:40000");
        let cookie = RetryCookies::new().issue(&a, now);
        assert!(!RetryCookies::new().verify(&a, &cookie, now), "a different secret");
    }

    #[test]
    fn garbage_and_zero_cookies_are_refused() {
        let c = RetryCookies::new();
        let now = Instant::now();
        let a = addr("198.51.100.4:40000");
        assert!(!c.verify(&a, &[0u8; COOKIE_LEN], now));
        assert!(!c.verify(&a, &[0xFF; COOKIE_LEN], now));
    }
}
