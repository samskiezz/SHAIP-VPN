//! Tunnel-address leases, one per client identity.
//!
//! A client keeps its tunnel address across reconnects and rekeys (its TCP
//! connections survive a new handshake), and — because the first-choice
//! address is a hash of the identity — usually across a server restart too.
//! When a session ends the lease is held for a grace period, then freed; if
//! the pool is full, the longest-idle released lease is reused.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

struct Lease {
    ip: Ipv4Addr,
    /// `None` while a session holds it; otherwise when it was released.
    released_at: Option<Instant>,
}

pub struct Pool {
    network: u32,
    prefix: u8,
    gateway: Ipv4Addr,
    leases: HashMap<[u8; 16], Lease>,
    by_ip: HashMap<Ipv4Addr, [u8; 16]>,
}

impl Pool {
    /// The pool for the subnet `gateway/prefix`: every host address except
    /// the gateway's. Prefixes /8 to /30.
    pub fn new(gateway: Ipv4Addr, prefix: u8) -> Result<Pool> {
        if !(8..=30).contains(&prefix) {
            bail!("tunnel subnet /{prefix} is out of range (use /8 to /30)");
        }
        let mask = u32::MAX << (32 - prefix);
        let network = u32::from(gateway) & mask;
        let broadcast = network | !mask;
        let gw = u32::from(gateway);
        if gw == network || gw == broadcast {
            bail!("the tunnel address {gateway}/{prefix} is the subnet's network or broadcast address");
        }
        Ok(Pool {
            network,
            prefix,
            gateway,
            leases: HashMap::new(),
            by_ip: HashMap::new(),
        })
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Host addresses in the subnet (network and broadcast excluded).
    fn hosts(&self) -> u32 {
        (1u32 << (32 - self.prefix)) - 2
    }

    /// Whether `ip` is inside the tunnel subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & (u32::MAX << (32 - self.prefix)) == self.network
    }

    /// The address for `id`: its existing lease, else a free one (first choice
    /// derived from the identity), else the longest-released lease's. `None`
    /// when every address is held by a live session.
    pub fn lease(&mut self, id: [u8; 16]) -> Option<Ipv4Addr> {
        if let Some(l) = self.leases.get_mut(&id) {
            l.released_at = None;
            return Some(l.ip);
        }
        let hosts = self.hosts();
        let start = u32::from_be_bytes([id[0], id[1], id[2], id[3]]) % hosts;
        let free = (0..hosts)
            .map(|k| Ipv4Addr::from(self.network + 1 + (start + k) % hosts))
            .find(|ip| *ip != self.gateway && !self.by_ip.contains_key(ip));
        let ip = match free {
            Some(ip) => ip,
            None => {
                let (victim, ip) = self
                    .leases
                    .iter()
                    .filter_map(|(vid, l)| l.released_at.map(|at| (at, *vid, l.ip)))
                    .min_by_key(|(at, _, _)| *at)
                    .map(|(_, vid, ip)| (vid, ip))?;
                self.leases.remove(&victim);
                ip
            }
        };
        self.leases.insert(id, Lease { ip, released_at: None });
        self.by_ip.insert(ip, id);
        Some(ip)
    }

    /// The session holding `id`'s lease ended; keep the address for a while.
    pub fn release(&mut self, id: [u8; 16], now: Instant) {
        if let Some(l) = self.leases.get_mut(&id) {
            l.released_at = Some(now);
        }
    }

    /// Free leases released more than `grace` ago.
    pub fn expire(&mut self, now: Instant, grace: Duration) {
        let by_ip = &mut self.by_ip;
        self.leases.retain(|_, l| match l.released_at {
            Some(at) if now.saturating_duration_since(at) > grace => {
                by_ip.remove(&l.ip);
                false
            }
            _ => true,
        });
    }

    /// Leases currently held (live or in their grace period).
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn a_client_keeps_its_address_across_sessions() {
        let mut p = Pool::new(Ipv4Addr::new(10, 77, 0, 1), 24).unwrap();
        let a = p.lease(id(1)).unwrap();
        assert!(p.contains(a) && a != p.gateway());
        p.release(id(1), Instant::now());
        assert_eq!(p.lease(id(1)), Some(a), "same address after a reconnect");
        // Deterministic first choice: a fresh pool (a restarted server) agrees.
        let mut q = Pool::new(Ipv4Addr::new(10, 77, 0, 1), 24).unwrap();
        assert_eq!(q.lease(id(1)), Some(a));
    }

    #[test]
    fn never_hands_out_gateway_network_or_broadcast_and_fills_up() {
        // /29: hosts .1–.6, gateway .1 → five client addresses.
        let mut p = Pool::new(Ipv4Addr::new(10, 9, 0, 1), 29).unwrap();
        let mut got = std::collections::HashSet::new();
        for n in 0..5 {
            let ip = p.lease(id(n)).unwrap();
            let last = ip.octets()[3];
            assert!((2..=6).contains(&last), "{ip}");
            assert!(got.insert(ip), "unique");
        }
        assert_eq!(p.lease(id(9)), None, "full of live sessions");
        // A released lease is reused only once the pool is otherwise full.
        let t0 = Instant::now();
        p.release(id(3), t0);
        let reused = p.lease(id(9)).unwrap();
        assert!(got.contains(&reused));
        assert_eq!(p.len(), 5);
    }

    #[test]
    fn released_leases_expire_after_the_grace_period() {
        let mut p = Pool::new(Ipv4Addr::new(10, 77, 0, 1), 24).unwrap();
        let t0 = Instant::now();
        p.lease(id(1)).unwrap();
        p.lease(id(2)).unwrap();
        p.release(id(1), t0);
        p.expire(t0 + Duration::from_secs(5), Duration::from_secs(10));
        assert_eq!(p.len(), 2, "still in grace");
        p.expire(t0 + Duration::from_secs(11), Duration::from_secs(10));
        assert_eq!(p.len(), 1, "expired; the live lease stays");
    }

    #[test]
    fn rejects_unusable_subnets() {
        assert!(Pool::new(Ipv4Addr::new(10, 77, 0, 0), 24).is_err(), "network address");
        assert!(Pool::new(Ipv4Addr::new(10, 77, 0, 255), 24).is_err(), "broadcast");
        assert!(Pool::new(Ipv4Addr::new(10, 77, 0, 1), 31).is_err());
    }
}
