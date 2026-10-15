//! Server-side tunnel-IP routing (§19).
//!
//! The server assigns each client a tunnel IP from `10.77.0.0/24` at handshake
//! time. When it reads an IP packet off its TUN device, it looks up the owning
//! session by the packet's destination address — exactly how WireGuard's
//! `AllowedIPs` maps a packet to a peer, specialized to a single subnet.

use crate::ipparse;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// Maps assigned tunnel IPs to connection ids.
#[derive(Default)]
pub struct Router {
    by_ip: HashMap<IpAddr, u64>,
}

impl Router {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind an explicit tunnel IP to a session.
    pub fn bind(&mut self, ip: IpAddr, conn_id: u64) {
        self.by_ip.insert(ip, conn_id);
    }

    /// Allocate the next free address in `10.77.0.2..=10.77.0.254` and bind it
    /// to `conn_id`. Returns `None` if the pool is exhausted.
    pub fn allocate_v4(&mut self, conn_id: u64) -> Option<Ipv4Addr> {
        use std::collections::hash_map::Entry;
        for last in 2u8..=254 {
            let v4 = Ipv4Addr::new(10, 77, 0, last);
            if let Entry::Vacant(slot) = self.by_ip.entry(IpAddr::V4(v4)) {
                slot.insert(conn_id);
                return Some(v4);
            }
        }
        None
    }

    /// Route a raw IP packet to its session by destination address.
    pub fn route(&self, ip_packet: &[u8]) -> Option<u64> {
        let dst = ipparse::destination_ip(ip_packet)?;
        self.by_ip.get(&dst).copied()
    }

    /// Drop every route for a session (on disconnect).
    pub fn remove_conn(&mut self, conn_id: u64) {
        self.by_ip.retain(|_, c| *c != conn_id);
    }

    /// Number of bound addresses.
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_to(dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn routes_packet_by_destination() {
        let mut r = Router::new();
        let ip = r.allocate_v4(42).unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 77, 0, 2));
        assert_eq!(r.route(&ipv4_to(ip.octets())), Some(42));
        assert_eq!(r.route(&ipv4_to([8, 8, 8, 8])), None); // not one of ours
    }

    #[test]
    fn allocations_are_unique_and_reclaimed() {
        let mut r = Router::new();
        let a = r.allocate_v4(1).unwrap();
        let b = r.allocate_v4(2).unwrap();
        assert_ne!(a, b);
        assert_eq!(r.len(), 2);
        r.remove_conn(1); // client 1 disconnects
        let c = r.allocate_v4(3).unwrap();
        assert_eq!(c, a, "the freed address is reassigned");
    }
}
