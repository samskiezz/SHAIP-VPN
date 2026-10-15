//! Minimal IP-packet address parsing (§19 TUN routing).
//!
//! When the server reads an IP packet off its TUN device it must forward it to
//! the client session that owns the destination tunnel address. That routing
//! decision needs only the destination address from the IP header — this
//! module extracts it (and the source, for logging/anti-spoof checks) for both
//! IPv4 and IPv6, without pulling in a full packet-parsing dependency.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The IP version in the first nibble of an IP packet, or `None` if the buffer
/// is empty.
pub fn version(packet: &[u8]) -> Option<u8> {
    packet.first().map(|b| b >> 4)
}

/// Destination address of an IPv4 or IPv6 packet. Returns `None` if the packet
/// is too short for its claimed version or the version is unrecognized.
pub fn destination_ip(packet: &[u8]) -> Option<IpAddr> {
    match version(packet)? {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Source address of an IPv4 or IPv6 packet, with the same validation.
pub fn source_ip(packet: &[u8]) -> Option<IpAddr> {
    match version(packet)? {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_src_and_dst() {
        let mut p = [0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p[12..16].copy_from_slice(&[10, 77, 0, 1]);
        p[16..20].copy_from_slice(&[10, 77, 0, 2]);
        assert_eq!(version(&p), Some(4));
        assert_eq!(source_ip(&p), Some(IpAddr::V4(Ipv4Addr::new(10, 77, 0, 1))));
        assert_eq!(
            destination_ip(&p),
            Some(IpAddr::V4(Ipv4Addr::new(10, 77, 0, 2)))
        );
    }

    #[test]
    fn parses_ipv6_dst() {
        let mut p = [0u8; 40];
        p[0] = 0x60; // version 6
        let dst = Ipv6Addr::new(0xfd77, 0, 0, 0, 0, 0, 0, 2);
        p[24..40].copy_from_slice(&dst.octets());
        assert_eq!(destination_ip(&p), Some(IpAddr::V6(dst)));
    }

    #[test]
    fn rejects_short_and_unknown() {
        assert_eq!(destination_ip(&[]), None);
        assert_eq!(destination_ip(&[0x45, 0, 0]), None); // too short for IPv4
        let zeroed = [0u8; 20];
        assert_eq!(destination_ip(&zeroed), None); // version 0
    }
}
