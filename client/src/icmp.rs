//! Minimal IPv4 ICMP echo packets, for probing a tunnel end to end.
//!
//! `shaip probe` sends an echo request through the tunnel to the server's
//! tunnel address. A TUN-mode server hands it to its kernel, which answers with
//! a real echo reply that comes back through the tunnel. An echo-mode server
//! returns the request verbatim. Checksums are computed per RFC 791/792 so a
//! kernel accepts the packet.

use std::net::Ipv4Addr;

/// The RFC 1071 Internet checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv4 ICMP echo request.
pub fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45; // IPv4, IHL 5
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&seq.to_be_bytes()); // IP id
    p[6] = 0x40; // don't fragment
    p[8] = 64; // TTL
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(&p[..20]);
    p[10..12].copy_from_slice(&ip_sum.to_be_bytes());
    p[20] = 8; // echo request
    p[24..26].copy_from_slice(&id.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    p[28..].copy_from_slice(payload);
    let icmp_sum = checksum(&p[20..]);
    p[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    p
}

/// An ICMP echo reply: `(source, id, seq)` if `pkt` is one with valid checksums.
pub fn parse_echo_reply(pkt: &[u8]) -> Option<(Ipv4Addr, u16, u16)> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if ihl < 20 || pkt.len() < ihl + 8 || checksum(&pkt[..ihl]) != 0 || checksum(&pkt[ihl..]) != 0 {
        return None;
    }
    let icmp = &pkt[ihl..];
    if icmp[0] != 0 {
        return None; // not an echo reply
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    Some((
        src,
        u16::from_be_bytes([icmp[4], icmp[5]]),
        u16::from_be_bytes([icmp[6], icmp[7]]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums_verify_and_a_reply_parses() {
        let src = Ipv4Addr::new(10, 77, 0, 2);
        let dst = Ipv4Addr::new(10, 77, 0, 1);
        let req = echo_request(src, dst, 0x1234, 7, b"shaip probe");
        // A correct header checksums to zero over itself.
        assert_eq!(checksum(&req[..20]), 0);
        assert_eq!(checksum(&req[20..]), 0);
        // A request is not a reply...
        assert_eq!(parse_echo_reply(&req), None);
        // ...but the same packet as a kernel would answer it is.
        let mut reply = req.clone();
        reply[12..16].copy_from_slice(&dst.octets());
        reply[16..20].copy_from_slice(&src.octets());
        reply[10..12].copy_from_slice(&[0, 0]);
        let s = checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&s.to_be_bytes());
        reply[20] = 0;
        reply[22..24].copy_from_slice(&[0, 0]);
        let s = checksum(&reply[20..]);
        reply[22..24].copy_from_slice(&s.to_be_bytes());
        assert_eq!(parse_echo_reply(&reply), Some((dst, 0x1234, 7)));
        // A corrupted reply is rejected.
        reply[30] ^= 0xff;
        assert_eq!(parse_echo_reply(&reply), None);
    }

    #[test]
    fn odd_length_checksum_matches_rfc1071_example() {
        // RFC 1071 §3 example words 0x0001 0xf203 0xf4f5 0xf6f7 sum to 0xddf2.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), !0xddf2);
        assert_eq!(checksum(&[0xff]), !0xff00);
    }
}
