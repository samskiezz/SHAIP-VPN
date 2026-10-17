//! Preconditions for a front end to claim that a full IPv4 tunnel is ready.
//! A successful crypto handshake with an echo server is not a routed VPN.

use std::net::Ipv4Addr;

fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
        && !ip.is_broadcast() && (1..240).contains(&ip.octets()[0])
}

/// Require a usable server-assigned address and, unless explicitly disabled by
/// the caller, a resolver in that tunnel subnet. Requiring an in-subnet DNS
/// address avoids a more-specific physical LAN route bypassing the VPN.
pub fn require_full_tunnel(
    address: Option<Ipv4Addr>,
    prefix: u8,
    dns: Option<Ipv4Addr>,
    require_dns: bool,
) -> Result<(), &'static str> {
    let address = address.filter(|ip| unicast(*ip))
        .ok_or("the server did not assign a usable tunnel address; echo mode cannot protect internet traffic")?;
    if !(1..=32).contains(&prefix) {
        return Err("the server supplied an invalid tunnel prefix");
    }
    if require_dns {
        let dns = dns.filter(|ip| unicast(*ip))
            .ok_or("the server supplied no usable tunnel DNS resolver; refusing system-DNS fallback")?;
        let mask = u32::MAX << (32 - prefix);
        if u32::from(address) & mask != u32::from(dns) & mask || dns == address {
            return Err("the DNS resolver must be a different address inside the assigned tunnel subnet");
        }
        if prefix <= 30 {
            let host = u32::from(dns) & !mask;
            if host == 0 || host == !mask {
                return Err("the DNS resolver cannot be a subnet network or broadcast address");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ip(s: &str) -> Option<Ipv4Addr> { Some(s.parse().unwrap()) }

    #[test]
    fn routed_gateway_is_accepted() {
        assert!(require_full_tunnel(ip("10.77.0.2"), 24, ip("10.77.0.1"), true).is_ok());
    }
    #[test]
    fn echo_and_missing_dns_are_refused() {
        assert!(require_full_tunnel(None, 24, ip("10.77.0.1"), true).is_err());
        assert!(require_full_tunnel(ip("10.77.0.2"), 24, None, true).is_err());
        // Keeping system DNS is an explicit opt-out, not a fallback.
        assert!(require_full_tunnel(ip("10.77.0.2"), 24, None, false).is_ok());
    }
    #[test]
    fn lan_loopback_and_self_resolvers_are_refused() {
        for dns in ["192.168.1.1", "127.0.0.53", "0.0.0.0", "224.0.0.1", "10.77.0.2", "10.77.0.0", "10.77.0.255"] {
            assert!(require_full_tunnel(ip("10.77.0.2"), 24, ip(dns), true).is_err(), "{dns}");
        }
    }
    #[test]
    fn invalid_prefix_never_reaches_a_shift() {
        for prefix in [0, 33, 255] {
            assert!(require_full_tunnel(ip("10.77.0.2"), prefix, ip("10.77.0.1"), true).is_err());
        }
    }
}
