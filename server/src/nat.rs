//! Egress NAT for TUN mode (`shaipd --nat IFACE`): what turns "packets reach
//! the server" into "packets reach the internet".
//!
//! Enables IPv4 forwarding and installs one nftables table that
//! - masquerades the tunnel subnet out of the egress interface,
//! - forwards tunnel → internet, and internet → tunnel only for connections a
//!   client opened (nothing unsolicited reaches a client); client ↔ client
//!   traffic is left to the daemon's own policy (off by default),
//! - clamps TCP MSS to the route MTU, so TCP never relies on PMTU discovery
//!   through the tunnel.
//!
//! Everything is removed again on drop (forwarding is switched back off if it
//! was off before). A daemon that crashes leaves the table, which the next
//! start replaces atomically.
//!
//! The kernel's connection tracking holds the NAT state of every open
//! connection (needed to send replies back). When a tunnel address leaves its
//! lease, [`forget_flows`] deletes that address's entries: they would outlive
//! the session, and a late reply to one would reach whoever holds the address
//! next. This uses the `conntrack` tool, so `--nat` requires it.

use anyhow::{bail, Context, Result};
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

pub struct NatGuard {
    table: String,
    restore_forwarding: bool,
}

fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running nft (install nftables; --nat needs it)")?;
    child.stdin.take().expect("piped stdin").write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Whether the `conntrack` tool (conntrack-tools) can be run.
pub fn conntrack_available() -> bool {
    Command::new("conntrack")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Delete the connection-tracking (NAT) entries of these tunnel addresses: the
/// connections their last holder opened, and any to them.
pub fn forget_flows(ips: &[Ipv4Addr]) {
    for ip in ips {
        for dir in ["--orig-src", "--orig-dst"] {
            // Exit status 1 only means there was nothing to delete.
            let _ = Command::new("conntrack")
                .args(["-D", dir, &ip.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// nftables table name for a TUN device (identifier-safe).
pub fn table_name(tun: &str) -> String {
    let safe: String = tun.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    format!("shaip_nat_{safe}")
}

/// The ruleset for `subnet` on `tun`, leaving through `egress`.
pub fn ruleset(tun: &str, net: Ipv4Addr, prefix: u8, egress: &str) -> String {
    let t = table_name(tun);
    format!(
        "add table ip {t}\ndelete table ip {t}\n\
table ip {t} {{\n\
  chain postrouting {{\n\
    type nat hook postrouting priority srcnat; policy accept;\n\
    ip saddr {net}/{prefix} oifname \"{egress}\" masquerade\n\
  }}\n\
  chain forward {{\n\
    type filter hook forward priority filter; policy accept;\n\
    iifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu\n\
    oifname \"{tun}\" tcp flags syn tcp option maxseg size set rt mtu\n\
    iifname \"{tun}\" oifname \"{egress}\" accept\n\
    iifname \"{egress}\" oifname \"{tun}\" ct state established,related accept\n\
    iifname \"{tun}\" oifname \"{tun}\" accept\n\
    oifname \"{tun}\" drop\n\
  }}\n\
}}\n"
    )
}

/// Turn on forwarding and NAT for `gateway/prefix` on `tun` out of `egress`.
pub fn enable(tun: &str, gateway: Ipv4Addr, prefix: u8, egress: &str) -> Result<NatGuard> {
    if !std::path::Path::new(&format!("/sys/class/net/{egress}")).exists() {
        bail!("--nat {egress}: no such network interface");
    }
    let net = Ipv4Addr::from(u32::from(gateway) & (u32::MAX << (32 - u32::from(prefix))));
    nft(&ruleset(tun, net, prefix, egress))?;
    let before = std::fs::read_to_string(IP_FORWARD).unwrap_or_default();
    let was_off = before.trim() == "0";
    if was_off {
        std::fs::write(IP_FORWARD, "1").context("enabling IPv4 forwarding")?;
    }
    tracing::info!(%tun, %egress, subnet = %format!("{net}/{prefix}"), "egress NAT on (forwarding + masquerade + MSS clamp)");
    Ok(NatGuard {
        table: table_name(tun),
        restore_forwarding: was_off,
    })
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        let t = &self.table;
        if let Err(e) = nft(&format!("add table ip {t}\ndelete table ip {t}\n")) {
            tracing::error!(error = %e, "could not remove the NAT rules");
        }
        if self.restore_forwarding {
            let _ = std::fs::write(IP_FORWARD, "0");
        }
        tracing::info!("egress NAT removed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_masquerades_only_the_tunnel_subnet() {
        let r = ruleset("shaip-e2e0", Ipv4Addr::new(10, 77, 0, 0), 24, "eth0");
        assert!(r.contains("table ip shaip_nat_shaip_e2e0 {"));
        assert!(r.contains("ip saddr 10.77.0.0/24 oifname \"eth0\" masquerade"));
        assert!(r.contains("ct state established,related accept"));
        // Nothing unsolicited is forwarded into the tunnel.
        let fwd = r.split("chain forward").nth(1).unwrap();
        assert!(fwd.find("established,related").unwrap() < fwd.find("oifname \"shaip-e2e0\" drop").unwrap());
    }
}
