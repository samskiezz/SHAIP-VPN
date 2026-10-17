//! Linux network configuration for a full-tunnel client: routes, DNS, and
//! leak blocking. Everything changed here is recorded and undone on drop (and
//! by `pqanon down` after a crash).
//!
//! - **Routes.** A host route keeps the tunnel's own UDP flow on the physical
//!   network (via the gateway that served it before), then `0.0.0.0/1` and
//!   `128.0.0.0/1` point every other IPv4 destination into the TUN device. The
//!   two halves outrank the default route without replacing it, so removing
//!   them restores the original routing exactly. Installed with the classic
//!   `SIOCADDRT` ioctl: no `ip` binary needed.
//! - **DNS.** The resolver the server pushes (its forwarder, reached through
//!   the tunnel) replaces the system's. A LAN resolver would otherwise stay
//!   reachable outside the tunnel (its subnet route is more specific than
//!   `/1`), sending every lookup past the VPN. With systemd-resolved this uses
//!   `resolvectl`; otherwise `/etc/resolv.conf` is rewritten in place and the
//!   original kept in the state directory until it is restored.
//! - **Leaks.** The tunnel carries IPv4 only, so IPv6 is rejected while it is
//!   up (nftables). With the kill switch, *all* traffic outside the tunnel is
//!   rejected except the tunnel's own flow and DHCP, and the rules stay if the
//!   client dies — fail closed — until it reconnects or `pqanon down` runs.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

const RTF_UP: libc::c_ushort = 0x0001;
const RTF_GATEWAY: libc::c_ushort = 0x0002;
const RTF_HOST: libc::c_ushort = 0x0004;

/// nftables table holding the client's leak-blocking rules.
pub const NFT_TABLE: &str = "pqanon_client";

/// `struct rtentry` from `<linux/route.h>` (the kernel layout; 120 bytes on
/// 64-bit targets).
#[repr(C)]
struct RtEntry {
    rt_pad1: libc::c_ulong,
    rt_dst: libc::sockaddr,
    rt_gateway: libc::sockaddr,
    rt_genmask: libc::sockaddr,
    rt_flags: libc::c_ushort,
    rt_pad2: libc::c_short,
    rt_pad3: libc::c_ulong,
    rt_pad4: *mut libc::c_void,
    rt_metric: libc::c_short,
    rt_dev: *mut libc::c_char,
    rt_mtu: libc::c_ulong,
    rt_window: libc::c_ulong,
    rt_irtt: libc::c_ushort,
}

/// One IPv4 route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub dst: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dev: Option<String>,
}

/// Where traffic to an address leaves today.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Egress {
    pub dev: String,
    pub gateway: Option<Ipv4Addr>,
}

fn sockaddr_v4(ip: Ipv4Addr) -> libc::sockaddr {
    // SAFETY: sockaddr_in and sockaddr are plain-old-data; zero is valid.
    let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(ip.octets()),
    };
    // SAFETY: as above.
    let mut sa: libc::sockaddr = unsafe { std::mem::zeroed() };
    // SAFETY: both are 16-byte POD structs on Linux.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::addr_of!(sin).cast::<u8>(),
            std::ptr::addr_of_mut!(sa).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr>(),
        );
    }
    sa
}

fn mask(prefix: u8) -> Ipv4Addr {
    Ipv4Addr::from(if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) })
}

fn route_ioctl(request: libc::c_ulong, r: &Route, metric: u16) -> io::Result<()> {
    // SAFETY: an AF_INET datagram socket; plain integer arguments.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a freshly opened fd we own.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let dev = match &r.dev {
        Some(d) => Some(std::ffi::CString::new(d.as_str()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?),
        None => None,
    };
    // SAFETY: RtEntry is plain-old-data; zero is a valid starting state.
    let mut rt: RtEntry = unsafe { std::mem::zeroed() };
    let net = u32::from(r.dst) & u32::from(mask(r.prefix));
    rt.rt_dst = sockaddr_v4(Ipv4Addr::from(net));
    rt.rt_genmask = sockaddr_v4(mask(r.prefix));
    rt.rt_flags = RTF_UP;
    if r.prefix == 32 {
        rt.rt_flags |= RTF_HOST;
    }
    if let Some(gw) = r.gateway {
        rt.rt_gateway = sockaddr_v4(gw);
        rt.rt_flags |= RTF_GATEWAY;
    }
    // The ioctl ABI stores metric + 1 (0 means "unset").
    rt.rt_metric = (metric as libc::c_short).saturating_add(1);
    if let Some(d) = &dev {
        rt.rt_dev = d.as_ptr() as *mut libc::c_char;
    }
    // SAFETY: valid socket, correctly laid out rtentry; `dev` outlives the call.
    if unsafe { libc::ioctl(sock.as_raw_fd(), request as _, &mut rt as *mut RtEntry) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Install a route (`SIOCADDRT`). An identical existing route is replaced.
pub fn add_route(r: &Route) -> io::Result<()> {
    match route_ioctl(libc::SIOCADDRT, r, 0) {
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            let _ = del_route(r);
            route_ioctl(libc::SIOCADDRT, r, 0)
        }
        other => other,
    }
}

/// Remove a route (`SIOCDELRT`).
pub fn del_route(r: &Route) -> io::Result<()> {
    route_ioctl(libc::SIOCDELRT, r, 0)
}

/// Parse `/proc/net/route` (IPv4 FIB, main table) into routes with metrics.
fn read_routes() -> io::Result<Vec<(Route, u32)>> {
    let text = std::fs::read_to_string("/proc/net/route")?;
    let hex = |s: &str| u32::from_str_radix(s, 16).ok().map(|v| Ipv4Addr::from(v.to_ne_bytes()));
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Some(dst), Some(gw), Some(m)) = (hex(f[1]), hex(f[2]), hex(f[7])) else {
            continue;
        };
        let flags = u16::from_str_radix(f[3], 16).unwrap_or(0);
        if flags & RTF_UP == 0 {
            continue;
        }
        let metric = f[6].parse().unwrap_or(0);
        out.push((
            Route {
                dst,
                prefix: u32::from(m).count_ones() as u8,
                gateway: (flags & RTF_GATEWAY != 0).then_some(gw),
                dev: Some(f[0].to_string()),
            },
            metric,
        ));
    }
    Ok(out)
}

/// The route the kernel's main table would pick for `dst` (longest prefix,
/// then lowest metric), ignoring routes through `skip_dev` and host routes to
/// `dst` itself (ours, from an earlier attempt).
pub fn egress_for(dst: Ipv4Addr, skip_dev: Option<&str>) -> io::Result<Option<Egress>> {
    let best = read_routes()?
        .into_iter()
        .filter(|(r, _)| r.dev.as_deref() != skip_dev || skip_dev.is_none())
        .filter(|(r, _)| !(r.prefix == 32 && r.dst == dst))
        .filter(|(r, _)| u32::from(dst) & u32::from(mask(r.prefix)) == u32::from(r.dst))
        .max_by(|(a, am), (b, bm)| a.prefix.cmp(&b.prefix).then(bm.cmp(am)));
    Ok(best.map(|(r, _)| Egress {
        dev: r.dev.unwrap_or_default(),
        gateway: r.gateway,
    }))
}

fn have(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn run(bin: &str, args: &[&str], stdin: Option<&str>) -> io::Result<()> {
    use std::io::Write;
    let mut child = Command::new(bin)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{bin}: {e}")))?;
    if let Some(input) = stdin {
        child.stdin.take().expect("piped stdin").write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{bin} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Where crash-recovery state lives (`PQANON_STATE_DIR`, default
/// `/var/lib/pqanon`): the original resolv.conf and the routes to undo.
pub fn state_dir() -> PathBuf {
    std::env::var_os("PQANON_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/pqanon"))
}

fn resolv_backup() -> PathBuf {
    state_dir().join("resolv.conf.orig")
}

fn route_record() -> PathBuf {
    state_dir().join("hostroute")
}

// --- DNS -------------------------------------------------------------------

enum DnsBackend {
    Resolved { dev: String },
    File,
}

/// The tunnel's resolver, installed until dropped.
pub struct DnsGuard {
    backend: DnsBackend,
}

fn uses_systemd_resolved(path: &Path) -> bool {
    std::fs::read_link(path)
        .map(|t| t.to_string_lossy().contains("systemd/resolve"))
        .unwrap_or(false)
        && have("resolvectl")
}

/// Point the system resolver at `server` (reached through `dev`).
pub fn set_dns(dev: &str, server: Ipv4Addr) -> io::Result<DnsGuard> {
    let path = PathBuf::from("/etc/resolv.conf");
    if uses_systemd_resolved(&path) {
        let ip = server.to_string();
        run("resolvectl", &["dns", dev, &ip], None)?;
        run("resolvectl", &["domain", dev, "~."], None)?;
        let _ = run("resolvectl", &["default-route", dev, "true"], None);
        return Ok(DnsGuard {
            backend: DnsBackend::Resolved { dev: dev.to_string() },
        });
    }
    // A backup left by a client that died is the real original: put it back
    // first so it is not overwritten by a copy of our own file.
    restore_resolv_conf()?;
    let original = std::fs::read(&path).unwrap_or_default();
    std::fs::create_dir_all(state_dir())?;
    crate::secure_write::write_private(&resolv_backup(), &original)
        .map_err(|e| io::Error::other(format!("saving {}: {e:#}", resolv_backup().display())))?;
    let ours = format!(
        "# Written by pqanon while the tunnel is up; the original is restored on disconnect.\n\
         nameserver {server}\noptions edns0\n"
    );
    // In place (not rename): /etc/resolv.conf may be a bind mount.
    std::fs::write(&path, ours)?;
    Ok(DnsGuard {
        backend: DnsBackend::File,
    })
}

/// Put back a resolv.conf saved by [`set_dns`] (no-op if none is saved).
pub fn restore_resolv_conf() -> io::Result<bool> {
    let backup = resolv_backup();
    match std::fs::read(&backup) {
        Ok(original) => {
            std::fs::write("/etc/resolv.conf", original)?;
            std::fs::remove_file(&backup)?;
            Ok(true)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        match &self.backend {
            DnsBackend::Resolved { dev } => {
                let _ = run("resolvectl", &["revert", dev], None);
            }
            DnsBackend::File => {
                if let Err(e) = restore_resolv_conf() {
                    tracing::error!(error = %e, "could not restore /etc/resolv.conf (run `pqanon down`)");
                }
            }
        }
    }
}

// --- Firewall (nftables) ---------------------------------------------------

/// Leak-blocking rules, removed on drop unless they are a kill switch that
/// must outlive a crash (then only a clean shutdown removes them).
pub struct FirewallGuard {
    removed_on_drop: bool,
}

fn nft_ruleset(tun: &str, server: SocketAddr, kill_switch: bool) -> String {
    let tunnel_flow = match server.ip() {
        IpAddr::V4(ip) => format!("ip daddr {ip} udp dport {} accept", server.port()),
        IpAddr::V6(ip) => format!("ip6 daddr {ip} udp dport {} accept", server.port()),
    };
    let mut rules = vec![
        "oifname \"lo\" accept".to_string(),
        format!("oifname \"{tun}\" accept"),
        tunnel_flow,
    ];
    if kill_switch {
        // DHCP renewals keep the physical link's lease alive.
        rules.push("udp sport 68 udp dport 67 accept".into());
        rules.push("reject with icmpx type admin-prohibited".into());
    } else {
        // The tunnel carries IPv4 only: IPv6 would bypass it.
        rules.push("meta nfproto ipv6 reject with icmpx type admin-prohibited".into());
    }
    format!(
        "add table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n\
         table inet {NFT_TABLE} {{\n  chain output {{\n    type filter hook output priority 0; policy accept;\n{}  }}\n}}\n",
        rules.iter().map(|r| format!("    {r}\n")).collect::<String>()
    )
}

/// Install the leak-blocking rules for a tunnel on `tun` to `server`.
pub fn block_leaks(tun: &str, server: SocketAddr, kill_switch: bool) -> io::Result<FirewallGuard> {
    if !have("nft") {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "nftables (`nft`) is not installed; it is needed to block IPv6 leaks and for the kill switch",
        ));
    }
    run("nft", &["-f", "-"], Some(&nft_ruleset(tun, server, kill_switch)))?;
    Ok(FirewallGuard {
        removed_on_drop: true,
    })
}

/// Remove the client's nftables table (no-op if absent).
pub fn remove_firewall() -> io::Result<()> {
    if !have("nft") {
        return Ok(());
    }
    run("nft", &["-f", "-"], Some(&format!("add table inet {NFT_TABLE}\ndelete table inet {NFT_TABLE}\n")))
}

impl FirewallGuard {
    /// Keep the rules after this process exits (a crash keeps blocking).
    pub fn persist(&mut self) {
        self.removed_on_drop = false;
    }
}

impl Drop for FirewallGuard {
    fn drop(&mut self) {
        if self.removed_on_drop {
            if let Err(e) = remove_firewall() {
                tracing::error!(error = %e, "could not remove the leak-blocking rules (run `pqanon down`)");
            }
        }
    }
}

// --- Full tunnel -----------------------------------------------------------

/// What [`FullTunnel::up`] configures.
pub struct FullTunnelOpts {
    /// The TUN device carrying the tunnel.
    pub tun: String,
    /// The server's UDP address (kept off the tunnel).
    pub server: SocketAddr,
    /// Route all IPv4 into the tunnel (false: only the tunnel subnet).
    pub redirect_default: bool,
    /// Resolver to install, if any.
    pub dns: Option<Ipv4Addr>,
    /// Block IPv6 while the tunnel is up.
    pub block_ipv6: bool,
    /// Reject everything outside the tunnel, surviving a crash.
    pub kill_switch: bool,
}

/// Routes and DNS are undone on drop; a persistent kill switch stays closed.
pub struct FullTunnel {
    tun: String,
    server: Option<Ipv4Addr>,
    host_route: Mutex<Option<Route>>,
    split_routes: Vec<Route>,
    dns: Option<DnsGuard>,
    firewall: Option<FirewallGuard>,
}

impl FullTunnel {
    pub fn up(o: FullTunnelOpts) -> anyhow::Result<FullTunnel> {
        let mut ft = FullTunnel {
            tun: o.tun.clone(),
            server: match o.server.ip() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            },
            host_route: Mutex::new(None),
            split_routes: Vec::new(),
            dns: None,
            firewall: None,
        };
        // Firewall first. Persist immediately: a later route/DNS setup failure
        // must not remove the protection installed before the handshake.
        if o.kill_switch || o.block_ipv6 {
            ft.firewall = Some(block_leaks(&o.tun, o.server, o.kill_switch)?);
            if o.kill_switch {
                ft.firewall.as_mut().unwrap().persist();
            }
        }
        if o.redirect_default {
            if let Some(server) = ft.server {
                ft.pin_host_route(server)?;
            } else {
                anyhow::bail!("full-tunnel routing needs an IPv4 server address");
            }
            for half in [Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)] {
                let r = Route { dst: half, prefix: 1, gateway: None, dev: Some(o.tun.clone()) };
                add_route(&r).map_err(|e| anyhow::anyhow!("adding {half}/1 via {}: {e}", o.tun))?;
                ft.split_routes.push(r);
            }
        }
        if let Some(dns) = o.dns {
            ft.dns = Some(set_dns(&o.tun, dns).map_err(|e| anyhow::anyhow!("setting DNS to {dns}: {e}"))?);
        }
        Ok(ft)
    }

    /// Route the server via whatever carried it before the tunnel came up.
    fn pin_host_route(&self, server: Ipv4Addr) -> anyhow::Result<()> {
        let Some(eg) = egress_for(server, Some(&self.tun))? else {
            anyhow::bail!("no route to the server {server}");
        };
        let r = Route { dst: server, prefix: 32, gateway: eg.gateway, dev: Some(eg.dev.clone()) };
        let mut slot = self.host_route.lock().expect("host route lock");
        if slot.as_ref() == Some(&r) {
            return Ok(());
        }
        if let Some(old) = slot.take() {
            let _ = del_route(&old);
        }
        // A loopback or on-host server needs no pin (and must not get one).
        if eg.dev != "lo" {
            add_route(&r).map_err(|e| anyhow::anyhow!("pinning the route to {server} via {}: {e}", eg.dev))?;
            let _ = std::fs::create_dir_all(state_dir());
            let _ = std::fs::write(
                route_record(),
                format!("{server} {} {}\n", eg.gateway.map(|g| g.to_string()).unwrap_or("-".into()), eg.dev),
            );
            *slot = Some(r);
        }
        Ok(())
    }

    /// Re-point the host route if the physical network changed (call before a
    /// reconnection attempt).
    pub fn refresh_host_route(&self) {
        if let Some(server) = self.server {
            if self.host_route.lock().expect("host route lock").is_some() || !self.split_routes.is_empty() {
                if let Err(e) = self.pin_host_route(server) {
                    tracing::warn!(error = %e, "could not refresh the route to the server");
                }
            }
        }
    }

    /// Re-install the default-route halves (after the TUN address changed).
    pub fn reassert_routes(&self) -> io::Result<()> {
        for r in &self.split_routes {
            add_route(r)?;
        }
        Ok(())
    }

    /// Tear down cleanly, including a kill switch.
    pub fn down(mut self) {
        if let Some(fw) = self.firewall.as_mut() {
            fw.removed_on_drop = true;
        }
    }
}

impl Drop for FullTunnel {
    fn drop(&mut self) {
        self.dns.take();
        for r in self.split_routes.drain(..) {
            let _ = del_route(&r); // gone with the device anyway
        }
        if let Some(r) = self.host_route.lock().expect("host route lock").take() {
            let _ = del_route(&r);
            let _ = std::fs::remove_file(route_record());
        }
        self.firewall.take();
    }
}

/// Undo whatever a client that died left behind: the kill switch / leak
/// rules (unless `keep_firewall`: a kill switch about to be re-armed stays
/// closed meanwhile), the resolv.conf rewrite, and the pinned host route.
pub fn cleanup_after_crash(keep_firewall: bool) -> io::Result<Vec<String>> {
    let mut done = Vec::new();
    if !keep_firewall && have("nft") {
        let present = Command::new("nft")
            .args(["list", "table", "inet", NFT_TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if present {
            remove_firewall()?;
            done.push("removed the kill-switch / leak-blocking rules".into());
        }
    }
    if restore_resolv_conf()? {
        done.push("restored /etc/resolv.conf".into());
    }
    if let Ok(rec) = std::fs::read_to_string(route_record()) {
        let f: Vec<&str> = rec.split_whitespace().collect();
        if let [ip, gw, dev] = f[..] {
            if let Ok(dst) = ip.parse() {
                let r = Route { dst, prefix: 32, gateway: gw.parse().ok(), dev: Some(dev.to_string()) };
                let _ = del_route(&r);
                done.push(format!("removed the host route to {ip}"));
            }
        }
        let _ = std::fs::remove_file(route_record());
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_failure_keeps_firewall() {
        // Separate process: PATH changes cannot affect concurrent tests, and
        // the fake nft never changes the host firewall or requires privileges.
        if let Some(dir) = std::env::var_os("SHAIP_FIREWALL_TEST_DIR") {
            let result = FullTunnel::up(FullTunnelOpts {
                tun: "pq-test".into(), server: "[::1]:443".parse().unwrap(),
                redirect_default: true, dns: None, block_ipv6: true, kill_switch: true,
            });
            assert!(result.is_err(), "IPv6 full-tunnel endpoint must fail after firewall setup");
            let calls = std::fs::read_to_string(PathBuf::from(dir).join("calls")).unwrap();
            assert_eq!(calls.lines().count(), 1, "setup failure must not issue a firewall removal");
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("shaip-firewall-test-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let script = dir.join("nft");
        std::fs::write(&script, b"#!/bin/sh\n[ \"$1\" = --version ] && exit 0\nprintf 'call\\n' >> \"$SHAIP_FIREWALL_TEST_DIR/calls\"\nwhile IFS= read -r line; do :; done\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "netcfg::tests::setup_failure_keeps_firewall", "--nocapture"])
            .env("SHAIP_FIREWALL_TEST_DIR", &dir).env("PATH", &dir).output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    }

    #[test]
    fn rtentry_matches_the_kernel_layout() {
        #[cfg(target_pointer_width = "64")]
        assert_eq!(std::mem::size_of::<RtEntry>(), 120);
    }

    #[test]
    fn masks() {
        assert_eq!(mask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(mask(1), Ipv4Addr::new(128, 0, 0, 0));
        assert_eq!(mask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(mask(32), Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn leak_rules_allow_only_the_tunnel() {
        let server: SocketAddr = "203.0.113.7:443".parse().unwrap();
        let ks = nft_ruleset("pq0", server, true);
        assert!(ks.contains("oifname \"pq0\" accept"));
        assert!(ks.contains("ip daddr 203.0.113.7 udp dport 443 accept"));
        assert!(ks.trim_end().ends_with("reject with icmpx type admin-prohibited\n  }\n}"));
        let v6 = nft_ruleset("pq0", server, false);
        assert!(v6.contains("meta nfproto ipv6 reject"));
        assert!(!v6.contains("udp sport 68"), "without the kill switch, IPv4 is untouched");
    }
}
