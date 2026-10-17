//! C ABI for native SHAIP VPN front ends (`include/pqanon.h`).
//!
//! A native shell — an iOS/macOS Network Extension, an Android `VpnService`, a
//! Windows service — owns the OS packet interface and calls into this library
//! to enroll the device and run the tunnel. It is the same `pqanon` code the
//! CLI runs, not a parallel copy:
//!
//! - `pqanon_session_*` is what an app should use: the reconnecting link the
//!   CLI's `pqanon run` uses (`pqanon::supervisor`), with keepalive RTT,
//!   dead-peer detection, reconnection and rekeying, and a status snapshot to
//!   show the user.
//! - `pqanon_tunnel_*` is one bare session (no keepalive, no reconnect), for
//!   probes and tests.
//!
//! Every entry point is null-safe and panic-safe: a panic becomes an error
//! return and never unwinds into C. Strings handed to C (errors, ids,
//! accounts) are heap-allocated and must be released with
//! `pqanon_string_free`. One thread may send while another receives on the
//! same tunnel.

use pqanon::client::{ClientConfig, Tunnel};
use pqanon::handshake::PeerPublic;
use pqanon::supervisor::{LinkState, ManagedTunnel, SupervisorConfig};
use std::ffi::{c_char, c_int, c_long, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Duration;

/// An established tunnel plus the runtime that drives its socket.
pub struct PqanonTunnel {
    rt: tokio::runtime::Runtime,
    tunnel: Tunnel,
}

/// Traffic counters (mirrors `pqanon::client::TunnelStats`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PqanonStats {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_dropped: u64,
}

fn set_err(err: *mut *mut c_char, msg: &str) {
    if err.is_null() {
        return;
    }
    let s = CString::new(msg.replace('\0', " ")).unwrap_or_default();
    // SAFETY: the caller passed a valid out-pointer (checked non-null above).
    unsafe { *err = s.into_raw() };
}

/// Run `f`, mapping an error or a panic to `fallback` plus an error string.
fn guard<T>(err: *mut *mut c_char, fallback: T, f: impl FnOnce() -> Result<T, String>) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            set_err(err, &e);
            fallback
        }
        Err(_) => {
            set_err(err, "internal panic in pqanon (a bug)");
            fallback
        }
    }
}

/// Borrow a required C string argument.
///
/// # Safety
/// `p` must be NULL or a valid NUL-terminated string.
unsafe fn arg<'a>(p: *const c_char, name: &str) -> Result<&'a str, String> {
    if p.is_null() {
        return Err(format!("{name} is NULL"));
    }
    CStr::from_ptr(p).to_str().map_err(|_| format!("{name} is not UTF-8"))
}

fn to_c(s: String) -> *mut c_char {
    CString::new(s).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The connection arguments shared by `pqanon_tunnel_connect` and
/// `pqanon_session_start`, copied out of C memory (so they can move to
/// another thread).
struct ConnectArgs {
    server: String,
    pq_hex: String,
    ed_hex: String,
    identity_path: String,
    device_cert_path: Option<String>,
    timeout_ms: u32,
}

impl ConnectArgs {
    /// # Safety
    /// String arguments must be NULL or valid NUL-terminated strings.
    unsafe fn from_c(
        server: *const c_char,
        server_ml_dsa_pub_hex: *const c_char,
        server_ed_pub_hex: *const c_char,
        identity_path: *const c_char,
        device_cert_path: *const c_char,
        timeout_ms: u32,
    ) -> Result<ConnectArgs, String> {
        Ok(ConnectArgs {
            server: arg(server, "server")?.to_string(),
            pq_hex: arg(server_ml_dsa_pub_hex, "server_ml_dsa_pub_hex")?.to_string(),
            ed_hex: arg(server_ed_pub_hex, "server_ed_pub_hex")?.to_string(),
            identity_path: arg(identity_path, "identity_path")?.to_string(),
            device_cert_path: if device_cert_path.is_null() {
                None
            } else {
                Some(arg(device_cert_path, "device_cert_path")?.to_string())
            },
            timeout_ms,
        })
    }

    /// Load the pins, the identity (created on first use) and the certificate.
    fn config(self) -> Result<ClientConfig, String> {
        let pq = hex::decode(self.pq_hex.trim()).map_err(|e| format!("server_ml_dsa_pub_hex: {e}"))?;
        let ed = hex::decode(self.ed_hex.trim()).map_err(|e| format!("server_ed_pub_hex: {e}"))?;
        let server_pub = PeerPublic::from_bytes(&pq, &ed).map_err(|e| format!("server pins: {e:#}"))?;
        let identity = pqanon::keystore::load_or_create_identity(Path::new(&self.identity_path))
            .map_err(|e| format!("{e:#}"))?
            .0;
        let device_cert = match self.device_cert_path {
            None => None,
            Some(p) => Some(
                std::fs::read_to_string(&p)
                    .map_err(|e| format!("reading device certificate {p}: {e}"))?
                    .trim()
                    .to_string(),
            ),
        };
        Ok(ClientConfig {
            server: self.server,
            server_pub,
            identity,
            device_cert,
            handshake_timeout: Duration::from_millis(u64::from(self.timeout_ms.max(1))),
        })
    }
}

/// Run `f` on a thread with a 16 MiB stack and wait for it. ML-DSA-65 key
/// generation and signing need far more stack than some callers' threads
/// have (iOS gives secondary threads 512 KiB), and `block_on` runs a future
/// on the calling thread. A panic is re-raised here, inside the caller's
/// `guard`.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    match std::thread::Builder::new()
        .name("pqanon-handshake".into())
        .stack_size(16 << 20)
        .spawn(f)
        .map(|h| h.join())
    {
        Ok(Ok(v)) => v,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(e) => panic!("cannot start a handshake thread: {e}"),
    }
}

/// The runtime driving a tunnel's socket. Handshakes (ML-DSA-65 signing)
/// need more stack than tokio's 2 MiB default on reconnects, which run on
/// worker threads.
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 << 20)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))
}

/// Library version (static string; do not free).
#[no_mangle]
pub extern "C" fn pqanon_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Connect to a pqanond server and wait for it to confirm the session.
///
/// # Safety
/// String arguments must be NULL or valid NUL-terminated strings;
/// `device_cert_path` may be NULL. `err` may be NULL or point to a `char *`.
#[no_mangle]
pub unsafe extern "C" fn pqanon_tunnel_connect(
    server: *const c_char,
    server_ml_dsa_pub_hex: *const c_char,
    server_ed_pub_hex: *const c_char,
    identity_path: *const c_char,
    device_cert_path: *const c_char,
    timeout_ms: u32,
    err: *mut *mut c_char,
) -> *mut PqanonTunnel {
    guard(err, std::ptr::null_mut(), || {
        let args = ConnectArgs::from_c(server, server_ml_dsa_pub_hex, server_ed_pub_hex, identity_path, device_cert_path, timeout_ms)?;
        let (rt, tunnel) = on_big_stack(move || {
            let cfg = args.config()?;
            let rt = runtime()?;
            let tunnel = rt.block_on(Tunnel::connect(cfg)).map_err(|e| format!("{e:#}"))?;
            Ok::<_, String>((rt, tunnel))
        })?;
        Ok(Box::into_raw(Box::new(PqanonTunnel { rt, tunnel })))
    })
}

/// Send one IP packet. Returns 0, or -1 on error.
///
/// # Safety
/// `t` must come from `pqanon_tunnel_connect`; `pkt` must point to `len`
/// readable bytes (or be NULL with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn pqanon_tunnel_send(
    t: *const PqanonTunnel,
    pkt: *const u8,
    len: usize,
    err: *mut *mut c_char,
) -> c_int {
    guard(err, -1, || {
        let t = t.as_ref().ok_or("tunnel is NULL")?;
        if pkt.is_null() && len > 0 {
            return Err("pkt is NULL".into());
        }
        let data = if len == 0 { &[][..] } else { std::slice::from_raw_parts(pkt, len) };
        t.rt.block_on(t.tunnel.send(data)).map_err(|e| format!("{e:#}"))?;
        Ok(0)
    })
}

/// Receive one IP packet into `buf`. Returns its length, 0 if `timeout_ms`
/// elapsed first, or -1 on error (including a packet larger than `cap`;
/// `PQANON_MAX_PACKET` always suffices).
///
/// # Safety
/// `t` must come from `pqanon_tunnel_connect`; `buf` must point to `cap`
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pqanon_tunnel_recv(
    t: *const PqanonTunnel,
    buf: *mut u8,
    cap: usize,
    timeout_ms: u32,
    err: *mut *mut c_char,
) -> c_long {
    guard(err, -1, || {
        let t = t.as_ref().ok_or("tunnel is NULL")?;
        if buf.is_null() {
            return Err("buf is NULL".into());
        }
        let wait = Duration::from_millis(u64::from(timeout_ms));
        match t.rt.block_on(async { tokio::time::timeout(wait, t.tunnel.recv()).await }) {
            Err(_) => Ok(0),
            Ok(Err(e)) => Err(format!("{e:#}")),
            Ok(Ok(pkt)) => {
                if pkt.len() > cap {
                    return Err(format!("a {}-byte packet does not fit a {cap}-byte buffer", pkt.len()));
                }
                std::ptr::copy_nonoverlapping(pkt.as_ptr(), buf, pkt.len());
                Ok(pkt.len() as c_long)
            }
        }
    })
}

/// The tunnel address the server assigned, as a host-order integer
/// (`0x0A4D0002` = 10.77.0.2), or 0 if it assigned none (echo-mode server).
///
/// # Safety
/// `t` must be NULL or come from `pqanon_tunnel_connect`.
#[no_mangle]
pub unsafe extern "C" fn pqanon_tunnel_assigned_ipv4(t: *const PqanonTunnel) -> u32 {
    t.as_ref()
        .and_then(|t| t.tunnel.info().assigned_v4)
        .map(u32::from)
        .unwrap_or(0)
}

/// Copy the traffic counters into `out`. Returns 0, or -1 if an argument is NULL.
///
/// # Safety
/// `t` must come from `pqanon_tunnel_connect`; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn pqanon_tunnel_stats(t: *const PqanonTunnel, out: *mut PqanonStats) -> c_int {
    let (Some(t), false) = (t.as_ref(), out.is_null()) else {
        return -1;
    };
    let s = t.tunnel.stats();
    *out = PqanonStats {
        packets_sent: s.packets_sent,
        bytes_sent: s.bytes_sent,
        packets_received: s.packets_received,
        bytes_received: s.bytes_received,
        packets_dropped: s.packets_dropped,
    };
    0
}

/// Close the tunnel and free it. NULL is a no-op.
///
/// # Safety
/// `t` must be NULL or come from `pqanon_tunnel_connect`, and must not be
/// used afterwards.
#[no_mangle]
pub unsafe extern "C" fn pqanon_tunnel_close(t: *mut PqanonTunnel) {
    if !t.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(t))));
    }
}

// --- Reconnecting session (pqanon::supervisor) ------------------------------

/// A link that stays up: reconnects, rekeys, keepalive RTT.
pub struct PqanonSession {
    // Declared first so it drops first: its sockets go before their runtime.
    link: ManagedTunnel,
    rt: tokio::runtime::Runtime,
}

/// `PqanonStatus.state` values.
pub const PQANON_STATE_CONNECTED: i32 = 0;
pub const PQANON_STATE_RECONNECTING: i32 = 1;
pub const PQANON_STATE_STOPPED: i32 = 2;

/// A status snapshot (mirrors `pqanon::supervisor::Status`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PqanonStatus {
    /// PQANON_STATE_*.
    pub state: i32,
    /// Server-assigned tunnel address, host order; 0 if none.
    pub assigned_ipv4: u32,
    pub prefix_len: u8,
    /// The server's tunnel address (the client's gateway); 0 if none.
    pub gateway_ipv4: u32,
    /// Resolver to use while connected (reached through the tunnel); 0: none pushed.
    pub dns_ipv4: u32,
    /// MTU for the tunnel interface.
    pub mtu: u16,
    /// Smoothed keepalive round-trip time in microseconds; 0 until measured.
    pub rtt_us: u32,
    /// When the link came up (Unix ms; rekeys do not reset it); 0 while down.
    pub up_since_unix_ms: u64,
    pub reconnects: u32,
    pub rekeys: u32,
    /// Totals across every session of this link.
    pub stats: PqanonStats,
    /// Outbound packets dropped because no session was up.
    pub dropped_offline: u64,
    /// The server's identity id (`pqanond --print-public` shows it as
    /// `identity_id`), proven by the handshake against the pinned keys.
    pub server_identity: [u8; 16],
}

/// Connect to a pqanond server, wait for it to confirm the first session, and
/// keep the link up from then on. Arguments as for `pqanon_tunnel_connect`.
/// Returns NULL (and `*err`) if the first connection fails — wrong pins, not
/// admitted, unreachable — so a misconfiguration surfaces at once.
///
/// # Safety
/// String arguments must be NULL or valid NUL-terminated strings;
/// `device_cert_path` may be NULL. `err` may be NULL or point to a `char *`.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_start(
    server: *const c_char,
    server_ml_dsa_pub_hex: *const c_char,
    server_ed_pub_hex: *const c_char,
    identity_path: *const c_char,
    device_cert_path: *const c_char,
    timeout_ms: u32,
    err: *mut *mut c_char,
) -> *mut PqanonSession {
    guard(err, std::ptr::null_mut(), || {
        let args = ConnectArgs::from_c(server, server_ml_dsa_pub_hex, server_ed_pub_hex, identity_path, device_cert_path, timeout_ms)?;
        let (link, rt) = on_big_stack(move || {
            let cfg = Box::new(args.config()?);
            let rt = runtime()?;
            let link = rt
                .block_on(ManagedTunnel::start(SupervisorConfig::new(*cfg)))
                .map_err(|e| format!("{e:#}"))?;
            Ok::<_, String>((link, rt))
        })?;
        Ok(Box::into_raw(Box::new(PqanonSession { link, rt })))
    })
}

/// Send one IP packet. While the link is reconnecting the packet is dropped
/// (and counted), never sent elsewhere. Returns 0, or -1 for bad arguments.
///
/// # Safety
/// `s` must come from `pqanon_session_start` and not be freed; `pkt` must
/// point to `len` readable bytes (or be NULL with `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_send(s: *const PqanonSession, pkt: *const u8, len: usize) -> c_int {
    guard(std::ptr::null_mut(), -1, || {
        let s = s.as_ref().ok_or("session is NULL")?;
        if pkt.is_null() && len > 0 {
            return Err("pkt is NULL".into());
        }
        let data = if len == 0 { &[][..] } else { std::slice::from_raw_parts(pkt, len) };
        s.rt.block_on(s.link.send(data));
        Ok(0)
    })
}

/// Receive one IP packet into `buf`, across reconnects. Returns its length, 0
/// if `timeout_ms` elapsed first, or -1 once the session is stopped (or for a
/// packet larger than `cap`; `PQANON_MAX_PACKET` always suffices).
///
/// # Safety
/// `s` must come from `pqanon_session_start` and not be freed; `buf` must
/// point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_recv(
    s: *const PqanonSession,
    buf: *mut u8,
    cap: usize,
    timeout_ms: u32,
    err: *mut *mut c_char,
) -> c_long {
    guard(err, -1, || {
        let s = s.as_ref().ok_or("session is NULL")?;
        if buf.is_null() {
            return Err("buf is NULL".into());
        }
        let wait = Duration::from_millis(u64::from(timeout_ms));
        match s.rt.block_on(async { tokio::time::timeout(wait, s.link.recv()).await }) {
            Err(_) => Ok(0),
            Ok(Err(e)) => Err(format!("{e:#}")),
            Ok(Ok(pkt)) => {
                if pkt.len() > cap {
                    return Err(format!("a {}-byte packet does not fit a {cap}-byte buffer", pkt.len()));
                }
                std::ptr::copy_nonoverlapping(pkt.as_ptr(), buf, pkt.len());
                Ok(pkt.len() as c_long)
            }
        }
    })
}

/// Copy a status snapshot into `out`. Returns 0, or -1 if an argument is NULL.
///
/// # Safety
/// `s` must come from `pqanon_session_start` and not be freed; `out` must be
/// writable.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_status(s: *const PqanonSession, out: *mut PqanonStatus) -> c_int {
    guard(std::ptr::null_mut(), -1, || {
        let (Some(s), false) = (s.as_ref(), out.is_null()) else {
            return Err("NULL argument".into());
        };
        let st = s.link.status();
        let v4 = |a: Option<std::net::Ipv4Addr>| a.map(u32::from).unwrap_or(0);
        *out = PqanonStatus {
            state: match st.state {
                LinkState::Connected => PQANON_STATE_CONNECTED,
                LinkState::Reconnecting => PQANON_STATE_RECONNECTING,
                LinkState::Stopped => PQANON_STATE_STOPPED,
            },
            assigned_ipv4: v4(st.info.assigned_v4),
            prefix_len: st.info.prefix_len,
            gateway_ipv4: v4(st.info.gateway_v4),
            dns_ipv4: v4(st.info.dns_v4),
            mtu: st.info.effective_mtu(),
            rtt_us: st.rtt.map(|r| r.as_micros().min(u128::from(u32::MAX)) as u32).unwrap_or(0),
            up_since_unix_ms: st
                .up_since
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            reconnects: st.reconnects,
            rekeys: st.rekeys,
            stats: PqanonStats {
                packets_sent: st.stats.packets_sent,
                bytes_sent: st.stats.bytes_sent,
                packets_received: st.stats.packets_received,
                bytes_received: st.stats.bytes_received,
                packets_dropped: st.stats.packets_dropped,
            },
            dropped_offline: st.dropped_offline,
            server_identity: st.server_identity,
        };
        Ok(0)
    })
}

/// The server's UDP address as resolved and used (e.g. `"203.0.113.7:443"`),
/// for the OS's tunnel-endpoint setting. Free it; NULL on bad arguments.
///
/// # Safety
/// `s` must come from `pqanon_session_start` and not be freed.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_server_addr(s: *const PqanonSession) -> *mut c_char {
    match s.as_ref() {
        Some(s) => to_c(s.link.status().server_addr.to_string()),
        None => std::ptr::null_mut(),
    }
}

/// Why the last session ended or the last attempt failed (free it), or NULL.
///
/// # Safety
/// `s` must come from `pqanon_session_start` and not be freed.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_last_error(s: *const PqanonSession) -> *mut c_char {
    s.as_ref()
        .and_then(|s| s.link.status().last_error)
        .map(to_c)
        .unwrap_or(std::ptr::null_mut())
}

/// Renegotiate now (call when the device changes networks; waiting for the
/// dead-peer timer would leave the user offline meanwhile). Returns 0, or -1
/// if `s` is NULL.
///
/// # Safety
/// `s` must come from `pqanon_session_start` and not be freed.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_reconnect(s: *const PqanonSession) -> c_int {
    match s.as_ref() {
        Some(s) => {
            s.link.reconnect_now("the network changed");
            0
        }
        None => -1,
    }
}

/// Close the session (telling the server) and stop reconnecting. Blocked and
/// later `pqanon_session_recv` calls return -1. The session stays allocated:
/// free it with `pqanon_session_free` once no other thread is inside a
/// `pqanon_session_*` call. NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or come from `pqanon_session_start` and not be freed.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_stop(s: *const PqanonSession) {
    if let Some(s) = s.as_ref() {
        let _ = catch_unwind(AssertUnwindSafe(|| s.rt.block_on(s.link.stop())));
    }
}

/// Free a session (stopping it first if needed). No other thread may be
/// inside a `pqanon_session_*` call on it. NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or come from `pqanon_session_start`, freed only once.
#[no_mangle]
pub unsafe extern "C" fn pqanon_session_free(s: *mut PqanonSession) {
    if !s.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let s = Box::from_raw(s);
            s.rt.block_on(s.link.stop());
            drop(s);
        }));
    }
}

/// Verify a `pqanon://enroll` link (or bare token) against the pinned
/// enrollment-authority key, locally — what a deep-link handler checks before
/// asking the user to confirm. Returns 0 and sets `*account_out`, or -1.
///
/// # Safety
/// String arguments must be NULL or valid NUL-terminated strings;
/// `account_out` and `err` may be NULL or point to a `char *`.
#[no_mangle]
pub unsafe extern "C" fn pqanon_enroll_link_verify(
    link: *const c_char,
    authority_pub_hex: *const c_char,
    account_out: *mut *mut c_char,
    err: *mut *mut c_char,
) -> c_int {
    guard(err, -1, || {
        let link = arg(link, "link")?;
        let authority = pqanon::enroll_client::parse_pin(arg(authority_pub_hex, "authority_pub_hex")?, "authority key")
            .map_err(|e| e.to_string())?;
        let token = if link.starts_with("pqanon://") {
            pqanon::enrollment::parse_enroll_url(link).map_err(|e| e.to_string())?
        } else {
            link.trim().to_string()
        };
        let claims = pqanon::enrollment::verify_enroll_token(&authority, &token, unix_now())
            .map_err(|e| format!("refusing this enrollment link: {e}"))?;
        if !account_out.is_null() {
            *account_out = to_c(claims.account);
        }
        Ok(0)
    })
}

/// Enroll this device: verify the link, prove possession of the identity key,
/// and verify + store the certificate at `<identity_path>.cert`. Returns the
/// device id (hex; free it), or NULL. `name` is reduced to a platform label
/// (iPhone, iPad, Android, Windows, Linux, Mac, or "device") before anything
/// is sent: pass the platform, never the user's device name.
///
/// # Safety
/// String arguments must be NULL or valid NUL-terminated strings; `err` may
/// be NULL or point to a `char *`.
#[no_mangle]
pub unsafe extern "C" fn pqanon_enroll(
    link: *const c_char,
    server: *const c_char,
    authority_pub_hex: *const c_char,
    ca_pub_hex: *const c_char,
    identity_path: *const c_char,
    name: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guard(err, std::ptr::null_mut(), || {
        let authority = pqanon::enroll_client::parse_pin(arg(authority_pub_hex, "authority_pub_hex")?, "authority key")
            .map_err(|e| e.to_string())?;
        let ca = pqanon::enroll_client::parse_pin(arg(ca_pub_hex, "ca_pub_hex")?, "CA key").map_err(|e| e.to_string())?;
        let (link, server) = (arg(link, "link")?.to_string(), arg(server, "server")?.to_string());
        let identity = arg(identity_path, "identity_path")?.to_string();
        let name = if name.is_null() { "device".to_string() } else { arg(name, "name")?.to_string() };
        // Creating the identity on first use is ML-DSA-65 key generation.
        let device_id = on_big_stack(move || {
            pqanon::enroll_client::enroll(&link, &server, &authority, &ca, Path::new(&identity), &name, None)
                .map(|done| hex::encode(done.cert.device_id))
                .map_err(|e| format!("{e:#}"))
        })?;
        Ok(to_c(device_id))
    })
}

/// Free a string this library returned. NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or a string returned by this library, freed only once.
#[no_mangle]
pub unsafe extern "C" fn pqanon_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    /// The hand-written header must declare every exported function, so it
    /// cannot silently fall behind the library.
    #[test]
    fn header_declares_every_export() {
        let header = include_str!("../include/pqanon.h");
        let src = include_str!("lib.rs");
        let exports: Vec<&str> = src
            .lines()
            .filter_map(|l| l.trim().strip_prefix("pub unsafe extern \"C\" fn ").or_else(|| l.trim().strip_prefix("pub extern \"C\" fn ")))
            .map(|rest| rest.split('(').next().unwrap())
            .collect();
        assert!(exports.len() >= 10, "found only {exports:?}");
        for f in exports {
            assert!(header.contains(&format!("{f}(")), "{f} is exported but not declared in pqanon.h");
        }
    }

    #[test]
    fn null_arguments_fail_cleanly() {
        use std::ffi::{c_char, CStr};
        let mut err: *mut c_char = std::ptr::null_mut();
        let t = unsafe {
            super::pqanon_tunnel_connect(
                std::ptr::null(), std::ptr::null(), std::ptr::null(),
                std::ptr::null(), std::ptr::null(), 100, &mut err,
            )
        };
        assert!(t.is_null());
        let msg = unsafe { CStr::from_ptr(err) }.to_str().unwrap().to_string();
        assert!(msg.contains("server is NULL"), "{msg}");
        unsafe { super::pqanon_string_free(err) };
        assert_eq!(unsafe { super::pqanon_tunnel_send(std::ptr::null(), std::ptr::null(), 0, std::ptr::null_mut()) }, -1);
        assert_eq!(unsafe { super::pqanon_tunnel_assigned_ipv4(std::ptr::null()) }, 0);
        unsafe { super::pqanon_tunnel_close(std::ptr::null_mut()) };
    }
}
