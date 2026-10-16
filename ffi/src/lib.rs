//! C ABI for native PQ-ANON front ends (`include/pqanon.h`).
//!
//! A native shell — an iOS/macOS Network Extension, an Android `VpnService`, a
//! Windows service — owns the OS packet interface and calls into this library
//! to enroll the device and run the tunnel. `pqanon_tunnel_connect` performs
//! the PQANON-HS/1 handshake and returns once the server has confirmed the
//! session; `pqanon_tunnel_send` / `pqanon_tunnel_recv` move whole IP packets.
//! It is the same `pqanon::client` code the CLI runs, not a parallel copy.
//!
//! Every entry point is null-safe and panic-safe: a panic becomes an error
//! return and never unwinds into C. Strings handed to C (errors, ids,
//! accounts) are heap-allocated and must be released with
//! `pqanon_string_free`. One thread may send while another receives on the
//! same tunnel.

use pqanon::client::{ClientConfig, Tunnel};
use pqanon::handshake::PeerPublic;
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
        let server = arg(server, "server")?.to_string();
        let pq = hex::decode(arg(server_ml_dsa_pub_hex, "server_ml_dsa_pub_hex")?.trim())
            .map_err(|e| format!("server_ml_dsa_pub_hex: {e}"))?;
        let ed = hex::decode(arg(server_ed_pub_hex, "server_ed_pub_hex")?.trim())
            .map_err(|e| format!("server_ed_pub_hex: {e}"))?;
        let server_pub = PeerPublic::from_bytes(&pq, &ed).map_err(|e| format!("server pins: {e:#}"))?;
        let identity = pqanon::keystore::load_or_create_identity(Path::new(arg(identity_path, "identity_path")?))
            .map_err(|e| format!("{e:#}"))?
            .0;
        let device_cert = if device_cert_path.is_null() {
            None
        } else {
            let p = arg(device_cert_path, "device_cert_path")?;
            Some(
                std::fs::read_to_string(p)
                    .map_err(|e| format!("reading device certificate {p}: {e}"))?
                    .trim()
                    .to_string(),
            )
        };
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;
        let tunnel = rt
            .block_on(Tunnel::connect(ClientConfig {
                server,
                server_pub,
                identity,
                device_cert,
                handshake_timeout: Duration::from_millis(u64::from(timeout_ms.max(1))),
            }))
            .map_err(|e| format!("{e:#}"))?;
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
/// device id (hex; free it), or NULL.
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
        let done = pqanon::enroll_client::enroll(
            arg(link, "link")?,
            arg(server, "server")?,
            &authority,
            &ca,
            Path::new(arg(identity_path, "identity_path")?),
            if name.is_null() { "device" } else { arg(name, "name")? },
            None,
        )
        .map_err(|e| format!("{e:#}"))?;
        Ok(to_c(hex::encode(done.cert.device_id)))
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
