//! SHAIP VPN client core library (`shaip`).
//!
//! Implements the SHAIP/1 protocol family:
//! - [`wire`]      — SHAIP/1 common envelope (AEAD framing).
//! - [`handshake`] — SHAIP-HS/1 hybrid post-quantum handshake.
//! - [`obf`]       — SHAIP-OBF/1 header morphing + length shaping.
//! - [`transport`] — SHAIP-UDP/1 reliability + custom congestion control.
//! - [`mix`]       — SHAIP-MIX/1 fixed-size onion cells.
//! - [`routing`]   — fast/anon per-domain routing policy.
//!
//! All cryptography is built on standard-library / RustCrypto primitives
//! (ML-KEM-768, ML-DSA-65, X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256,
//! HMAC-SHA256). No hand-rolled primitives. The cryptographic core is safe
//! Rust; the only FFI is the Linux TUN binding in [`tun`], which is isolated
//! and necessarily uses libc.

pub mod bloom;
pub mod client;
pub mod crl;
pub mod ctl;
pub mod dataplane;
pub mod decoy;
pub mod descriptor;
pub mod directory;
pub mod dnssec;
pub mod enroll_client;
pub mod enrollment;
pub mod handshake;
pub mod i18n;
pub mod icmp;
pub mod ipparse;
pub mod kdf;
pub mod keystore;
pub mod metrics;
pub mod mix;
pub mod obf;
pub mod redact;
pub mod retry;
pub mod router;
pub mod routing;
pub mod supervisor;
pub mod transport;
pub mod wire;

/// Linux TUN device binding for the data plane (§19). Linux only.
#[cfg(target_os = "linux")]
pub mod tun;

/// Linux routes, DNS and leak blocking for a full-tunnel client.
#[cfg(target_os = "linux")]
pub mod netcfg;

/// Linux UDP segmentation/aggregation offload (GSO/GRO) for the data path.
#[cfg(target_os = "linux")]
pub mod udp_offload;

// Supporting library primitives for the §19 integration backlog. Self-contained
// and unit-tested; wired into the daemons as those features land.
pub mod delayed_ack;
pub mod dns_cache;
pub mod dns_neg;
pub mod dns_resolver;
pub mod pay_client;
pub mod payment;
pub mod dns_qmin;
pub mod dns_tcp;
pub mod entropy;
pub mod fec;
pub mod hex_util;
pub mod identity_check;
pub mod mix_cover;
pub mod mix_delay;
pub mod mix_reputation;
pub mod perm_check;
pub mod reconnect;
pub mod secure_write;
pub mod stream;

// Further backlog primitives (quotas/QoS, transport drivers, client UX).
pub mod allowlist;
pub mod app_routing;
pub mod autostart;
pub mod battery;
pub mod blacklist;
pub mod bulk;
pub mod bw_limit;
pub mod conn_rate;
pub mod fingerprint;
pub mod idle;
pub mod loss_burst;
pub mod notify;
pub mod pacing_budget;
pub mod path_cache;
pub mod progress;
pub mod qos;
pub mod quota;
pub mod retx_queue;
pub mod send_window;
pub mod stream_sched;
pub mod threshold;
pub mod timeout;
pub mod wifi;
