//! PQ-ANON client core library (`pqanon`).
//!
//! Implements the PQANON/1 protocol family:
//! - [`wire`]      — PQANON/1 common envelope (AEAD framing).
//! - [`handshake`] — PQANON-HS/1 hybrid post-quantum handshake.
//! - [`obf`]       — PQANON-OBF/1 header morphing + length shaping.
//! - [`transport`] — PQANON-UDP/1 reliability + custom congestion control.
//! - [`mix`]       — PQANON-MIX/1 fixed-size onion cells.
//! - [`routing`]   — fast/anon per-domain routing policy.
//!
//! All cryptography is built on standard-library / RustCrypto primitives
//! (ML-KEM-768, ML-DSA-65, X25519, Ed25519, ChaCha20-Poly1305, HKDF-SHA256,
//! HMAC-SHA256). No hand-rolled primitives.

pub mod handshake;
pub mod kdf;
pub mod mix;
pub mod obf;
pub mod routing;
pub mod transport;
pub mod wire;

// Supporting library primitives for the §19 integration backlog. Self-contained
// and unit-tested; wired into the daemons as those features land.
pub mod delayed_ack;
pub mod dns_cache;
pub mod dns_neg;
pub mod dns_qmin;
pub mod dns_tcp;
pub mod entropy;
pub mod hex_util;
pub mod identity_check;
pub mod mix_cover;
pub mod mix_delay;
pub mod mix_reputation;
pub mod perm_check;
pub mod reconnect;
pub mod secure_write;
pub mod stream;
