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
