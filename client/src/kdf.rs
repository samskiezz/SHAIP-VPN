//! Keyed derivation helpers (HKDF-SHA256) shared across modules.
//!
//! Centralizes the label scheme so every module derives keys the same way.

use hkdf::Hkdf;
use sha2::Sha256;

/// Expand `ikm` (+ optional `salt`) into `N` bytes with `info` as the label.
pub fn hkdf<const N: usize>(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; N];
    hk.expand(info, &mut out)
        .expect("HKDF expand length within bounds");
    out
}

/// Derive the two directional data keys from the mixed shared secret (§6.4).
pub fn directional_keys(ss_mix: &[u8; 32]) -> (/* c2s */ [u8; 32], /* s2c */ [u8; 32]) {
    let c2s = hkdf::<32>(ss_mix, None, b"c2s");
    let s2c = hkdf::<32>(ss_mix, None, b"s2c");
    (c2s, s2c)
}

/// Derive the 8-byte connection id, known to both sides without transmission.
pub fn conn_id(ss_mix: &[u8; 32]) -> u64 {
    let b = hkdf::<8>(ss_mix, None, b"conn-id");
    u64::from_be_bytes(b)
}

/// Derive both directional keys for a rekey epoch (§6.5).
pub fn rekey_keys(ss_mix: &[u8; 32], new_epoch: u16) -> ([u8; 32], [u8; 32]) {
    let info = format!("rekey-{new_epoch}");
    let both = hkdf::<64>(ss_mix, None, info.as_bytes());
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&both[..32]);
    s2c.copy_from_slice(&both[32..]);
    (c2s, s2c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directional_keys_differ() {
        let ss = [7u8; 32];
        let (c2s, s2c) = directional_keys(&ss);
        assert_ne!(c2s, s2c);
    }

    #[test]
    fn conn_id_is_stable() {
        let ss = [5u8; 32];
        assert_eq!(conn_id(&ss), conn_id(&ss));
    }
}
