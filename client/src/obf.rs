//! PQANON-OBF/1 — header morphing, length shaping, timing jitter (§9).
//!
//! Goal: after morphing, no fixed bytes (not even the `PQAN` magic) ever appear
//! on the wire, and two packets with identical plaintext produce different wire
//! bytes. This module implements the reversible transforms; the timing jitter
//! buffer and cover-traffic scheduler live in [`crate::transport`].
//!
//! Wire layout produced by [`Obfuscator::morph`]:
//!
//! ```text
//! byte 0            : (prefix_len << 4) | random_low_nibble
//! bytes 1..1+P      : P = prefix_len random bytes
//! next 2 bytes      : real datagram length (big-endian) XOR morph_key[0..2]
//! next T bytes      : datagram, header permuted+XORed, then random padding to T
//! ```

use crate::wire::HEADER_LEN;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

/// 16 target sizes, shaped to resemble the size distribution of HTTPS/TLS 1.3
/// on port 443. Shipped as a static default (§9.2); refreshable at runtime.
pub const PADDING_TABLE: [u16; 16] = [
    128, 192, 256, 320, 384, 448, 512, 640, 768, 896, 1024, 1152, 1280, 1408, 1536, 2048,
];

pub struct Obfuscator {
    morph_key: [u8; 64],
    padding_table: [u16; 16],
}

impl Obfuscator {
    /// Derive the per-epoch morph key: `HKDF(ss_mix, info = "morph-{epoch}", 64)`.
    pub fn new(ss_mix: &[u8; 32], epoch: u16) -> Self {
        let hk = Hkdf::<Sha256>::new(None, ss_mix);
        let mut key = [0u8; 64];
        hk.expand(format!("morph-{epoch}").as_bytes(), &mut key)
            .expect("64 bytes within HKDF bound");
        Self {
            morph_key: key,
            padding_table: PADDING_TABLE,
        }
    }

    /// Replace the length-shaping table (e.g. from refreshed local statistics).
    pub fn set_padding_table(&mut self, table: [u16; 16]) {
        self.padding_table = table;
    }

    /// Pad, permute, XOR, and prepend a random prefix. Returns the on-wire bytes.
    pub fn morph(&self, datagram: &[u8]) -> Vec<u8> {
        let real_len = datagram.len();
        let target = self.pick_size(real_len);

        // Permute + XOR the first HEADER_LEN bytes of the datagram.
        let mut body = datagram.to_vec();
        let perm = self.header_permutation();
        permute_header(&mut body, &perm, &self.morph_key);

        // Pad the body up to the shaped target with random bytes.
        let mut pad = vec![0u8; target.saturating_sub(real_len)];
        rand::rngs::OsRng.fill_bytes(&mut pad);
        body.extend_from_slice(&pad);

        // Random prefix (0..=15 bytes).
        let mut nibble = [0u8; 1];
        rand::rngs::OsRng.fill_bytes(&mut nibble);
        let prefix_len = (nibble[0] & 0x0F) as usize;
        let mut prefix = vec![0u8; prefix_len];
        rand::rngs::OsRng.fill_bytes(&mut prefix);

        // Obfuscated 2-byte real-length field.
        let len_field = (real_len as u16).to_be_bytes();
        let len_obf = [
            len_field[0] ^ self.morph_key[0],
            len_field[1] ^ self.morph_key[1],
        ];

        let mut out = Vec::with_capacity(1 + prefix_len + 2 + body.len());
        // High nibble = prefix_len; low nibble = random noise (ignored on read).
        out.push(((prefix_len as u8) << 4) | (nibble[0] >> 4));
        out.extend_from_slice(&prefix);
        out.extend_from_slice(&len_obf);
        out.extend_from_slice(&body);
        out
    }

    /// Reverse [`Obfuscator::morph`].
    pub fn demorph(&self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        if packet.is_empty() {
            anyhow::bail!("empty packet");
        }
        let prefix_len = (packet[0] >> 4) as usize;
        let len_at = 1 + prefix_len;
        if packet.len() < len_at + 2 {
            anyhow::bail!("truncated (length field)");
        }
        let real_len = u16::from_be_bytes([
            packet[len_at] ^ self.morph_key[0],
            packet[len_at + 1] ^ self.morph_key[1],
        ]) as usize;

        let body_at = len_at + 2;
        if packet.len() < body_at + real_len {
            anyhow::bail!("truncated (body shorter than declared length)");
        }
        let mut body = packet[body_at..body_at + real_len].to_vec();
        let perm = self.header_permutation();
        unpermute_header(&mut body, &perm, &self.morph_key);
        Ok(body)
    }

    fn pick_size(&self, real_len: usize) -> usize {
        for &s in &self.padding_table {
            if s as usize >= real_len {
                return s as usize;
            }
        }
        real_len.div_ceil(128) * 128
    }

    /// Deterministic Fisher-Yates permutation of the `HEADER_LEN` header byte
    /// positions, seeded from `morph_key[24..32]` (§9.1 step 3).
    fn header_permutation(&self) -> [usize; HEADER_LEN] {
        let mut seed = [0u8; 8];
        seed.copy_from_slice(&self.morph_key[24..32]);
        let mut rng = SplitMix64::new(u64::from_le_bytes(seed));

        let mut perm = [0usize; HEADER_LEN];
        for (i, slot) in perm.iter_mut().enumerate() {
            *slot = i;
        }
        // Fisher-Yates from the back.
        for i in (1..HEADER_LEN).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            perm.swap(i, j);
        }
        perm
    }
}

/// XOR the first `HEADER_LEN` bytes with `morph_key[2..2+HEADER_LEN]`, then move
/// byte `i` to position `perm[i]`.
fn permute_header(buf: &mut [u8], perm: &[usize; HEADER_LEN], key: &[u8; 64]) {
    let n = HEADER_LEN.min(buf.len());
    // XOR first (uses key bytes disjoint from the length-field key bytes 0..2).
    for i in 0..n {
        buf[i] ^= key[2 + i];
    }
    if buf.len() < HEADER_LEN {
        return; // too short to permute a full header; XOR-only is reversible
    }
    let original: [u8; HEADER_LEN] = buf[..HEADER_LEN].try_into().unwrap();
    for i in 0..HEADER_LEN {
        buf[perm[i]] = original[i];
    }
}

/// Inverse of [`permute_header`].
fn unpermute_header(buf: &mut [u8], perm: &[usize; HEADER_LEN], key: &[u8; 64]) {
    if buf.len() >= HEADER_LEN {
        let permuted: [u8; HEADER_LEN] = buf[..HEADER_LEN].try_into().unwrap();
        for i in 0..HEADER_LEN {
            buf[i] = permuted[perm[i]];
        }
    }
    let n = HEADER_LEN.min(buf.len());
    for i in 0..n {
        buf[i] ^= key[2 + i];
    }
}

/// Minimal SplitMix64 PRNG — deterministic, seeded; used only to derive the
/// header permutation from the morph key. Not used for any secret material.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn morph_demorph_roundtrip() {
        let ss = [42u8; 32];
        let obf = Obfuscator::new(&ss, 1);
        let original = b"hello pqanon".to_vec();
        let morphed = obf.morph(&original);
        let back = obf.demorph(&morphed).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn roundtrip_full_header_packet() {
        let ss = [1u8; 32];
        let obf = Obfuscator::new(&ss, 5);
        // A realistic sealed packet: 22-byte header starting with PQAN magic.
        let mut pkt = vec![0x50, 0x51, 0x41, 0x4E, 0x01, 0x04];
        pkt.extend_from_slice(&[0u8; 16]); // rest of header
        pkt.extend_from_slice(&[0xABu8; 200]); // ciphertext + tag
        let morphed = obf.morph(&pkt);
        assert_eq!(obf.demorph(&morphed).unwrap(), pkt);
    }

    #[test]
    fn magic_not_on_wire() {
        let ss = [7u8; 32];
        let obf = Obfuscator::new(&ss, 1);
        let mut pkt = vec![0x50, 0x51, 0x41, 0x4E, 0x01, 0x04];
        pkt.extend_from_slice(&[0u8; 16]);
        pkt.extend_from_slice(&[0u8; 100]);
        let morphed = obf.morph(&pkt);
        // The cleartext magic must not survive morphing.
        assert!(
            !morphed.windows(4).any(|w| w == [0x50, 0x51, 0x41, 0x4E]),
            "PQAN magic leaked onto the wire"
        );
    }

    #[test]
    fn length_shaped_to_table() {
        let ss = [3u8; 32];
        let obf = Obfuscator::new(&ss, 1);
        // 100-byte datagram → body padded to the 128 bucket.
        let morphed = obf.morph(&[0u8; 100]);
        // 1 (nibble) + prefix (0..15) + 2 (len) + 128 (body) .
        let body = morphed.len() - 1 - 2 - (morphed[0] >> 4) as usize;
        assert_eq!(body, 128);
    }

    #[test]
    fn different_each_time() {
        let ss = [9u8; 32];
        let obf = Obfuscator::new(&ss, 1);
        let a = obf.morph(b"same input");
        let b = obf.morph(b"same input");
        // Random prefix + padding make identical plaintext differ on the wire.
        assert_ne!(a, b);
    }
}
