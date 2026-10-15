//! A fixed-size Bloom filter for mix-cell replay detection (§10).
//!
//! Each mix node keeps one of these over the cells it has already processed.
//! A replayed cell is byte-for-byte identical (it is AEAD-sealed and cannot be
//! mutated in flight), so hashing the cell gives a stable replay tag. The
//! filter has no false negatives — a cell it has seen always tests present —
//! and a tunable false-positive rate set by the bit count and hash count.
//!
//! Hashing uses SHA-256 with Kirsch–Mitzenmacher double hashing: two 64-bit
//! words from one digest generate all `k` bit indices, so there is exactly one
//! hash per item regardless of `k`.

use sha2::{Digest, Sha256};

/// A bit-array Bloom filter.
pub struct BloomFilter {
    bits: Vec<u64>,
    num_bits: usize,
    num_hashes: u32,
}

impl BloomFilter {
    /// Create a filter with `num_bits` bits and `num_hashes` hash functions.
    /// Both are clamped to at least 1.
    pub fn new(num_bits: usize, num_hashes: u32) -> Self {
        let num_bits = num_bits.max(1);
        let words = num_bits.div_ceil(64);
        Self {
            bits: vec![0u64; words],
            num_bits,
            num_hashes: num_hashes.max(1),
        }
    }

    fn indices(&self, item: &[u8]) -> Vec<usize> {
        let digest = Sha256::digest(item);
        let h1 = u64::from_le_bytes(digest[0..8].try_into().unwrap());
        // Force h2 odd so it is coprime with any power-of-two-ish span and
        // the generated indices cycle through distinct positions.
        let h2 = u64::from_le_bytes(digest[8..16].try_into().unwrap()) | 1;
        let m = self.num_bits as u64;
        (0..self.num_hashes)
            .map(|i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % m) as usize)
            .collect()
    }

    /// Record `item` as seen.
    pub fn insert(&mut self, item: &[u8]) {
        for idx in self.indices(item) {
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
    }

    /// Test whether `item` has (probably) been seen. No false negatives.
    pub fn contains(&self, item: &[u8]) -> bool {
        self.indices(item)
            .into_iter()
            .all(|idx| self.bits[idx / 64] & (1u64 << (idx % 64)) != 0)
    }

    /// Atomically test-and-record. Returns `true` if the item was already
    /// present (i.e. this is a probable replay); otherwise records it and
    /// returns `false`. This is the primitive a mix node calls per cell.
    pub fn check_and_insert(&mut self, item: &[u8]) -> bool {
        let idxs = self.indices(item);
        let present = idxs
            .iter()
            .all(|&idx| self.bits[idx / 64] & (1u64 << (idx % 64)) != 0);
        if !present {
            for idx in idxs {
                self.bits[idx / 64] |= 1u64 << (idx % 64);
            }
        }
        present
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_inserted_items() {
        let mut bf = BloomFilter::new(1 << 16, 4);
        bf.insert(b"hello");
        assert!(bf.contains(b"hello"));
        assert!(!bf.contains(b"world"));
    }

    #[test]
    fn check_and_insert_flags_replays() {
        let mut bf = BloomFilter::new(1 << 16, 4);
        assert!(!bf.check_and_insert(b"cell-tag-1"), "first sighting is not a replay");
        assert!(bf.check_and_insert(b"cell-tag-1"), "second sighting is a replay");
        assert!(!bf.check_and_insert(b"cell-tag-2"), "a different cell is not a replay");
    }

    #[test]
    fn never_has_false_negatives() {
        // A Bloom filter guarantees no false negatives: everything inserted
        // always tests present. This is deterministic, not probabilistic.
        let mut bf = BloomFilter::new(1 << 20, 7);
        for i in 0..2000u32 {
            bf.insert(&i.to_le_bytes());
        }
        for i in 0..2000u32 {
            assert!(bf.contains(&i.to_le_bytes()), "false negative at {i}");
        }
    }
}
