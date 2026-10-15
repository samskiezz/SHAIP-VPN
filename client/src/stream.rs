//! In-order stream reassembly for PQANON-UDP/1 stream mode (§8.5). Chunks may
//! arrive out of order; `insert` returns any newly contiguous bytes.

use std::collections::BTreeMap;

pub struct StreamReassembler {
    next_expected: u64,
    buffered: BTreeMap<u64, Vec<u8>>,
    max_buffered: usize,
}

impl Default for StreamReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamReassembler {
    pub fn new() -> Self {
        Self {
            next_expected: 0,
            buffered: BTreeMap::new(),
            max_buffered: 1 << 20,
        }
    }

    /// Insert a chunk at `offset`. Returns contiguous data now ready to deliver.
    pub fn insert(&mut self, offset: u64, data: Vec<u8>) -> Vec<u8> {
        if offset + data.len() as u64 <= self.next_expected {
            return Vec::new(); // fully duplicate
        }
        if offset <= self.next_expected {
            let skip = (self.next_expected - offset) as usize;
            let rest = data[skip..].to_vec();
            self.next_expected += rest.len() as u64;
            let mut out = rest;
            // Drain buffered chunks that are now contiguous.
            while let Some((&off, _)) = self.buffered.iter().next() {
                if off > self.next_expected {
                    break;
                }
                let (_, chunk) = self.buffered.pop_first().unwrap();
                if off + chunk.len() as u64 <= self.next_expected {
                    continue; // already covered
                }
                let skip = (self.next_expected - off) as usize;
                let rest = chunk[skip..].to_vec();
                self.next_expected += rest.len() as u64;
                out.extend_from_slice(&rest);
            }
            out
        } else {
            if self.buffered.len() < self.max_buffered {
                self.buffered.insert(offset, data);
            }
            Vec::new()
        }
    }

    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorders_into_sequence() {
        let mut r = StreamReassembler::new();
        assert_eq!(r.insert(3, b"DEF".to_vec()), b""); // early, buffered
        assert_eq!(r.insert(0, b"ABC".to_vec()), b"ABCDEF"); // fills + drains
        assert_eq!(r.next_expected(), 6);
    }

    #[test]
    fn drops_duplicates() {
        let mut r = StreamReassembler::new();
        assert_eq!(r.insert(0, b"ABC".to_vec()), b"ABC");
        assert_eq!(r.insert(0, b"ABC".to_vec()), b"");
    }
}
