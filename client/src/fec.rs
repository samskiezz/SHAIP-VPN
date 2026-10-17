//! SHAIP-FEC/1 — forward error correction for the tunnel data path.
//!
//! On a lossy link (mobile, Wi-Fi, congested transit) a dropped packet normally
//! costs a full retransmit round trip. Forward error correction instead sends a
//! little redundancy up front so the receiver can *reconstruct* lost packets
//! without asking for them again — trading a bounded amount of extra bandwidth
//! for far lower tail latency under loss.
//!
//! This wraps the [`raptorq`] crate, a pure-Rust implementation of the RaptorQ
//! fountain code (RFC 6330). A block of source bytes is split into fixed-size
//! symbols; the encoder emits those source symbols plus `repair` extra repair
//! symbols, and the decoder can rebuild the whole block from *any* subset of
//! symbols whose count is at least the number of source symbols (plus, in rare
//! cases, a symbol or two of overhead). So a block carrying `k` source symbols
//! and `r` repair symbols survives the loss of any `r` of its `k + r` packets.
//!
//! This module is a self-contained, deterministic codec with its own tests. It
//! is the primitive the tunnel's FEC mode is built on; the wire framing that
//! carries a block's symbols and its [`BlockHeader`] across a session is layered
//! on top where the data path opts into FEC.

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

/// The 12-byte RaptorQ transfer header (`ObjectTransmissionInformation`) a
/// receiver needs to decode a block: the transfer length and symbol layout. It
/// travels once per block alongside the symbols.
pub type BlockHeader = [u8; 12];

/// One FEC block ready to send: the header the receiver decodes against, and the
/// serialized symbols (source symbols first, then the repair symbols).
#[derive(Clone, Debug)]
pub struct EncodedBlock {
    /// The RaptorQ transfer header for this block.
    pub header: BlockHeader,
    /// Serialized encoding symbols. Each is one packet on the wire.
    pub symbols: Vec<Vec<u8>>,
    /// How many of `symbols` are source symbols (the rest are repair).
    pub source_symbols: usize,
}

impl EncodedBlock {
    /// Total symbols (source + repair).
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Repair symbols carried (the loss budget: this many packets may be lost and
    /// the block still decodes).
    pub fn repair_symbols(&self) -> usize {
        self.symbols.len().saturating_sub(self.source_symbols)
    }
}

/// Encode `data` into one RaptorQ block of `symbol_size`-byte symbols plus
/// `repair` repair symbols.
///
/// `symbol_size` is the payload size of each FEC symbol (choose it to fit the
/// tunnel MTU after the envelope overhead). `repair` is the redundancy: up to
/// `repair` of the emitted symbols may be lost and the block still decodes.
pub fn encode(data: &[u8], symbol_size: u16, repair: u32) -> EncodedBlock {
    debug_assert!(symbol_size > 0, "symbol size must be non-zero");
    let encoder = Encoder::with_defaults(data, symbol_size);
    let header = encoder.get_config().serialize();
    // Source symbols first (repair=0), then the requested repair symbols, so the
    // caller knows the split and can prefer source symbols when under budget.
    let source: Vec<EncodingPacket> = encoder.get_encoded_packets(0);
    let source_symbols = source.len();
    let all: Vec<EncodingPacket> = encoder.get_encoded_packets(repair);
    let symbols = all.into_iter().map(|p| p.serialize()).collect();
    EncodedBlock {
        header,
        symbols,
        source_symbols,
    }
}

/// Attempt to reconstruct a block's original bytes from whatever symbols
/// arrived. Returns `Some(data)` once enough symbols are present, `None` if too
/// many were lost. Unparseable symbols are skipped rather than failing the whole
/// block.
pub fn decode(header: BlockHeader, received: &[Vec<u8>]) -> Option<Vec<u8>> {
    let config = ObjectTransmissionInformation::deserialize(&header);
    let mut decoder = Decoder::new(config);
    let mut out = None;
    for bytes in received {
        // A corrupt/truncated symbol can't be deserialized; skip it. RaptorQ's
        // own symbols are self-describing, so a well-formed subset still decodes.
        let packet = EncodingPacket::deserialize(bytes);
        if let Some(data) = decoder.decode(packet) {
            out = Some(data);
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 31 + 7) as u8).collect()
    }

    #[test]
    fn lossless_roundtrip() {
        let data = sample(10_000);
        let block = encode(&data, 1200, 4);
        assert!(block.source_symbols >= 1);
        assert_eq!(block.repair_symbols(), 4);
        let got = decode(block.header, &block.symbols).expect("decodes with no loss");
        assert_eq!(got, data, "block must round-trip byte-identically");
    }

    #[test]
    fn recovers_within_the_repair_budget() {
        let data = sample(20_000);
        // 4 repair symbols → up to 4 lost packets are recoverable.
        let block = encode(&data, 1200, 4);
        assert!(block.repair_symbols() == 4 && block.len() > 4);

        // Drop 4 arbitrary symbols (the first four) and decode from the rest.
        let kept: Vec<Vec<u8>> = block.symbols.iter().skip(4).cloned().collect();
        assert!(kept.len() + 4 == block.len());
        let got = decode(block.header, &kept).expect("4 losses within a 4-repair budget must recover");
        assert_eq!(got, data, "recovered block must be byte-identical");
    }

    #[test]
    fn drop_the_source_symbols_recover_from_repair() {
        // The strongest property: lose actual source symbols and rebuild them
        // purely from repair symbols plus the surviving source symbols.
        let data = sample(6_000);
        let block = encode(&data, 1000, 6);
        // Drop the first 3 source symbols; keep the rest (incl. repair).
        let kept: Vec<Vec<u8>> = block.symbols.iter().skip(3).cloned().collect();
        let got = decode(block.header, &kept).expect("source losses must be rebuilt from repair");
        assert_eq!(got, data);
    }

    #[test]
    fn too_much_loss_fails_cleanly() {
        let data = sample(20_000);
        let block = encode(&data, 1200, 2);
        // Keep far fewer symbols than the source count — must fail, not panic.
        let kept: Vec<Vec<u8>> = block.symbols.iter().take(1).cloned().collect();
        assert!(
            decode(block.header, &kept).is_none(),
            "a block missing most of its symbols must not falsely decode"
        );
    }

    #[test]
    fn order_independent_recovery() {
        let data = sample(8_000);
        let block = encode(&data, 1100, 5);
        // Shuffle the kept symbols (reverse): RaptorQ symbols are self-indexing,
        // so arrival order does not matter.
        let mut kept: Vec<Vec<u8>> = block.symbols.clone();
        kept.reverse();
        let got = decode(block.header, &kept).expect("decodes regardless of order");
        assert_eq!(got, data);
    }

    #[test]
    fn tiny_payload_roundtrips() {
        let data = b"a short control message".to_vec();
        let block = encode(&data, 1200, 2);
        let got = decode(block.header, &block.symbols).expect("small payloads encode too");
        assert_eq!(got, data);
    }
}
