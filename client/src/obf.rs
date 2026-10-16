//! PQANON-OBF/2 — what goes on the wire (§9).
//!
//! Goal: to anyone without the keys, every datagram is indistinguishable from
//! random bytes: no magic, no fixed header bytes, no byte that repeats across
//! a flow's packets. There are two layers, one per phase of a connection.
//!
//! **Session layer** ([`Obfuscator`]), for everything after the handshake. A
//! sealed datagram is `header(22) || ciphertext+tag`; the ciphertext is already
//! pseudorandom, so only the header needs hiding. It is masked the way QUIC
//! protects its headers (RFC 9001 §5.4.4): a 16-byte sample of the ciphertext
//! selects a ChaCha20 keystream under a per-session key, and the header is
//! XORed with it. Every packet's ciphertext differs, so every packet's mask
//! differs. Random padding then brings the datagram to a shaped size:
//!
//! ```text
//! header ⊕ ChaCha20(k_hp, sample) || ciphertext+tag || random padding
//! ```
//!
//! **Boot layer** ([`BootKey`]), for the handshake, before any session key
//! exists. Each handshake message is split into fragments, and each fragment
//! travels in its own datagram, sealed with ChaCha20-Poly1305 under a key
//! derived from the server's pinned public keys, with a random nonce:
//!
//! ```text
//! nonce(12) || AEAD(k_boot, nonce, msg_id(4) || index(1) || count(1) || len(2) || chunk || zeros)
//! ```
//!
//! Every boot datagram is exactly [`BOOT_DATAGRAM`] bytes, small enough to
//! cross any path without IP fragmentation (handshake messages carry ML-DSA
//! signatures and run to ~6 KB, which many networks would drop as fragments).
//! A datagram that does not open under `k_boot` is not ours; the server stays
//! silent, as most UDP services do.
//!
//! What this does not hide: packet sizes and timing (shaped, not removed), and
//! the handshake from anyone who holds the server's public keys, i.e. anyone
//! with a client config for that server.

use crate::handshake::PeerPublic;
use crate::wire::{HEADER_LEN, MAGIC, TAG_LEN, VERSION};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use sha2::Sha256;

/// 16 target sizes, shaped to resemble the size distribution of HTTPS/TLS 1.3
/// on port 443 (§9.2). A sealed datagram is padded up to the first size that
/// holds it, plus 0–15 random bytes.
pub const PADDING_TABLE: [u16; 16] = [
    128, 192, 256, 320, 384, 448, 512, 640, 768, 896, 1024, 1152, 1280, 1408, 1536, 2048,
];

/// Random bytes added on top of a size bucket, so sizes don't sit on 16 values.
pub const SIZE_JITTER: usize = 15;

/// Bytes of ciphertext sampled for the header mask.
const SAMPLE_LEN: usize = 16;

/// Session-layer obfuscation: header protection and length shaping.
pub struct Obfuscator {
    hp_key: [u8; 32],
    padding_table: [u16; 16],
}

impl Obfuscator {
    /// The header-protection key: `HKDF(ss_mix, info = "PQANON-OBF/2 hp {epoch}")`.
    /// Both ends of a session derive it; nobody else can.
    pub fn new(ss_mix: &[u8; 32], epoch: u16) -> Self {
        let hk = Hkdf::<Sha256>::new(None, ss_mix);
        let mut hp_key = [0u8; 32];
        hk.expand(format!("PQANON-OBF/2 hp {epoch}").as_bytes(), &mut hp_key)
            .expect("32 bytes within HKDF bound");
        Self {
            hp_key,
            padding_table: PADDING_TABLE,
        }
    }

    /// Replace the length-shaping table (e.g. from refreshed local statistics).
    pub fn set_padding_table(&mut self, table: [u16; 16]) {
        self.padding_table = table;
    }

    /// Mask the header of a sealed datagram (`header || ciphertext+tag`) and
    /// pad it. Returns the on-wire bytes.
    pub fn morph(&self, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        if sealed.len() < HEADER_LEN + SAMPLE_LEN {
            anyhow::bail!("too short to morph: a sealed datagram has at least a header and a tag");
        }
        let mut out = Vec::with_capacity(self.pick_size(sealed.len()) + SIZE_JITTER);
        out.extend_from_slice(sealed);
        let mask = self.mask(&sealed[HEADER_LEN..HEADER_LEN + SAMPLE_LEN]);
        for (b, m) in out[..HEADER_LEN].iter_mut().zip(mask) {
            *b ^= m;
        }
        let target = self.pick_size(sealed.len()) + rand::rngs::OsRng.gen_range(0..=SIZE_JITTER);
        let mut pad = vec![0u8; target - sealed.len()];
        rand::rngs::OsRng.fill_bytes(&mut pad);
        out.extend_from_slice(&pad);
        Ok(out)
    }

    /// Reverse [`Obfuscator::morph`]: unmask the header and drop the padding.
    /// Fails cheaply on anything that isn't this session's (the AEAD that
    /// follows is the real check).
    pub fn demorph(&self, packet: &[u8]) -> anyhow::Result<Vec<u8>> {
        if packet.len() < HEADER_LEN + SAMPLE_LEN {
            anyhow::bail!("short packet");
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&packet[..HEADER_LEN]);
        let mask = self.mask(&packet[HEADER_LEN..HEADER_LEN + SAMPLE_LEN]);
        for (b, m) in header.iter_mut().zip(mask) {
            *b ^= m;
        }
        if header[0..4] != MAGIC || header[4] != VERSION {
            anyhow::bail!("not this session's packet");
        }
        let body_len = u16::from_be_bytes([header[20], header[21]]) as usize + TAG_LEN;
        if packet.len() < HEADER_LEN + body_len {
            anyhow::bail!("truncated (body shorter than declared length)");
        }
        let mut sealed = Vec::with_capacity(HEADER_LEN + body_len);
        sealed.extend_from_slice(&header);
        sealed.extend_from_slice(&packet[HEADER_LEN..HEADER_LEN + body_len]);
        Ok(sealed)
    }

    /// ChaCha20 header protection after RFC 9001 §5.4.4: the sample's first
    /// four bytes are the block counter (little-endian), the other twelve the
    /// nonce. The counter's top bit is cleared so it can never be the final
    /// block of the 32-bit counter space, which the cipher refuses (an
    /// attacker-chosen sample of 0xFF bytes would otherwise make it panic).
    fn mask(&self, sample: &[u8]) -> [u8; HEADER_LEN] {
        let counter = u32::from_le_bytes(sample[0..4].try_into().unwrap()) & 0x7FFF_FFFF;
        let mut c = ChaCha20::new(chacha20::Key::from_slice(&self.hp_key), chacha20::Nonce::from_slice(&sample[4..16]));
        let mut m = [0u8; HEADER_LEN];
        // Neither call can fail for a counter below 2^31; if one ever did, the
        // zero mask only makes demorph fail on that packet.
        if c.try_seek(u64::from(counter) * 64).is_ok() {
            let _ = c.try_apply_keystream(&mut m);
        }
        m
    }

    fn pick_size(&self, len: usize) -> usize {
        for &s in &self.padding_table {
            if s as usize >= len {
                return s as usize;
            }
        }
        len.div_ceil(128) * 128
    }
}

// ---------------------------------------------------------------------------
// Boot layer (handshake messages)
// ---------------------------------------------------------------------------

/// Size of every handshake datagram's UDP payload: under IPv6's 1280-byte
/// minimum MTU with headers (1280 − 40 − 8 = 1232), so no path fragments it.
pub const BOOT_DATAGRAM: usize = 1200;
const BOOT_NONCE: usize = 12;
const FRAG_HEADER: usize = 8;
/// Message bytes carried per handshake datagram.
pub const BOOT_CHUNK: usize = BOOT_DATAGRAM - BOOT_NONCE - TAG_LEN - FRAG_HEADER;
/// The most fragments one handshake message may use (a ~9 KB ceiling; the
/// largest real message, CLIENT_FINISH with a device certificate, needs 6).
pub const BOOT_MAX_FRAGMENTS: usize = 8;

/// The handshake-layer key, derived from the server's pinned public keys:
/// `HKDF(salt = "PQANON-OBF/2 boot", ikm = ML-DSA-65 key || Ed25519 key)`.
/// The client has them from its config; the server from its identity.
#[derive(Clone)]
pub struct BootKey {
    key: [u8; 32],
}

/// One opened handshake datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub msg_id: u32,
    pub index: u8,
    pub count: u8,
    pub chunk: Vec<u8>,
}

impl BootKey {
    pub fn for_server(server: &PeerPublic) -> Self {
        let mut ikm = server.pq_bytes();
        ikm.extend_from_slice(&server.ed_bytes());
        let hk = Hkdf::<Sha256>::new(Some(b"PQANON-OBF/2 boot"), &ikm);
        let mut key = [0u8; 32];
        hk.expand(b"handshake datagrams", &mut key)
            .expect("32 bytes within HKDF bound");
        Self { key }
    }

    /// Split one handshake message into sealed datagrams of exactly
    /// [`BOOT_DATAGRAM`] bytes, at least `min_datagrams` of them (extra ones
    /// carry no message bytes: the client pads its hello so the server's
    /// larger reply stays within the anti-amplification limit).
    pub fn seal_message(&self, msg: &[u8], min_datagrams: usize) -> anyhow::Result<Vec<Vec<u8>>> {
        let count = msg.len().div_ceil(BOOT_CHUNK).max(min_datagrams).max(1);
        if count > BOOT_MAX_FRAGMENTS {
            anyhow::bail!("handshake message too large ({} bytes)", msg.len());
        }
        let msg_id: u32 = rand::random();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let mut out = Vec::with_capacity(count);
        for index in 0..count {
            let chunk = msg.get(index * BOOT_CHUNK..).map_or(&[][..], |rest| &rest[..rest.len().min(BOOT_CHUNK)]);
            let mut pt = Vec::with_capacity(FRAG_HEADER + BOOT_CHUNK);
            pt.extend_from_slice(&msg_id.to_be_bytes());
            pt.push(index as u8);
            pt.push(count as u8);
            pt.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            pt.extend_from_slice(chunk);
            pt.resize(FRAG_HEADER + BOOT_CHUNK, 0); // the AEAD hides the padding
            let mut nonce = [0u8; BOOT_NONCE];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce), pt.as_slice())
                .map_err(|e| anyhow::anyhow!("aead encrypt: {e}"))?;
            let mut d = Vec::with_capacity(BOOT_DATAGRAM);
            d.extend_from_slice(&nonce);
            d.extend_from_slice(&ct);
            debug_assert_eq!(d.len(), BOOT_DATAGRAM);
            out.push(d);
        }
        Ok(out)
    }

    /// Open one handshake datagram; `None` if it isn't one (wrong size, wrong
    /// key, tampered, or malformed inside).
    pub fn open(&self, wire: &[u8]) -> Option<Fragment> {
        if wire.len() != BOOT_DATAGRAM {
            return None;
        }
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let pt = cipher
            .decrypt(Nonce::from_slice(&wire[..BOOT_NONCE]), &wire[BOOT_NONCE..])
            .ok()?;
        let msg_id = u32::from_be_bytes(pt[0..4].try_into().unwrap());
        let (index, count) = (pt[4], pt[5]);
        let len = u16::from_be_bytes([pt[6], pt[7]]) as usize;
        if count == 0 || count as usize > BOOT_MAX_FRAGMENTS || index >= count || len > BOOT_CHUNK {
            return None;
        }
        Some(Fragment {
            msg_id,
            index,
            count,
            chunk: pt[FRAG_HEADER..FRAG_HEADER + len].to_vec(),
        })
    }
}

/// Collects the fragments of one handshake message. A fragment of a different
/// message (a new `msg_id`) starts over: the sender moved on.
#[derive(Default)]
pub struct Reassembly {
    msg_id: u32,
    parts: Vec<Option<Vec<u8>>>,
    /// Datagram bytes received for the current message, duplicates included
    /// once (what the anti-amplification limit is measured against).
    received: usize,
}

impl Reassembly {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a fragment; returns the whole message once every fragment is in.
    pub fn push(&mut self, f: Fragment) -> Option<Vec<u8>> {
        if self.parts.is_empty() || f.msg_id != self.msg_id || f.count as usize != self.parts.len() {
            self.msg_id = f.msg_id;
            self.parts = vec![None; f.count as usize];
            self.received = 0;
        }
        let slot = &mut self.parts[f.index as usize];
        if slot.is_none() {
            *slot = Some(f.chunk);
            self.received += BOOT_DATAGRAM;
        }
        if self.parts.iter().all(Option::is_some) {
            let msg = self.parts.iter().flatten().flatten().copied().collect();
            self.parts.clear();
            return Some(msg);
        }
        None
    }

    /// Bytes of distinct datagrams that made up the last completed (or the
    /// current partial) message.
    pub fn received(&self) -> usize {
        self.received
    }
}

/// The anti-amplification limit: before the client has proved it receives at
/// its address (by completing the handshake), the server sends at most three
/// times the bytes it received (the same limit as QUIC, RFC 9000 §8.1).
pub const AMPLIFICATION_LIMIT: usize = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::Identity;
    use crate::transport::Session;
    use crate::wire::MsgType;

    fn session_pair() -> (Session, Obfuscator) {
        let s = Session::new(0x0123_4567_89AB_CDEF, [1u8; 32], [2u8; 32], "127.0.0.1:9".parse().unwrap(), true, 1400);
        (s, Obfuscator::new(&[42u8; 32], 1))
    }

    #[test]
    fn morph_demorph_roundtrip() {
        let (mut s, obf) = session_pair();
        for n in [0usize, 1, 40, 500, 1370] {
            let sealed = s.seal_data(MsgType::Data, vec![0xA5; n]).unwrap();
            let wire = obf.morph(&sealed).unwrap();
            assert_eq!(obf.demorph(&wire).unwrap(), sealed, "payload {n}");
        }
    }

    #[test]
    fn another_sessions_key_does_not_demorph() {
        let (mut s, obf) = session_pair();
        let wire = obf.morph(&s.seal_data(MsgType::Data, b"x".to_vec()).unwrap()).unwrap();
        assert!(Obfuscator::new(&[43u8; 32], 1).demorph(&wire).is_err());
        assert!(Obfuscator::new(&[42u8; 32], 2).demorph(&wire).is_err(), "a different epoch is a different key");
    }

    /// The point of the layer: across a flow, no byte position holds a fixed
    /// value. The old morph XORed every header with one key per session, so 16
    /// of its 22 header bytes were identical in every packet.
    #[test]
    fn no_byte_repeats_across_a_flows_packets() {
        let (mut s, obf) = session_pair();
        let packets: Vec<Vec<u8>> = (0..64)
            .map(|_| obf.morph(&s.seal_data(MsgType::Data, vec![0u8; 100]).unwrap()).unwrap())
            .collect();
        for pos in 0..128 {
            let first = packets[0][pos];
            let same = packets.iter().filter(|p| p[pos] == first).count();
            assert!(same < 8, "byte {pos} holds the same value in {same} of 64 packets");
        }
        assert!(!packets.iter().any(|p| p.windows(4).any(|w| w == MAGIC)), "PQAN magic on the wire");
    }

    #[test]
    fn sizes_are_shaped_with_jitter() {
        let (mut s, obf) = session_pair();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..300 {
            // 80 bytes seal to 22 + 80 + 16 = 118, inside the 128 bucket.
            let wire = obf.morph(&s.seal_data(MsgType::Data, vec![0u8; 80]).unwrap()).unwrap();
            assert!((128..=128 + SIZE_JITTER).contains(&wire.len()), "{}", wire.len());
            seen.insert(wire.len());
        }
        assert!(seen.len() > 8, "sizes vary within the bucket");
    }

    /// Any 16 bytes may be the sample (the attacker picks them): none panics.
    #[test]
    fn extreme_samples_do_not_panic() {
        let (_, obf) = session_pair();
        for fill in [0x00u8, 0x7F, 0x80, 0xFF] {
            assert!(obf.demorph(&[fill; 200]).is_err());
        }
        for _ in 0..2000 {
            let p: Vec<u8> = (0..64).map(|_| rand::random()).collect();
            let _ = obf.demorph(&p);
        }
    }

    #[test]
    fn short_or_truncated_packets_are_refused() {
        let (mut s, obf) = session_pair();
        assert!(obf.morph(&[0u8; HEADER_LEN + SAMPLE_LEN - 1]).is_err());
        assert!(obf.demorph(&[]).is_err());
        let wire = obf.morph(&s.seal_data(MsgType::Data, vec![1u8; 300]).unwrap()).unwrap();
        assert!(obf.demorph(&wire[..HEADER_LEN + 200]).is_err());
    }

    fn boot() -> BootKey {
        BootKey::for_server(&Identity::generate().public())
    }

    #[test]
    fn handshake_messages_split_into_small_datagrams_and_reassemble() {
        let k = boot();
        for len in [0usize, 1, BOOT_CHUNK, BOOT_CHUNK + 1, 6000] {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let datagrams = k.seal_message(&msg, 1).unwrap();
            assert_eq!(datagrams.len(), len.div_ceil(BOOT_CHUNK).max(1));
            assert!(datagrams.iter().all(|d| d.len() == BOOT_DATAGRAM));
            // Delivered out of order, with a duplicate.
            let mut r = Reassembly::new();
            let mut done = None;
            for d in datagrams.iter().rev().chain(datagrams.first()) {
                if let Some(m) = r.push(k.open(d).unwrap()) {
                    done = Some(m);
                }
            }
            assert_eq!(done.unwrap(), msg, "len {len}");
        }
    }

    #[test]
    fn padding_datagrams_raise_the_count() {
        let k = boot();
        let d = k.seal_message(b"short", 3).unwrap();
        assert_eq!(d.len(), 3);
        let mut r = Reassembly::new();
        let got: Vec<_> = d.iter().filter_map(|x| r.push(k.open(x).unwrap())).collect();
        assert_eq!(got, vec![b"short".to_vec()]);
        assert_eq!(r.received(), 3 * BOOT_DATAGRAM);
    }

    #[test]
    fn boot_datagrams_need_the_servers_keys() {
        let (a, b) = (boot(), boot());
        let d = a.seal_message(b"hello", 1).unwrap();
        assert!(b.open(&d[0]).is_none(), "another server's key");
        let mut t = d[0].clone();
        t[600] ^= 1;
        assert!(a.open(&t).is_none(), "tampered");
        assert!(a.open(&d[0][..BOOT_DATAGRAM - 1]).is_none(), "wrong size");
        assert!(a.open(&[0u8; BOOT_DATAGRAM]).is_none(), "zeros");
    }

    #[test]
    fn boot_datagrams_look_random() {
        let k = boot();
        let msg = vec![0u8; 3000]; // all zeros inside: the worst case
        let mut counts = [0u32; 256];
        let mut total = 0u32;
        for _ in 0..40 {
            for d in k.seal_message(&msg, 1).unwrap() {
                for &b in &d {
                    counts[b as usize] += 1;
                }
                total += d.len() as u32;
            }
        }
        // Chi-square against uniform, 255 degrees of freedom: a uniform source
        // stays under ~330 with overwhelming probability.
        let expect = total as f64 / 256.0;
        let chi: f64 = counts.iter().map(|&c| (c as f64 - expect).powi(2) / expect).sum();
        assert!(chi < 400.0, "chi-square {chi:.0}");
    }

    #[test]
    fn too_large_a_message_is_refused() {
        assert!(boot().seal_message(&vec![0u8; BOOT_CHUNK * BOOT_MAX_FRAGMENTS + 1], 1).is_err());
    }

    #[test]
    fn a_new_message_restarts_reassembly() {
        let k = boot();
        let first = k.seal_message(&vec![1u8; 2000], 1).unwrap();
        let second = k.seal_message(&vec![2u8; 2000], 1).unwrap();
        let mut r = Reassembly::new();
        assert!(r.push(k.open(&first[0]).unwrap()).is_none());
        assert!(r.push(k.open(&second[0]).unwrap()).is_none());
        assert_eq!(r.push(k.open(&second[1]).unwrap()), Some(vec![2u8; 2000]));
    }
}
