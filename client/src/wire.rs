//! SHAIP/1 common envelope — §5 of the specification.
//!
//! Every cleartext datagram, at every layer, before obfuscation, uses the
//! 22-byte header below. The header is passed to ChaCha20-Poly1305 as
//! associated data (AAD), so any tampering with `epoch`, `conn_id`, `seq`,
//! `type`, or `length` breaks authentication.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};

/// Protocol magic, "PQAN".
pub const MAGIC: [u8; 4] = [0x50, 0x51, 0x41, 0x4E];
/// Protocol version.
pub const VERSION: u8 = 0x01;
/// Fixed header length in bytes.
pub const HEADER_LEN: usize = 22;
/// Poly1305 authentication tag length.
pub const TAG_LEN: usize = 16;
/// Per-packet overhead (header + tag).
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN;

/// Message type discriminator (§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MsgType {
    ClientHello = 0x01,
    ServerHello = 0x02,
    ClientFinish = 0x03,
    Data = 0x04,
    Ack = 0x05,
    Rekey = 0x06,
    Close = 0x07,
    Cover = 0x08,
    MixCell = 0x09,
    ProbeResp = 0x0A,
    Retry = 0x0B,
}

impl MsgType {
    pub fn from_u8(b: u8) -> Option<Self> {
        use MsgType::*;
        Some(match b {
            0x01 => ClientHello,
            0x02 => ServerHello,
            0x03 => ClientFinish,
            0x04 => Data,
            0x05 => Ack,
            0x06 => Rekey,
            0x07 => Close,
            0x08 => Cover,
            0x09 => MixCell,
            0x0A => ProbeResp,
            0x0B => Retry,
            _ => return None,
        })
    }
}

/// A fully-formed SHAIP/1 envelope prior to (or after) AEAD.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub msg_type: MsgType,
    pub epoch: u16,
    pub conn_id: u64,
    pub seq: u32,
    pub payload: Vec<u8>,
}

impl Envelope {
    /// Serialize the 22-byte cleartext header (used as AEAD associated data).
    pub fn header_bytes(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(&MAGIC);
        h[4] = VERSION;
        h[5] = self.msg_type as u8;
        h[6..8].copy_from_slice(&self.epoch.to_be_bytes());
        h[8..16].copy_from_slice(&self.conn_id.to_be_bytes());
        h[16..20].copy_from_slice(&self.seq.to_be_bytes());
        h[20..22].copy_from_slice(&(self.payload.len() as u16).to_be_bytes());
        h
    }

    /// Seal: returns `header (AAD) || AEAD ciphertext || tag`.
    pub fn seal(&self, key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
        let header = self.header_bytes();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Self::derive_nonce(self.epoch, self.seq);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &self.payload,
                    aad: &header,
                },
            )
            .map_err(|e| anyhow::anyhow!("aead encrypt: {e}"))?;

        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open: verify + decrypt a sealed datagram with `key`.
    pub fn open(buf: &[u8], key: &[u8; 32]) -> anyhow::Result<Self> {
        if buf.len() < HEADER_LEN + TAG_LEN {
            anyhow::bail!("short packet");
        }
        if buf[0..4] != MAGIC || buf[4] != VERSION {
            anyhow::bail!("bad magic or version");
        }
        let msg_type = MsgType::from_u8(buf[5]).ok_or_else(|| anyhow::anyhow!("bad msg type"))?;
        let epoch = u16::from_be_bytes([buf[6], buf[7]]);
        let conn_id = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let seq = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let declared_len = u16::from_be_bytes([buf[20], buf[21]]) as usize;

        let header = &buf[..HEADER_LEN];
        let body = &buf[HEADER_LEN..];

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Self::derive_nonce(epoch, seq);
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: header,
                },
            )
            .map_err(|e| anyhow::anyhow!("aead decrypt: {e}"))?;

        if pt.len() != declared_len {
            anyhow::bail!(
                "length mismatch (declared {declared_len}, got {})",
                pt.len()
            );
        }
        Ok(Self {
            msg_type,
            epoch,
            conn_id,
            seq,
            payload: pt,
        })
    }

    /// Serialize a handshake (pre-key) message as `header || payload`, with no
    /// AEAD. Handshake payloads carry public KEM keys and signatures, which are
    /// self-authenticating; confidentiality before a session key exists is not
    /// required, and obfuscation (SHAIP-OBF/1) still hides them on the wire.
    pub fn to_plain(&self) -> Vec<u8> {
        let header = self.header_bytes();
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a handshake (pre-key) message produced by [`Envelope::to_plain`].
    pub fn from_plain(buf: &[u8]) -> anyhow::Result<Self> {
        if buf.len() < HEADER_LEN {
            anyhow::bail!("short handshake packet");
        }
        if buf[0..4] != MAGIC || buf[4] != VERSION {
            anyhow::bail!("bad magic or version");
        }
        let msg_type = MsgType::from_u8(buf[5]).ok_or_else(|| anyhow::anyhow!("bad msg type"))?;
        let epoch = u16::from_be_bytes([buf[6], buf[7]]);
        let conn_id = u64::from_be_bytes(buf[8..16].try_into().unwrap());
        let seq = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let declared_len = u16::from_be_bytes([buf[20], buf[21]]) as usize;
        let body = &buf[HEADER_LEN..];
        if body.len() != declared_len {
            anyhow::bail!("handshake length mismatch");
        }
        Ok(Self {
            msg_type,
            epoch,
            conn_id,
            seq,
            payload: body.to_vec(),
        })
    }

    /// Deterministic nonce: `epoch(2) || seq(4) || 0*6`.
    ///
    /// Never repeats within an epoch because `seq` is strictly monotonic.
    /// Directional keys (c2s vs s2c) keep the two directions from colliding.
    fn derive_nonce(epoch: u16, seq: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0..2].copy_from_slice(&epoch.to_be_bytes());
        n[2..6].copy_from_slice(&seq.to_be_bytes());
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [9u8; 32];
        let env = Envelope {
            msg_type: MsgType::Data,
            epoch: 3,
            conn_id: 0xDEAD_BEEF_CAFE_0001,
            seq: 42,
            payload: b"the quick brown fox".to_vec(),
        };
        let sealed = env.seal(&key).unwrap();
        assert_eq!(sealed.len(), OVERHEAD + env.payload.len());
        let opened = Envelope::open(&sealed, &key).unwrap();
        assert_eq!(opened.payload, env.payload);
        assert_eq!(opened.seq, 42);
        assert_eq!(opened.conn_id, 0xDEAD_BEEF_CAFE_0001);
    }

    #[test]
    fn tampered_header_fails_aead() {
        let key = [1u8; 32];
        let env = Envelope {
            msg_type: MsgType::Data,
            epoch: 1,
            conn_id: 42,
            seq: 7,
            payload: b"attack at dawn".to_vec(),
        };
        let mut sealed = env.seal(&key).unwrap();
        sealed[16] ^= 1; // flip a bit in the seq field (AAD)
        assert!(Envelope::open(&sealed, &key).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let env = Envelope {
            msg_type: MsgType::Cover,
            epoch: 1,
            conn_id: 1,
            seq: 1,
            payload: vec![0u8; 64],
        };
        let sealed = env.seal(&[1u8; 32]).unwrap();
        assert!(Envelope::open(&sealed, &[2u8; 32]).is_err());
    }
}
