//! PQANON-MIX/1 — fixed-size onion cells, 5-hop default path (§10).
//!
//! The specification's cell sketch doesn't actually peel, so this module defines
//! a concrete, reversible onion:
//!
//! - every on-wire cell is exactly [`CELL_SIZE`] (2048) bytes;
//! - each layer is `ephemeral_x25519_pub(32) || nonce(12) || AEAD(...)`, the
//!   AEAD plaintext being `flag(1) || [next_hop_addr(18)] || inner`;
//! - a hop derives its per-cell key via `X25519(hop_sk, ephemeral_pub)` and
//!   HKDF, learning only the next hop — never the origin or full path.
//!
//! No Sphinx, no Nym packet format: the construction is defined here.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::net::SocketAddr;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic, StaticSecret};

/// Every cell is exactly this many bytes, at every hop, in every direction.
pub const CELL_SIZE: usize = 2048;
const FLAG_RELAY: u8 = 0x00;
const FLAG_EXIT: u8 = 0x01;
const ADDR_LEN: usize = 18; // 16-byte IPv6 + 2-byte port
const EPUB_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// A mix hop: its network address and its long-term X25519 public key.
#[derive(Clone)]
pub struct MixHop {
    pub addr: SocketAddr,
    pub pubkey: XPublic,
}

/// The outcome of peeling one layer at a hop.
pub enum Peeled {
    /// Forward `cell` to `next`. Boxed to keep the enum small (cells are 2 KiB).
    Relay {
        next: SocketAddr,
        cell: Box<[u8; CELL_SIZE]>,
    },
    /// This is the exit: deliver `payload`.
    Deliver { payload: Vec<u8> },
}

/// A client-side 5-hop path.
pub struct MixPath {
    pub hops: Vec<MixHop>,
}

impl MixPath {
    pub fn new(hops: Vec<MixHop>) -> anyhow::Result<Self> {
        if hops.len() != 5 {
            anyhow::bail!("mix path must have exactly 5 hops");
        }
        Ok(Self { hops })
    }

    /// Wrap `payload` into a 2048-byte onion for this path.
    pub fn wrap(&self, payload: &[u8]) -> anyhow::Result<[u8; CELL_SIZE]> {
        // Innermost plaintext delivered by the exit hop.
        let mut inner = Vec::with_capacity(1 + payload.len());
        inner.push(FLAG_EXIT);
        inner.extend_from_slice(payload);

        // Encrypt from the exit hop inward to the entry hop.
        // The address a hop forwards to is the *following* hop's address.
        for i in (0..self.hops.len()).rev() {
            let layer = encrypt_layer(&self.hops[i].pubkey, &inner)?;
            // Every forwarded cell is `frame(layer)`, so each layer must leave
            // room for the 2-byte length prefix.
            if layer.len() > CELL_SIZE - 2 {
                anyhow::bail!("payload too large for mix cell");
            }
            if i == 0 {
                // Entry layer: frame into the fixed-size cell.
                return Ok(frame(&layer));
            }
            // Build the plaintext the (i-1)-th hop will see: relay to hop i,
            // carrying hop i's *raw* layer (it will be re-framed on forward).
            let next = self.hops[i].addr;
            let mut relay_plain = Vec::with_capacity(1 + ADDR_LEN + layer.len());
            relay_plain.push(FLAG_RELAY);
            relay_plain.extend_from_slice(&encode_addr(next));
            relay_plain.extend_from_slice(&layer);
            inner = relay_plain;
        }
        unreachable!("path has exactly 5 hops")
    }
}

/// Peel one layer at a hop holding `hop_sk`.
pub fn peel(hop_sk: &StaticSecret, cell: &[u8; CELL_SIZE]) -> anyhow::Result<Peeled> {
    let layer = unframe(cell)?;
    let plain = decrypt_layer(hop_sk, &layer)?;
    if plain.is_empty() {
        anyhow::bail!("empty layer plaintext");
    }
    match plain[0] {
        FLAG_EXIT => Ok(Peeled::Deliver {
            payload: plain[1..].to_vec(),
        }),
        FLAG_RELAY => {
            if plain.len() < 1 + ADDR_LEN + 2 {
                anyhow::bail!("relay layer too short");
            }
            let next = decode_addr(&plain[1..1 + ADDR_LEN])?;
            let inner_layer = &plain[1 + ADDR_LEN..];
            if inner_layer.len() > CELL_SIZE - 2 {
                anyhow::bail!("inner layer larger than a cell");
            }
            // Re-frame the next hop's raw layer into a fresh 2048-byte cell.
            let cell = Box::new(frame(inner_layer));
            Ok(Peeled::Relay { next, cell })
        }
        other => anyhow::bail!("unknown layer flag {other}"),
    }
}

fn encrypt_layer(hop_pub: &XPublic, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let esk = EphemeralSecret::random_from_rng(OsRng);
    let epub = XPublic::from(&esk);
    let shared = esk.diffie_hellman(hop_pub);

    let key = hop_key(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("mix layer encrypt failed"))?;

    let mut out = Vec::with_capacity(EPUB_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(epub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_layer(hop_sk: &StaticSecret, layer: &[u8]) -> anyhow::Result<Vec<u8>> {
    if layer.len() < EPUB_LEN + NONCE_LEN + TAG_LEN {
        anyhow::bail!("layer too short");
    }
    let epub_arr: [u8; 32] = layer[..EPUB_LEN].try_into().unwrap();
    let epub = XPublic::from(epub_arr);
    let nonce = &layer[EPUB_LEN..EPUB_LEN + NONCE_LEN];
    let ct = &layer[EPUB_LEN + NONCE_LEN..];

    let shared = hop_sk.diffie_hellman(&epub);
    let key = hop_key(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("mix layer decrypt failed"))
}

fn hop_key(shared: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hk.expand(b"PQANON-MIX/1", &mut key).unwrap();
    key
}

/// Frame a layer into a fixed 2048-byte cell: `len(2) || layer || random pad`.
fn frame(layer: &[u8]) -> [u8; CELL_SIZE] {
    let mut cell = [0u8; CELL_SIZE];
    let len = layer.len() as u16;
    cell[0..2].copy_from_slice(&len.to_be_bytes());
    cell[2..2 + layer.len()].copy_from_slice(layer);
    // Random padding so cells don't carry a trailing-zero signature.
    OsRng.fill_bytes(&mut cell[2 + layer.len()..]);
    cell
}

fn unframe(cell: &[u8; CELL_SIZE]) -> anyhow::Result<Vec<u8>> {
    let len = u16::from_be_bytes([cell[0], cell[1]]) as usize;
    if 2 + len > CELL_SIZE {
        anyhow::bail!("framed length exceeds cell");
    }
    Ok(cell[2..2 + len].to_vec())
}

fn encode_addr(addr: SocketAddr) -> [u8; ADDR_LEN] {
    let mut out = [0u8; ADDR_LEN];
    match addr {
        SocketAddr::V6(a) => out[..16].copy_from_slice(&a.ip().octets()),
        SocketAddr::V4(a) => out[..16].copy_from_slice(&a.ip().to_ipv6_mapped().octets()),
    }
    out[16..18].copy_from_slice(&addr.port().to_be_bytes());
    out
}

fn decode_addr(buf: &[u8]) -> anyhow::Result<SocketAddr> {
    if buf.len() != ADDR_LEN {
        anyhow::bail!("bad addr length");
    }
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&buf[..16]);
    let port = u16::from_be_bytes([buf[16], buf[17]]);
    let v6 = std::net::Ipv6Addr::from(ip);
    // Unmap IPv4-mapped addresses back to V4 for readability.
    let addr = match v6.to_ipv4_mapped() {
        Some(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), port),
        None => SocketAddr::new(std::net::IpAddr::V6(v6), port),
    };
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop() -> (StaticSecret, MixHop) {
        let sk = StaticSecret::random_from_rng(OsRng);
        let pubkey = XPublic::from(&sk);
        let addr: SocketAddr = format!("10.0.0.{}:8443", rand::random::<u8>())
            .parse()
            .unwrap();
        (sk, MixHop { addr, pubkey })
    }

    #[test]
    fn five_hop_onion_roundtrip() {
        let hops: Vec<(StaticSecret, MixHop)> = (0..5).map(|_| hop()).collect();
        let path = MixPath::new(hops.iter().map(|(_, h)| h.clone()).collect()).unwrap();

        let payload = b"routed through five mixes".to_vec();
        let mut cell = path.wrap(&payload).unwrap();
        assert_eq!(cell.len(), CELL_SIZE);

        // Peel at each hop in order.
        for (i, (sk, hopinfo)) in hops.iter().enumerate() {
            match peel(sk, &cell).unwrap() {
                Peeled::Relay {
                    next,
                    cell: next_cell,
                } => {
                    assert!(i < 4, "only non-exit hops relay");
                    // The relayed address is the *following* hop.
                    assert_eq!(next, hops[i + 1].1.addr);
                    let _ = hopinfo;
                    cell = *next_cell;
                }
                Peeled::Deliver { payload: got } => {
                    assert_eq!(i, 4, "only the exit delivers");
                    assert_eq!(got, payload);
                }
            }
        }
    }

    #[test]
    fn wrong_hop_key_fails() {
        let hops: Vec<(StaticSecret, MixHop)> = (0..5).map(|_| hop()).collect();
        let path = MixPath::new(hops.iter().map(|(_, h)| h.clone()).collect()).unwrap();
        let cell = path.wrap(b"secret").unwrap();
        // A different secret cannot peel the entry layer.
        let (wrong, _) = hop();
        assert!(peel(&wrong, &cell).is_err());
    }

    #[test]
    fn rejects_non_five_hop_paths() {
        let hops: Vec<MixHop> = (0..3).map(|_| hop().1).collect();
        assert!(MixPath::new(hops).is_err());
    }

    #[test]
    fn peel_never_panics_on_garbage() {
        use rand::RngCore;
        let sk = StaticSecret::random_from_rng(OsRng);
        let mut cell = [0u8; CELL_SIZE];
        // Random cells must never crash the peel — only error.
        for _ in 0..20_000 {
            OsRng.fill_bytes(&mut cell);
            let _ = peel(&sk, &cell);
        }
        // Framed-but-garbage: a valid length prefix over random body, including
        // the boundary lengths that exercise the unframe bounds checks.
        for len in [0usize, 1, 2, 16, 44, 100, CELL_SIZE - 2, CELL_SIZE - 1] {
            cell = [0u8; CELL_SIZE];
            cell[0..2].copy_from_slice(&(len as u16).to_be_bytes());
            OsRng.fill_bytes(&mut cell[2..]);
            let _ = peel(&sk, &cell);
        }
    }
}
