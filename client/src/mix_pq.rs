//! SHAIP-MIX/2 — post-quantum hybrid onion cells for the mix layer.
//!
//! [`crate::mix`] (SHAIP-MIX/1) builds a real 5-hop onion where each layer's key
//! comes from an X25519 Diffie–Hellman with that hop. That is secure today, but a
//! "harvest now, decrypt later" adversary who records the cells could, with a
//! future quantum computer, recover the per-hop X25519 secrets and unwind the
//! route. SHAIP-MIX/2 closes that by mixing a **post-quantum** shared secret into
//! every layer: the client also ML-KEM-768-encapsulates to each hop, and the
//! layer key is `HKDF(x25519_shared || ml_kem_shared)`. Breaking a layer now
//! requires breaking *both* X25519 and ML-KEM — the standard hybrid guarantee.
//!
//! The construction is otherwise identical to SHAIP-MIX/1 — fixed-size cells,
//! re-padded at every hop so they look alike on the wire, each hop learning only
//! the next hop — so its anonymity properties carry over unchanged; the only
//! addition is the KEM secret in the key-derivation input. Cells are larger
//! ([`CELL_SIZE`]) because each layer carries the 1088-byte ML-KEM ciphertext.
//!
//! This is the self-contained, tested onion. Putting the mix path into the live
//! data plane (the daemon that peels and forwards) is a separate step; this is the
//! packet format it will use.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::net::SocketAddr;
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic, StaticSecret};

type KemEk = <MlKem768 as KemCore>::EncapsulationKey;
type KemDk = <MlKem768 as KemCore>::DecapsulationKey;

/// Fixed on-wire cell size. Larger than SHAIP-MIX/1's 2048 because each of the
/// five layers carries a 1088-byte ML-KEM-768 ciphertext; 8192 leaves room for a
/// full tunnel packet as the innermost payload.
pub const CELL_SIZE: usize = 8192;

const FLAG_RELAY: u8 = 0x00;
const FLAG_EXIT: u8 = 0x01;
const ADDR_LEN: usize = 18; // 16-byte IPv6 + 2-byte port
const EPUB_LEN: usize = 32;
const KEM_CT_LEN: usize = 1088; // ML-KEM-768 ciphertext
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// A mix hop's public key material: its address, long-term X25519 key, and
/// long-term ML-KEM-768 encapsulation key (1184 bytes).
#[derive(Clone)]
pub struct PqMixHop {
    pub addr: SocketAddr,
    pub x_pub: XPublic,
    pub kem_ek: Vec<u8>,
}

/// A hop's secret material, for peeling.
pub struct PqMixSecret {
    pub x_sk: StaticSecret,
    pub kem_dk: KemDk,
}

impl PqMixSecret {
    /// Generate a fresh hop keypair, returning the secret and the public hop
    /// descriptor for the given address.
    pub fn generate(addr: SocketAddr) -> (Self, PqMixHop) {
        let x_sk = StaticSecret::random_from_rng(OsRng);
        let x_pub = XPublic::from(&x_sk);
        let (kem_dk, kem_ek) = MlKem768::generate(&mut OsRng);
        (
            Self { x_sk, kem_dk },
            PqMixHop {
                addr,
                x_pub,
                kem_ek: kem_ek.as_bytes().to_vec(),
            },
        )
    }
}

/// The outcome of peeling one layer.
pub enum Peeled {
    Relay {
        next: SocketAddr,
        cell: Box<[u8; CELL_SIZE]>,
    },
    Deliver {
        payload: Vec<u8>,
    },
}

/// A client-side 5-hop post-quantum path.
pub struct PqMixPath {
    pub hops: Vec<PqMixHop>,
}

impl PqMixPath {
    pub fn new(hops: Vec<PqMixHop>) -> anyhow::Result<Self> {
        if hops.len() != 5 {
            anyhow::bail!("mix path must have exactly 5 hops");
        }
        Ok(Self { hops })
    }

    /// Wrap `payload` into a fixed-size post-quantum onion for this path.
    pub fn wrap(&self, payload: &[u8]) -> anyhow::Result<[u8; CELL_SIZE]> {
        let mut inner = Vec::with_capacity(1 + payload.len());
        inner.push(FLAG_EXIT);
        inner.extend_from_slice(payload);

        for i in (0..self.hops.len()).rev() {
            let layer = encrypt_layer(&self.hops[i], &inner)?;
            if layer.len() > CELL_SIZE - 2 {
                anyhow::bail!("payload too large for post-quantum mix cell");
            }
            if i == 0 {
                return Ok(frame(&layer));
            }
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

/// Peel one layer at a hop holding `secret`.
pub fn peel(secret: &PqMixSecret, cell: &[u8; CELL_SIZE]) -> anyhow::Result<Peeled> {
    let layer = unframe(cell)?;
    let plain = decrypt_layer(secret, &layer)?;
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
            let cell = Box::new(frame(inner_layer));
            Ok(Peeled::Relay { next, cell })
        }
        other => anyhow::bail!("unknown layer flag {other}"),
    }
}

fn encrypt_layer(hop: &PqMixHop, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    // X25519 half.
    let esk = EphemeralSecret::random_from_rng(OsRng);
    let epub = XPublic::from(&esk);
    let x_shared = esk.diffie_hellman(&hop.x_pub);

    // ML-KEM-768 half: encapsulate to the hop's KEM key.
    let enc = Encoded::<KemEk>::try_from(hop.kem_ek.as_slice())
        .map_err(|_| anyhow::anyhow!("bad hop ML-KEM key length"))?;
    let kem_ek = KemEk::from_bytes(&enc);
    let (kem_ct, kem_ss) = kem_ek
        .encapsulate(&mut OsRng)
        .map_err(|_| anyhow::anyhow!("ML-KEM encapsulate failed"))?;
    debug_assert_eq!(kem_ct.len(), KEM_CT_LEN);

    let key = hop_key(x_shared.as_bytes(), kem_ss.as_slice());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| anyhow::anyhow!("mix layer encrypt failed"))?;

    let mut out = Vec::with_capacity(EPUB_LEN + KEM_CT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(epub.as_bytes());
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt_layer(secret: &PqMixSecret, layer: &[u8]) -> anyhow::Result<Vec<u8>> {
    if layer.len() < EPUB_LEN + KEM_CT_LEN + NONCE_LEN + TAG_LEN {
        anyhow::bail!("layer too short");
    }
    let epub_arr: [u8; 32] = layer[..EPUB_LEN].try_into().unwrap();
    let epub = XPublic::from(epub_arr);
    let kem_ct_bytes = &layer[EPUB_LEN..EPUB_LEN + KEM_CT_LEN];
    let nonce = &layer[EPUB_LEN + KEM_CT_LEN..EPUB_LEN + KEM_CT_LEN + NONCE_LEN];
    let ct = &layer[EPUB_LEN + KEM_CT_LEN + NONCE_LEN..];

    let x_shared = secret.x_sk.diffie_hellman(&epub);
    let kem_ct = Ciphertext::<MlKem768>::try_from(kem_ct_bytes)
        .map_err(|_| anyhow::anyhow!("bad ML-KEM ciphertext"))?;
    let kem_ss = secret
        .kem_dk
        .decapsulate(&kem_ct)
        .map_err(|_| anyhow::anyhow!("ML-KEM decapsulate failed"))?;

    let key = hop_key(x_shared.as_bytes(), kem_ss.as_slice());
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| anyhow::anyhow!("mix layer decrypt failed"))
}

/// Hybrid layer key: HKDF over `x25519_shared || ml_kem_shared`.
fn hop_key(x_shared: &[u8], kem_shared: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(x_shared.len() + kem_shared.len());
    ikm.extend_from_slice(x_shared);
    ikm.extend_from_slice(kem_shared);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut key = [0u8; 32];
    hk.expand(b"SHAIP-MIX/2", &mut key).unwrap();
    key
}

fn frame(layer: &[u8]) -> [u8; CELL_SIZE] {
    let mut cell = [0u8; CELL_SIZE];
    let len = layer.len() as u16;
    cell[0..2].copy_from_slice(&len.to_be_bytes());
    cell[2..2 + layer.len()].copy_from_slice(layer);
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
    let addr = match v6.to_ipv4_mapped() {
        Some(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), port),
        None => SocketAddr::new(std::net::IpAddr::V6(v6), port),
    };
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(n: u8) -> (PqMixSecret, PqMixHop) {
        let addr: SocketAddr = format!("10.0.0.{n}:8443").parse().unwrap();
        PqMixSecret::generate(addr)
    }

    #[test]
    fn five_hop_pq_onion_roundtrip() {
        let hops: Vec<(PqMixSecret, PqMixHop)> = (1..=5).map(hop).collect();
        let path = PqMixPath::new(hops.iter().map(|(_, h)| h.clone()).collect()).unwrap();

        let payload = b"routed through five post-quantum mixes".to_vec();
        let mut cell = path.wrap(&payload).unwrap();
        assert_eq!(cell.len(), CELL_SIZE);

        for (i, (secret, hopinfo)) in hops.iter().enumerate() {
            match peel(secret, &cell).unwrap() {
                Peeled::Relay { next, cell: next_cell } => {
                    assert!(i < 4, "only the first four hops relay");
                    // A relaying hop learns exactly the next hop's address.
                    assert_eq!(next, hops[i + 1].1.addr, "hop {i} must forward to the next hop");
                    let _ = hopinfo;
                    cell = *next_cell;
                    assert_eq!(cell.len(), CELL_SIZE, "every on-wire cell stays fixed-size");
                }
                Peeled::Deliver { payload: got } => {
                    assert_eq!(i, 4, "only the exit delivers");
                    assert_eq!(got, payload, "the exit must recover the original payload");
                }
            }
        }
    }

    #[test]
    fn a_wrong_hop_key_cannot_peel() {
        let hops: Vec<(PqMixSecret, PqMixHop)> = (1..=5).map(hop).collect();
        let path = PqMixPath::new(hops.iter().map(|(_, h)| h.clone()).collect()).unwrap();
        let cell = path.wrap(b"secret").unwrap();
        // A different hop's secret (hop 2) must not peel the entry layer.
        assert!(peel(&hops[1].0, &cell).is_err(), "only the addressed hop can peel its layer");
    }

    #[test]
    fn tampered_cell_fails_aead() {
        let hops: Vec<(PqMixSecret, PqMixHop)> = (1..=5).map(hop).collect();
        let path = PqMixPath::new(hops.iter().map(|(_, h)| h.clone()).collect()).unwrap();
        let mut cell = path.wrap(b"secret").unwrap();
        // Flip a byte inside the entry layer's ciphertext region.
        cell[2 + EPUB_LEN + KEM_CT_LEN + NONCE_LEN] ^= 0x01;
        assert!(peel(&hops[0].0, &cell).is_err(), "tampering must break authentication");
    }

    #[test]
    fn cells_are_indistinguishable_in_size() {
        // Two different payloads produce cells of the same fixed size.
        let hops: Vec<(PqMixSecret, PqMixHop)> = (1..=5).map(hop).collect();
        let path = PqMixPath::new(hops.iter().map(|(_, h)| h.clone()).collect()).unwrap();
        let a = path.wrap(b"short").unwrap();
        let b = path.wrap(&vec![7u8; 1200]).unwrap();
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), CELL_SIZE);
    }
}
