//! PQANON-HS/1 — hybrid post-quantum handshake (§6, §7).
//!
//! The specification lists the client half of the handshake. A handshake that
//! actually runs needs both halves, so this module implements client **and**
//! server state machines and derives an identical `ss_mix` on both sides from:
//!
//! - ML-KEM-768 (post-quantum KEM): the server encapsulates to the client's
//!   ephemeral KEM key, giving `ss_pq`.
//! - X25519 (classical ECDH): ephemeral on both sides, giving `ss_x`.
//!
//! `ss_mix = HKDF(ikm = ss_pq || ss_x, salt = client_nonce || server_nonce,
//! info = "PQANON-HS/1")`. Breaking either KEM alone is insufficient.
//!
//! Both sides mutually authenticate by signing the transcript with long-term
//! ML-DSA-65 **and** Ed25519 keys. The client's long-term verifying keys travel
//! inside the (obfuscated) CLIENT_FINISH so the server can both check the
//! `identity_id` against its authorized set and verify the signatures — no
//! identifier ever appears in cleartext on the wire.

use crate::kdf;
use crate::wire::{Envelope, MsgType};
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{
    Signer as EdSigner, SigningKey as EdSigningKey, Verifier as EdVerifier,
    VerifyingKey as EdVerifyingKey,
};
use hmac::{Hmac, Mac};
use ml_dsa::{
    EncodedSignature, EncodedSigningKey, EncodedVerifyingKey, KeyGen, MlDsa65,
    Signature as DsaSignature, SigningKey as DsaSigningKey, VerifyingKey as DsaVerifyingKey,
};
use zeroize::Zeroizing;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as XPublic};

type HmacSha256 = Hmac<Sha256>;
type KemEk = <MlKem768 as KemCore>::EncapsulationKey;
type KemDk = <MlKem768 as KemCore>::DecapsulationKey;

/// Maximum handshake clock skew tolerated (§6.1): 30 seconds.
pub const MAX_SKEW_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// Length-prefixed field helpers
// ---------------------------------------------------------------------------

fn put_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

struct FieldReader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> FieldReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }
    fn take(&mut self) -> Result<&'a [u8]> {
        if self.off + 4 > self.buf.len() {
            bail!("truncated field length");
        }
        let len = u32::from_be_bytes(self.buf[self.off..self.off + 4].try_into().unwrap()) as usize;
        self.off += 4;
        if self.off + len > self.buf.len() {
            bail!("truncated field body");
        }
        let s = &self.buf[self.off..self.off + len];
        self.off += len;
        Ok(s)
    }
    fn consumed(&self) -> usize {
        self.off
    }
}

// ---------------------------------------------------------------------------
// Identities
// ---------------------------------------------------------------------------

/// A long-term identity: an ML-DSA-65 keypair plus an Ed25519 keypair.
#[derive(Clone)]
pub struct Identity {
    pq_sk: DsaSigningKey<MlDsa65>,
    pq_vk: DsaVerifyingKey<MlDsa65>,
    ed: EdSigningKey,
}

impl Identity {
    /// Generate a fresh random identity.
    pub fn generate() -> Self {
        let kp = MlDsa65::key_gen(&mut OsRng);
        Self {
            pq_sk: kp.signing_key().clone(),
            pq_vk: kp.verifying_key().clone(),
            ed: EdSigningKey::generate(&mut OsRng),
        }
    }

    /// The public half, suitable for pinning on the peer.
    pub fn public(&self) -> PeerPublic {
        PeerPublic {
            pq: self.pq_vk.clone(),
            ed: self.ed.verifying_key(),
        }
    }

    /// `identity_id = SHA-256(pq_pub || ed_pub)[0..16]` (§7).
    pub fn identity_id(&self) -> [u8; 16] {
        self.public().identity_id()
    }

    fn sign_transcript(&self, transcript: &[u8]) -> (Vec<u8>, [u8; 64]) {
        let pq_sig: DsaSignature<MlDsa65> = self.pq_sk.sign(transcript);
        let ed_sig = self.ed.sign(transcript);
        (pq_sig.encode().to_vec(), ed_sig.to_bytes())
    }

    /// Serialize the full secret identity for storage:
    /// `magic || Ed25519 seed (32) || ML-DSA-65 signing key || ML-DSA-65 verifying key`.
    ///
    /// FIPS 204's signing-key encoding omits `t1`, so the verifying key cannot be
    /// recomputed from it and is stored alongside. The bytes are secret key
    /// material and are zeroized on drop.
    pub fn to_secret_bytes(&self) -> Zeroizing<Vec<u8>> {
        let sk = self.pq_sk.encode();
        let vk = self.pq_vk.encode();
        let mut out = Zeroizing::new(Vec::with_capacity(
            IDENTITY_MAGIC.len() + 32 + sk.len() + vk.len(),
        ));
        out.extend_from_slice(IDENTITY_MAGIC);
        out.extend_from_slice(&self.ed.to_bytes());
        out.extend_from_slice(&sk);
        out.extend_from_slice(&vk);
        out
    }

    /// Parse [`Identity::to_secret_bytes`] output. Rejects a wrong magic or
    /// length, and proves the stored halves belong together with a sign/verify
    /// round trip, so a corrupted or spliced key file fails here instead of as an
    /// unexplained handshake failure later.
    pub fn from_secret_bytes(b: &[u8]) -> Result<Self> {
        let sk_len = std::mem::size_of::<EncodedSigningKey<MlDsa65>>();
        let vk_len = std::mem::size_of::<EncodedVerifyingKey<MlDsa65>>();
        let rest = b
            .strip_prefix(IDENTITY_MAGIC)
            .ok_or_else(|| anyhow!("not a PQANON identity (bad magic)"))?;
        if rest.len() != 32 + sk_len + vk_len {
            bail!("identity has the wrong length ({} bytes)", b.len());
        }
        let (ed_seed, rest) = rest.split_at(32);
        let (sk_bytes, vk_bytes) = rest.split_at(sk_len);
        let ed_seed = Zeroizing::new(<[u8; 32]>::try_from(ed_seed).expect("split at 32"));
        let sk_enc = EncodedSigningKey::<MlDsa65>::try_from(sk_bytes)
            .map_err(|_| anyhow!("bad ML-DSA signing key encoding"))?;
        let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(vk_bytes)
            .map_err(|_| anyhow!("bad ML-DSA verifying key encoding"))?;
        let id = Self {
            pq_sk: DsaSigningKey::<MlDsa65>::decode(&sk_enc),
            pq_vk: DsaVerifyingKey::<MlDsa65>::decode(&vk_enc),
            ed: EdSigningKey::from_bytes(&ed_seed),
        };
        let (pq_sig, ed_sig) = id.sign_transcript(IDENTITY_SELFTEST);
        id.public()
            .verify_transcript(IDENTITY_SELFTEST, &pq_sig, &ed_sig)
            .map_err(|_| anyhow!("identity is corrupt: its signing and verifying keys do not match"))?;
        Ok(id)
    }
}

/// Leading magic of a serialized [`Identity`].
const IDENTITY_MAGIC: &[u8] = b"PQANON-IDENTITY-V1";
/// Message signed when loading an identity to prove its key halves match.
const IDENTITY_SELFTEST: &[u8] = b"PQANON-IDENTITY-SELFTEST-V1";

/// The public half of an [`Identity`]: pinned ML-DSA-65 + Ed25519 verifying keys.
#[derive(Clone)]
pub struct PeerPublic {
    pq: DsaVerifyingKey<MlDsa65>,
    ed: EdVerifyingKey,
}

impl PeerPublic {
    /// Reconstruct from encoded bytes (ML-DSA verifying key, Ed25519 32 bytes).
    pub fn from_bytes(pq_bytes: &[u8], ed_bytes: &[u8]) -> Result<Self> {
        let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pq_bytes)
            .map_err(|_| anyhow!("bad ML-DSA verifying key length"))?;
        let pq = DsaVerifyingKey::<MlDsa65>::decode(&enc);
        let ed_arr: [u8; 32] = ed_bytes
            .try_into()
            .map_err(|_| anyhow!("bad Ed25519 verifying key length"))?;
        let ed = EdVerifyingKey::from_bytes(&ed_arr)
            .map_err(|_| anyhow!("invalid Ed25519 verifying key"))?;
        Ok(Self { pq, ed })
    }

    /// Encoded ML-DSA-65 verifying key bytes.
    pub fn pq_bytes(&self) -> Vec<u8> {
        self.pq.encode().to_vec()
    }

    /// Encoded Ed25519 verifying key bytes.
    pub fn ed_bytes(&self) -> [u8; 32] {
        self.ed.to_bytes()
    }

    /// `identity_id = SHA-256(pq_pub || ed_pub)[0..16]` (§7).
    pub fn identity_id(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(self.pq_bytes());
        h.update(self.ed_bytes());
        let digest = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }

    fn verify_transcript(&self, transcript: &[u8], pq_sig: &[u8], ed_sig: &[u8]) -> Result<()> {
        let enc = EncodedSignature::<MlDsa65>::try_from(pq_sig)
            .map_err(|_| anyhow!("bad ML-DSA signature length"))?;
        let sig = DsaSignature::<MlDsa65>::decode(&enc)
            .ok_or_else(|| anyhow!("malformed ML-DSA signature"))?;
        self.pq
            .verify(transcript, &sig)
            .map_err(|_| anyhow!("ML-DSA signature invalid"))?;

        let ed_arr: [u8; 64] = ed_sig
            .try_into()
            .map_err(|_| anyhow!("bad Ed25519 signature length"))?;
        let ed = ed25519_dalek::Signature::from_bytes(&ed_arr);
        self.ed
            .verify_strict(transcript, &ed)
            .map_err(|_| anyhow!("Ed25519 signature invalid"))?;
        Ok(())
    }
}

/// The negotiated result shared by both sides once the handshake completes.
#[derive(Debug, Clone)]
pub struct Established {
    pub ss_mix: [u8; 32],
    pub conn_id: u64,
    pub k_c2s: [u8; 32],
    pub k_s2c: [u8; 32],
    /// The peer's `identity_id` (server learns the client's; client knows the server's).
    pub peer_id: [u8; 16],
}

fn finish_from_ss(ss_mix: [u8; 32], peer_id: [u8; 16]) -> Established {
    let (k_c2s, k_s2c) = kdf::directional_keys(&ss_mix);
    Established {
        ss_mix,
        conn_id: kdf::conn_id(&ss_mix),
        k_c2s,
        k_s2c,
        peer_id,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client-side handshake driver.
pub struct ClientHandshake {
    id: Identity,
    server: PeerPublic,
    hs_conn_id: u64,
    client_nonce: [u8; 32],
    eph_pq_dk: Option<KemDk>,
    eph_x: Option<EphemeralSecret>,
    transcript: Vec<u8>,
    ss_mix: Option<[u8; 32]>,
}

impl ClientHandshake {
    /// `id` is the client's long-term identity; `server` is the pinned server key.
    pub fn new(id: Identity, server: PeerPublic, hs_conn_id: u64) -> Self {
        let mut client_nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut client_nonce);
        Self {
            id,
            server,
            hs_conn_id,
            client_nonce,
            eph_pq_dk: None,
            eph_x: None,
            transcript: Vec::new(),
            ss_mix: None,
        }
    }

    /// Message 1 — CLIENT_HELLO (§6.2).
    pub fn client_hello(&mut self, cookie: [u8; 32]) -> Result<Envelope> {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        let ek_bytes = ek.as_bytes();
        self.eph_pq_dk = Some(dk);

        let esk = EphemeralSecret::random_from_rng(OsRng);
        let epub = XPublic::from(&esk);
        self.eph_x = Some(esk);

        let ts = now_ms();

        let mut payload = Vec::with_capacity(1400);
        put_field(&mut payload, &ek_bytes);
        put_field(&mut payload, epub.as_bytes());
        put_field(&mut payload, &self.client_nonce);
        put_field(&mut payload, &ts.to_be_bytes());
        put_field(&mut payload, &cookie);

        self.transcript.extend_from_slice(&payload);

        Ok(Envelope {
            msg_type: MsgType::ClientHello,
            epoch: 0,
            conn_id: self.hs_conn_id,
            seq: 0,
            payload,
        })
    }

    /// Message 2 — process SERVER_HELLO (§6.3), deriving `ss_mix`.
    pub fn recv_server_hello(&mut self, env: &Envelope) -> Result<()> {
        if env.msg_type != MsgType::ServerHello {
            bail!("expected SERVER_HELLO");
        }
        let p = &env.payload;
        let mut r = FieldReader::new(p);

        let _s_pq_encap_pub = r.take()?; // reserved; unused in ss derivation
        let s_x = r.take()?;
        let s_nonce = r.take()?;
        let pq_ct = r.take()?;
        let signed_prefix_len = r.consumed();
        let pq_sig = r.take()?;
        let ed_sig = r.take()?;

        // Verify server signatures over (client_hello || server_hello_prefix).
        let mut signed = self.transcript.clone();
        signed.extend_from_slice(&p[..signed_prefix_len]);
        self.server.verify_transcript(&signed, pq_sig, ed_sig)?;

        // ss_pq via ML-KEM decapsulation with the client's ephemeral key.
        let ct = Ciphertext::<MlKem768>::try_from(pq_ct)
            .map_err(|_| anyhow!("bad ML-KEM ciphertext length"))?;
        let dk = self
            .eph_pq_dk
            .as_ref()
            .ok_or_else(|| anyhow!("missing client KEM key"))?;
        let ss_pq = dk
            .decapsulate(&ct)
            .map_err(|_| anyhow!("ML-KEM decapsulation failed"))?;

        // ss_x via X25519.
        let s_x_arr: [u8; 32] = s_x.try_into().map_err(|_| anyhow!("bad X25519 pub"))?;
        let spub = XPublic::from(s_x_arr);
        let esk = self
            .eph_x
            .take()
            .ok_or_else(|| anyhow!("missing client X25519 key"))?;
        let ss_x = esk.diffie_hellman(&spub);

        let mut sn = [0u8; 32];
        sn.copy_from_slice(s_nonce);

        let ss_mix = derive_ss_mix(&ss_pq, ss_x.as_bytes(), &self.client_nonce, &sn);
        self.ss_mix = Some(ss_mix);

        // Append the full server_hello to the transcript.
        self.transcript.extend_from_slice(p);
        Ok(())
    }

    /// Message 3 — CLIENT_FINISH (§6.4).
    pub fn client_finish(&mut self) -> Result<(Envelope, Established)> {
        let ss_mix = self.ss_mix.ok_or_else(|| anyhow!("no ss_mix"))?;

        let (pq_sig, ed_sig) = self.id.sign_transcript(&self.transcript);

        let mut mac = HmacSha256::new_from_slice(&ss_mix).unwrap();
        mac.update(&self.transcript);
        let mac_bytes = mac.finalize().into_bytes();

        let pub_ = self.id.public();
        let mut payload = Vec::new();
        put_field(&mut payload, &pub_.pq_bytes());
        put_field(&mut payload, &pub_.ed_bytes());
        put_field(&mut payload, &pq_sig);
        put_field(&mut payload, &ed_sig);
        put_field(&mut payload, &mac_bytes);

        let env = Envelope {
            msg_type: MsgType::ClientFinish,
            epoch: 0,
            conn_id: self.hs_conn_id,
            seq: 0,
            payload,
        };
        let est = finish_from_ss(ss_mix, self.server.identity_id());
        Ok((env, est))
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Server-side handshake driver.
pub struct ServerHandshake {
    id: Identity,
    authorized: Vec<[u8; 16]>,
    /// When true, any well-formed client identity is accepted (demo daemons).
    allow_any: bool,
    hs_conn_id: u64,
    server_nonce: [u8; 32],
    eph_x: Option<EphemeralSecret>,
    client_ek_bytes: Vec<u8>,
    client_x_pub: Option<XPublic>,
    client_nonce: [u8; 32],
    transcript: Vec<u8>,
    ss_mix: Option<[u8; 32]>,
}

impl ServerHandshake {
    /// `id` is the server's long-term identity; `authorized` is the pinned set
    /// of client `identity_id`s permitted to complete a handshake (§7).
    pub fn new(id: Identity, authorized: Vec<[u8; 16]>, hs_conn_id: u64) -> Self {
        let mut server_nonce = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut server_nonce);
        Self {
            id,
            authorized,
            allow_any: false,
            hs_conn_id,
            server_nonce,
            eph_x: None,
            client_ek_bytes: Vec::new(),
            client_x_pub: None,
            client_nonce: [0u8; 32],
            transcript: Vec::new(),
            ss_mix: None,
        }
    }

    /// Like [`ServerHandshake::new`] but accepts any well-formed client identity
    /// (no pinned allow-list). Intended for demo daemons, never production.
    pub fn new_open(id: Identity, hs_conn_id: u64) -> Self {
        let mut s = Self::new(id, Vec::new(), hs_conn_id);
        s.allow_any = true;
        s
    }

    /// Process CLIENT_HELLO. `check_freshness` enforces the 30 s skew bound.
    pub fn recv_client_hello(&mut self, env: &Envelope, check_freshness: bool) -> Result<()> {
        if env.msg_type != MsgType::ClientHello {
            bail!("expected CLIENT_HELLO");
        }
        let p = &env.payload;
        let mut r = FieldReader::new(p);
        let ek = r.take()?;
        let x = r.take()?;
        let nonce = r.take()?;
        let ts = r.take()?;
        let _cookie = r.take()?; // verified separately by the cookie module

        if ek.len() != 1184 {
            bail!("unexpected ML-KEM encapsulation key length");
        }
        let ts_ms = u64::from_be_bytes(ts.try_into().map_err(|_| anyhow!("bad timestamp"))?);
        if check_freshness {
            let skew = now_ms().saturating_sub(ts_ms);
            if skew > MAX_SKEW_MS {
                bail!("stale CLIENT_HELLO (skew {skew} ms)");
            }
        }

        self.client_ek_bytes = ek.to_vec();
        let x_arr: [u8; 32] = x.try_into().map_err(|_| anyhow!("bad X25519 pub"))?;
        self.client_x_pub = Some(XPublic::from(x_arr));
        self.client_nonce.copy_from_slice(nonce);

        self.transcript.extend_from_slice(p);
        Ok(())
    }

    /// Produce SERVER_HELLO and derive `ss_mix`.
    pub fn server_hello(&mut self) -> Result<Envelope> {
        // Reconstruct the client's KEM key and encapsulate to it.
        let enc = Encoded::<KemEk>::try_from(self.client_ek_bytes.as_slice())
            .map_err(|_| anyhow!("bad client KEM key"))?;
        let client_ek = KemEk::from_bytes(&enc);
        let (ct, ss_pq) = client_ek
            .encapsulate(&mut OsRng)
            .map_err(|_| anyhow!("ML-KEM encapsulation failed"))?;

        // Server ephemeral X25519.
        let esk = EphemeralSecret::random_from_rng(OsRng);
        let epub = XPublic::from(&esk);
        self.eph_x = Some(esk);

        // Server's own (reserved) KEM encapsulation key, carried for spec fidelity.
        let (_srv_dk, srv_ek) = MlKem768::generate(&mut OsRng);
        let srv_ek_bytes = srv_ek.as_bytes();

        let mut prefix = Vec::with_capacity(1400);
        put_field(&mut prefix, &srv_ek_bytes);
        put_field(&mut prefix, epub.as_bytes());
        put_field(&mut prefix, &self.server_nonce);
        put_field(&mut prefix, &ct);

        // ss_x and ss_mix.
        let client_x = self
            .client_x_pub
            .as_ref()
            .ok_or_else(|| anyhow!("missing client X25519 pub"))?;
        let esk = self.eph_x.take().unwrap();
        let ss_x = esk.diffie_hellman(client_x);
        let ss_mix = derive_ss_mix(
            &ss_pq,
            ss_x.as_bytes(),
            &self.client_nonce,
            &self.server_nonce,
        );
        self.ss_mix = Some(ss_mix);

        // Sign (client_hello || server_hello_prefix).
        let mut signed = self.transcript.clone();
        signed.extend_from_slice(&prefix);
        let (pq_sig, ed_sig) = self.id.sign_transcript(&signed);

        let mut payload = prefix;
        put_field(&mut payload, &pq_sig);
        put_field(&mut payload, &ed_sig);

        self.transcript.extend_from_slice(&payload);

        Ok(Envelope {
            msg_type: MsgType::ServerHello,
            epoch: 0,
            conn_id: self.hs_conn_id,
            seq: 0,
            payload,
        })
    }

    /// Process CLIENT_FINISH: authenticate the client and finish the handshake.
    pub fn recv_client_finish(&mut self, env: &Envelope) -> Result<Established> {
        if env.msg_type != MsgType::ClientFinish {
            bail!("expected CLIENT_FINISH");
        }
        let ss_mix = self.ss_mix.ok_or_else(|| anyhow!("no ss_mix"))?;
        let p = &env.payload;
        let mut r = FieldReader::new(p);
        let client_pq_vk = r.take()?;
        let client_ed_vk = r.take()?;
        let pq_sig = r.take()?;
        let ed_sig = r.take()?;
        let mac = r.take()?;

        let client = PeerPublic::from_bytes(client_pq_vk, client_ed_vk)?;
        let client_id = client.identity_id();
        if !self.allow_any && !self.authorized.contains(&client_id) {
            bail!("client identity not authorized");
        }

        // Client signed over the transcript as it stood at CLIENT_FINISH time,
        // i.e. (client_hello || server_hello). The server's transcript matches.
        client.verify_transcript(&self.transcript, pq_sig, ed_sig)?;

        // Confirm the client derived the same ss_mix.
        let mut expect = HmacSha256::new_from_slice(&ss_mix).unwrap();
        expect.update(&self.transcript);
        expect
            .verify_slice(mac)
            .map_err(|_| anyhow!("handshake MAC mismatch"))?;

        Ok(finish_from_ss(ss_mix, client_id))
    }
}

/// `ss_mix = HKDF(ikm = ss_pq || ss_x, salt = client_nonce || server_nonce,
/// info = "PQANON-HS/1")` (§6.3).
fn derive_ss_mix(
    ss_pq: &[u8],
    ss_x: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(ss_pq.len() + 32);
    ikm.extend_from_slice(ss_pq);
    ikm.extend_from_slice(ss_x);
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(client_nonce);
    salt.extend_from_slice(server_nonce);
    kdf::hkdf::<32>(&ikm, Some(&salt), b"PQANON-HS/1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_roundtrip() {
        let server_id = Identity::generate();
        let client_id = Identity::generate();

        let server_pub = server_id.public();
        let client_authorized = vec![client_id.identity_id()];

        let hs_conn_id = 0x0102_0304_0506_0708;
        let mut client = ClientHandshake::new(client_id, server_pub, hs_conn_id);
        let mut server = ServerHandshake::new(server_id, client_authorized, hs_conn_id);

        // Round-trip all three messages through plain framing (as on the wire,
        // pre-obfuscation) to exercise serialization too.
        let hello = client.client_hello([7u8; 32]).unwrap();
        let hello = Envelope::from_plain(&hello.to_plain()).unwrap();
        server.recv_client_hello(&hello, false).unwrap();

        let shello = server.server_hello().unwrap();
        let shello = Envelope::from_plain(&shello.to_plain()).unwrap();
        client.recv_server_hello(&shello).unwrap();

        let (finish, client_est) = client.client_finish().unwrap();
        let finish = Envelope::from_plain(&finish.to_plain()).unwrap();
        let server_est = server.recv_client_finish(&finish).unwrap();

        // Both sides agree on every derived value.
        assert_eq!(client_est.ss_mix, server_est.ss_mix);
        assert_eq!(client_est.conn_id, server_est.conn_id);
        assert_eq!(client_est.k_c2s, server_est.k_c2s);
        assert_eq!(client_est.k_s2c, server_est.k_s2c);
    }

    #[test]
    fn unauthorized_client_rejected() {
        let server_id = Identity::generate();
        let client_id = Identity::generate();
        let server_pub = server_id.public();

        // Server authorizes a *different* identity.
        let other = Identity::generate().identity_id();

        let hs = 1u64;
        let mut client = ClientHandshake::new(client_id, server_pub, hs);
        let mut server = ServerHandshake::new(server_id, vec![other], hs);

        let hello = client.client_hello([0u8; 32]).unwrap();
        server.recv_client_hello(&hello, false).unwrap();
        let shello = server.server_hello().unwrap();
        client.recv_server_hello(&shello).unwrap();
        let (finish, _) = client.client_finish().unwrap();
        assert!(server.recv_client_finish(&finish).is_err());
    }

    #[test]
    fn restored_identity_still_matches_its_pin() {
        // A server restarts from its stored identity; a client that pinned the
        // original public keys must still complete the handshake.
        let original = Identity::generate();
        let pinned = original.public();
        let bytes = original.to_secret_bytes();
        // FIPS 204 ML-DSA-65 sizes: signing key 4032, verifying key 1952.
        assert_eq!(bytes.len(), IDENTITY_MAGIC.len() + 32 + 4032 + 1952);
        let restored = Identity::from_secret_bytes(&bytes).unwrap();
        assert_eq!(restored.identity_id(), original.identity_id());

        let client_id = Identity::generate();
        let authorized = vec![client_id.identity_id()];
        let mut client = ClientHandshake::new(client_id, pinned, 9);
        let mut server = ServerHandshake::new(restored, authorized, 9);
        let hello = client.client_hello([0u8; 32]).unwrap();
        server.recv_client_hello(&hello, false).unwrap();
        let shello = server.server_hello().unwrap();
        client.recv_server_hello(&shello).unwrap();
        let (fin, ce) = client.client_finish().unwrap();
        let se = server.recv_client_finish(&fin).unwrap();
        assert_eq!(ce.ss_mix, se.ss_mix);
    }

    #[test]
    fn corrupt_identity_bytes_are_rejected() {
        let a = Identity::generate();
        let good = a.to_secret_bytes();

        let mut bad_magic = good.to_vec();
        bad_magic[0] ^= 0xff;
        assert!(Identity::from_secret_bytes(&bad_magic).is_err());

        assert!(Identity::from_secret_bytes(&good[..good.len() - 1]).is_err());

        // Splice another identity's ML-DSA verifying key onto a's signing key:
        // lengths are right, but the halves no longer belong together.
        let b = Identity::generate().to_secret_bytes();
        let vk_len = 1952;
        let mut spliced = good.to_vec();
        let n = spliced.len();
        spliced[n - vk_len..].copy_from_slice(&b[n - vk_len..]);
        let err = Identity::from_secret_bytes(&spliced).err().unwrap().to_string();
        assert!(err.contains("do not match"), "{err}");
    }

    #[test]
    fn wrong_server_key_rejected() {
        let server_id = Identity::generate();
        let client_id = Identity::generate();
        // Client pins the WRONG server key.
        let wrong_server_pub = Identity::generate().public();

        let hs = 2u64;
        let mut client = ClientHandshake::new(client_id, wrong_server_pub, hs);
        let mut server = ServerHandshake::new(server_id, vec![], hs);

        let hello = client.client_hello([0u8; 32]).unwrap();
        server.recv_client_hello(&hello, false).unwrap();
        let shello = server.server_hello().unwrap();
        // Client must reject the server's signature.
        assert!(client.recv_server_hello(&shello).is_err());
    }
}
