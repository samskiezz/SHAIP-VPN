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
//! ML-DSA-65 **and** Ed25519 keys. The client's long-term verifying keys (and,
//! for a device-bound server, its device certificate) travel inside
//! CLIENT_FINISH, which is AEAD-sealed under a key derived from `ss_mix`. The
//! server can check the `identity_id` against its authorized set (or verify the
//! device certificate) and the signatures, while no identifier ever appears in
//! cleartext on the wire.

use crate::enrollment::DeviceCert;
use crate::kdf;
use crate::wire::{Envelope, MsgType};
use anyhow::{anyhow, bail, Result};
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
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

    /// Proof of possession for an enrollment claim: an Ed25519 signature over
    /// `PQANON-ENROLL-CLAIM-V1:<token>`, byte-for-byte what the control plane
    /// verifies. The ASCII prefix keeps it from being valid anywhere else this
    /// key signs — a handshake transcript starts with a length-prefixed ML-KEM
    /// key, never with this text.
    pub fn sign_enrollment_claim(&self, token: &str) -> [u8; 64] {
        self.ed
            .sign(format!("PQANON-ENROLL-CLAIM-V1:{token}").as_bytes())
            .to_bytes()
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
    /// On a device-bound server: the client's verified device certificate.
    pub device: Option<DeviceCert>,
}

fn finish_from_ss(ss_mix: [u8; 32], peer_id: [u8; 16]) -> Established {
    let (k_c2s, k_s2c) = kdf::directional_keys(&ss_mix);
    Established {
        ss_mix,
        conn_id: kdf::conn_id(&ss_mix),
        k_c2s,
        k_s2c,
        peer_id,
        device: None,
    }
}

// ---------------------------------------------------------------------------
// Sealed CLIENT_FINISH
// ---------------------------------------------------------------------------
//
// CLIENT_FINISH carries the client's long-term public keys and, on a device-
// bound server, its device certificate — all of which identify the user. It is
// therefore AEAD-sealed under a key derived from `ss_mix`, which a passive
// observer never learns. The key is unique to this handshake and seals exactly
// one message, so a fixed nonce is safe.

fn finish_cipher(ss_mix: &[u8; 32]) -> ChaCha20Poly1305 {
    // Scoped: at module level KeyInit would make HMAC's `new_from_slice`
    // ambiguous (HMAC implements both KeyInit and Mac).
    use chacha20poly1305::KeyInit;
    let key = kdf::hkdf::<32>(ss_mix, None, b"PQANON-HS/1 client-finish");
    ChaCha20Poly1305::new(Key::from_slice(&key))
}

fn finish_aad(hs_conn_id: u64) -> Vec<u8> {
    let mut aad = b"PQANON-HS/1 CLIENT_FINISH".to_vec();
    aad.extend_from_slice(&hs_conn_id.to_be_bytes());
    aad
}

fn seal_finish(ss_mix: &[u8; 32], hs_conn_id: u64, inner: &[u8]) -> Result<Vec<u8>> {
    let aad = finish_aad(hs_conn_id);
    finish_cipher(ss_mix)
        .encrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: inner, aad: &aad })
        .map_err(|_| anyhow!("CLIENT_FINISH seal failed"))
}

fn open_finish(ss_mix: &[u8; 32], hs_conn_id: u64, sealed: &[u8]) -> Result<Vec<u8>> {
    let aad = finish_aad(hs_conn_id);
    finish_cipher(ss_mix)
        .decrypt(Nonce::from_slice(&[0u8; 12]), Payload { msg: sealed, aad: &aad })
        .map_err(|_| anyhow!("CLIENT_FINISH does not open (tampered, or a different ss_mix)"))
}

// ---------------------------------------------------------------------------
// Device-certificate admission (one-click enrollment)
// ---------------------------------------------------------------------------

/// Reports whether a device id is revoked (fed from the signed CRL).
pub type RevocationCheck = std::sync::Arc<dyn Fn(&[u8; 16]) -> bool + Send + Sync>;

/// Admission by device certificate. A device-bound server admits a client only
/// if it presents a certificate, signed by the pinned device CA, that binds the
/// same Ed25519 key that signs the handshake transcript — and the device is not
/// revoked. A replayed certificate is useless without that key.
#[derive(Clone)]
pub struct DevicePolicy {
    /// The pinned device-CA key (the control plane's `/api/enroll/keys`).
    pub ca: EdVerifyingKey,
    /// True for a revoked device id.
    pub is_revoked: RevocationCheck,
}

fn admit_device(policy: &DevicePolicy, cert: Option<&[u8]>, client: &PeerPublic) -> Result<DeviceCert> {
    let cert = cert.ok_or_else(|| anyhow!("client presented no device certificate"))?;
    let cert = std::str::from_utf8(cert).map_err(|_| anyhow!("device certificate is not text"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dc = crate::enrollment::verify_device_cert(&policy.ca, cert, now)
        .map_err(|e| anyhow!("device certificate rejected: {e}"))?;
    if dc.device_pub != client.ed_bytes() {
        bail!("device certificate is bound to a different key");
    }
    if (policy.is_revoked)(&dc.device_id) {
        bail!("device has been revoked");
    }
    Ok(dc)
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
    device_cert: Option<String>,
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
            device_cert: None,
        }
    }

    /// Present this device certificate to a device-bound server. It must bind
    /// this identity's Ed25519 key (the server checks); it travels inside the
    /// sealed CLIENT_FINISH, never in cleartext.
    pub fn set_device_cert(&mut self, cert: impl Into<String>) {
        self.device_cert = Some(cert.into());
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
        let mut inner = Vec::new();
        put_field(&mut inner, &pub_.pq_bytes());
        put_field(&mut inner, &pub_.ed_bytes());
        put_field(&mut inner, &pq_sig);
        put_field(&mut inner, &ed_sig);
        put_field(&mut inner, &mac_bytes);
        if let Some(cert) = &self.device_cert {
            put_field(&mut inner, cert.as_bytes());
        }
        let payload = seal_finish(&ss_mix, self.hs_conn_id, &inner)?;

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
    /// When set, admission is by device certificate instead of `authorized`.
    device_policy: Option<DevicePolicy>,
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
            device_policy: None,
        }
    }

    /// Like [`ServerHandshake::new`] but accepts any well-formed client identity
    /// (no pinned allow-list). Intended for demo daemons, never production.
    pub fn new_open(id: Identity, hs_conn_id: u64) -> Self {
        let mut s = Self::new(id, Vec::new(), hs_conn_id);
        s.allow_any = true;
        s
    }

    /// Admit clients by enrolled device certificate (see [`DevicePolicy`])
    /// rather than by a static allow-list of identity ids.
    pub fn new_device_bound(id: Identity, policy: DevicePolicy, hs_conn_id: u64) -> Self {
        let mut s = Self::new(id, Vec::new(), hs_conn_id);
        s.device_policy = Some(policy);
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
        let inner = open_finish(&ss_mix, self.hs_conn_id, &env.payload)?;
        let mut r = FieldReader::new(&inner);
        let client_pq_vk = r.take()?;
        let client_ed_vk = r.take()?;
        let pq_sig = r.take()?;
        let ed_sig = r.take()?;
        let mac = r.take()?;
        let cert = if r.consumed() < inner.len() { Some(r.take()?) } else { None };
        if r.consumed() != inner.len() {
            bail!("trailing bytes in CLIENT_FINISH");
        }

        let client = PeerPublic::from_bytes(client_pq_vk, client_ed_vk)?;
        let client_id = client.identity_id();
        let device = match &self.device_policy {
            // The transcript signature verified below proves the client holds
            // the key the certificate binds.
            Some(policy) => Some(admit_device(policy, cert, &client)?),
            None => {
                if !self.allow_any && !self.authorized.contains(&client_id) {
                    bail!("client identity not authorized");
                }
                None
            }
        };

        // Client signed over the transcript as it stood at CLIENT_FINISH time,
        // i.e. (client_hello || server_hello). The server's transcript matches.
        client.verify_transcript(&self.transcript, pq_sig, ed_sig)?;

        // Confirm the client derived the same ss_mix.
        let mut expect = HmacSha256::new_from_slice(&ss_mix).unwrap();
        expect.update(&self.transcript);
        expect
            .verify_slice(mac)
            .map_err(|_| anyhow!("handshake MAC mismatch"))?;

        let mut est = finish_from_ss(ss_mix, client_id);
        est.device = device;
        Ok(est)
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

    /// Run a handshake up to the server's CLIENT_FINISH verdict, returning the
    /// CLIENT_FINISH bytes exactly as framed on the wire.
    fn finish_over_wire(
        client: &mut ClientHandshake,
        server: &mut ServerHandshake,
    ) -> (Vec<u8>, Result<Established>) {
        let hello = client.client_hello([0u8; 32]).unwrap();
        server.recv_client_hello(&hello, false).unwrap();
        let shello = server.server_hello().unwrap();
        client.recv_server_hello(&shello).unwrap();
        let (fin, _) = client.client_finish().unwrap();
        let wire = fin.to_plain();
        let fin = Envelope::from_plain(&wire).unwrap();
        (wire.clone(), server.recv_client_finish(&fin))
    }

    fn unix_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn policy(ca: &EdSigningKey, revoked: Vec<[u8; 16]>) -> DevicePolicy {
        DevicePolicy {
            ca: ca.verifying_key(),
            is_revoked: std::sync::Arc::new(move |id| revoked.contains(id)),
        }
    }

    fn cert_for(ca: &EdSigningKey, id: &Identity, device_id: [u8; 16], expires_in: i64) -> String {
        let now = unix_now();
        crate::enrollment::test_issuer::device_cert(
            ca,
            device_id,
            "acct-test",
            id.public().ed_bytes(),
            now - 60,
            now + expires_in,
        )
    }

    #[test]
    fn client_finish_hides_identity_and_certificate_on_the_wire() {
        let server_id = Identity::generate();
        let client_id = Identity::generate();
        let ca = EdSigningKey::generate(&mut OsRng);
        let cert = cert_for(&ca, &client_id, [3; 16], 3600);
        let ed = client_id.public().ed_bytes();
        let pq = client_id.public().pq_bytes();

        let mut c = ClientHandshake::new(client_id, server_id.public(), 5);
        c.set_device_cert(cert.clone());
        let mut s = ServerHandshake::new_device_bound(server_id, policy(&ca, vec![]), 5);
        let (wire, res) = finish_over_wire(&mut c, &mut s);
        res.expect("enrolled device admitted");

        let contains = |needle: &[u8]| wire.windows(needle.len()).any(|w| w == needle);
        assert!(!contains(&ed), "Ed25519 identity key leaked onto the wire");
        assert!(!contains(&pq[..64]), "ML-DSA identity key leaked onto the wire");
        assert!(!contains(cert.as_bytes()), "device certificate leaked onto the wire");
        assert!(!contains(b"acct-test"), "account id leaked onto the wire");
    }

    #[test]
    fn tampered_client_finish_is_rejected() {
        let server_id = Identity::generate();
        let client_id = Identity::generate();
        let authorized = vec![client_id.identity_id()];
        let mut c = ClientHandshake::new(client_id, server_id.public(), 6);
        let mut s = ServerHandshake::new(server_id, authorized, 6);
        let hello = c.client_hello([0u8; 32]).unwrap();
        s.recv_client_hello(&hello, false).unwrap();
        let shello = s.server_hello().unwrap();
        c.recv_server_hello(&shello).unwrap();
        let (mut fin, _) = c.client_finish().unwrap();
        let last = fin.payload.len() - 1;
        fin.payload[last] ^= 0x01;
        let err = s.recv_client_finish(&fin).err().unwrap().to_string();
        assert!(err.contains("does not open"), "{err}");
    }

    #[test]
    fn device_bound_server_admits_an_enrolled_device() {
        let server_id = Identity::generate();
        let client_id = Identity::generate();
        let ca = EdSigningKey::generate(&mut OsRng);
        let mut c = ClientHandshake::new(client_id.clone(), server_id.public(), 7);
        c.set_device_cert(cert_for(&ca, &client_id, [0x42; 16], 3600));
        let mut s = ServerHandshake::new_device_bound(server_id, policy(&ca, vec![]), 7);
        let (_, res) = finish_over_wire(&mut c, &mut s);
        let est = res.expect("admitted");
        let dev = est.device.expect("device recorded");
        assert_eq!(dev.device_id, [0x42; 16]);
        assert_eq!(dev.account, "acct-test");
        assert_eq!(est.peer_id, client_id.identity_id());
    }

    #[test]
    fn device_bound_server_refuses_unenrolled_mismatched_foreign_revoked_or_expired() {
        let ca = EdSigningKey::generate(&mut OsRng);
        let other_ca = EdSigningKey::generate(&mut OsRng);
        let refuse = |cert: Option<String>, revoked: Vec<[u8; 16]>, client_id: Identity, want: &str| {
            let server_id = Identity::generate();
            let mut c = ClientHandshake::new(client_id, server_id.public(), 8);
            if let Some(cert) = cert {
                c.set_device_cert(cert);
            }
            let mut s = ServerHandshake::new_device_bound(server_id, policy(&ca, revoked), 8);
            let (_, res) = finish_over_wire(&mut c, &mut s);
            let err = res.expect_err("must be refused").to_string();
            assert!(err.contains(want), "want {want:?}, got {err:?}");
        };

        let id = Identity::generate();
        // No certificate at all.
        refuse(None, vec![], id.clone(), "no device certificate");
        // A valid certificate, but for another device's key.
        let other = Identity::generate();
        refuse(Some(cert_for(&ca, &other, [1; 16], 3600)), vec![], id.clone(), "different key");
        // Signed by a CA this server does not pin.
        refuse(Some(cert_for(&other_ca, &id, [1; 16], 3600)), vec![], id.clone(), "rejected");
        // Revoked.
        refuse(Some(cert_for(&ca, &id, [9; 16], 3600)), vec![[9; 16]], id.clone(), "revoked");
        // Expired.
        refuse(Some(cert_for(&ca, &id, [1; 16], -30)), vec![], id, "rejected");
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
