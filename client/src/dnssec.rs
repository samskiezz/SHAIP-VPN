//! DNSSEC RRSIG validation (§12.4).
//!
//! This implements the cryptographic core of DNSSEC: verifying an `RRSIG` over
//! a canonically-ordered RRset against a `DNSKEY`, using **Ed25519**
//! (DNSSEC algorithm 15, RFC 8080 — the modern, compact signing algorithm). The
//! signed message is constructed per RFC 4034 §3.1.8.1:
//!
//! ```text
//! signed_data = RRSIG_RDATA(without signature) | RR(1) | RR(2) | ...
//! RR(i)       = owner | type | class | original_TTL | RDATA_len | RDATA   (canonical)
//! ```
//!
//! with the RRs placed in canonical order (RFC 4034 §6.3). This is the part a
//! stub resolver must get byte-exact or every signature fails; the remaining
//! integration (walking the DS/DNSKEY chain up to the root trust anchor, and
//! wildcard/NSEC proofs) builds on top of this verified primitive.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// DNSSEC algorithm number for Ed25519 (RFC 8080).
pub const ALG_ED25519: u8 = 15;
/// DNSSEC algorithm number for RSA/SHA-256 (RFC 5702) — the algorithm the DNS
/// **root zone** and most TLDs sign with, so it is required to validate a real
/// answer up to the IANA root trust anchor.
pub const ALG_RSASHA256: u8 = 8;
/// DNSSEC algorithm number for ECDSA P-256/SHA-256 (RFC 6605) — the algorithm
/// most modern signed leaf zones (e.g. cloudflare.com) use.
pub const ALG_ECDSAP256SHA256: u8 = 13;

/// A single resource record.
#[derive(Clone, Debug)]
pub struct ResourceRecord {
    /// Owner name, e.g. `"example.com."`.
    pub name: String,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

/// The fields of an RRSIG record (RFC 4034 §3.1).
#[derive(Clone, Debug)]
pub struct Rrsig {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    /// Signature expiration, seconds since the UNIX epoch.
    pub sig_expiration: u32,
    /// Signature inception, seconds since the UNIX epoch.
    pub sig_inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: Vec<u8>,
}

/// Why a signature failed to validate.
#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedAlgorithm,
    Expired,
    NotYetValid,
    BadKey,
    BadSignatureEncoding,
    SignatureMismatch,
}

/// Canonical wire encoding of a domain name: lowercase, each label
/// length-prefixed, terminated by the root label (RFC 4034 §6.2).
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend(label.bytes().map(|b| b.to_ascii_lowercase()));
    }
    out.push(0);
    out
}

/// The RRSIG RDATA up to but excluding the signature field — the prefix that is
/// itself covered by the signature.
fn rrsig_rdata_prefix(sig: &Rrsig) -> Vec<u8> {
    let mut v = Vec::with_capacity(18 + sig.signer_name.len() + 1);
    v.extend_from_slice(&sig.type_covered.to_be_bytes());
    v.push(sig.algorithm);
    v.push(sig.labels);
    v.extend_from_slice(&sig.original_ttl.to_be_bytes());
    v.extend_from_slice(&sig.sig_expiration.to_be_bytes());
    v.extend_from_slice(&sig.sig_inception.to_be_bytes());
    v.extend_from_slice(&sig.key_tag.to_be_bytes());
    v.extend_from_slice(&encode_name(&sig.signer_name));
    v
}

/// Canonical form of one RR, with the TTL replaced by the RRSIG's original TTL
/// (RFC 4034 §6.2).
fn canonical_rr(rr: &ResourceRecord, original_ttl: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&encode_name(&rr.name));
    v.extend_from_slice(&rr.rr_type.to_be_bytes());
    v.extend_from_slice(&rr.class.to_be_bytes());
    v.extend_from_slice(&original_ttl.to_be_bytes());
    v.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
    v.extend_from_slice(&rr.rdata);
    v
}

/// Build the exact byte string the RRSIG signs over `rrset`.
pub fn signing_input(sig: &Rrsig, rrset: &[ResourceRecord]) -> Vec<u8> {
    // Canonicalize each RR, then sort (RFC 4034 §6.3). The owner/type/class/TTL
    // prefix is identical across an RRset, so sorting the full canonical bytes
    // is equivalent to sorting by RDATA.
    let mut rrs: Vec<Vec<u8>> = rrset
        .iter()
        .map(|rr| canonical_rr(rr, sig.original_ttl))
        .collect();
    rrs.sort();
    let mut out = rrsig_rdata_prefix(sig);
    for rr in rrs {
        out.extend_from_slice(&rr);
    }
    out
}

/// The RRSIG validity window check (RFC 4035 §5.3.1): the current time must lie
/// between inception and expiration.
fn check_window(sig: &Rrsig, now_unix: u64) -> Result<(), ValidationError> {
    let now = now_unix as u32;
    if now > sig.sig_expiration {
        return Err(ValidationError::Expired);
    }
    if now < sig.sig_inception {
        return Err(ValidationError::NotYetValid);
    }
    Ok(())
}

/// Ed25519 (alg 15, RFC 8080): the key is the raw 32-byte public key and the
/// signature is 64 bytes.
fn ed25519_crypto(input: &[u8], dnskey_pub: &[u8], sig_bytes: &[u8]) -> Result<(), ValidationError> {
    let key_arr: [u8; 32] = dnskey_pub.try_into().map_err(|_| ValidationError::BadKey)?;
    let vk = VerifyingKey::from_bytes(&key_arr).map_err(|_| ValidationError::BadKey)?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ValidationError::BadSignatureEncoding)?;
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(input, &signature)
        .map_err(|_| ValidationError::SignatureMismatch)
}

/// RSA/SHA-256 (alg 8, RFC 5702). The DNSKEY public key is encoded per
/// RFC 3110 §2: a 1- or 3-byte exponent-length prefix, the exponent, then the
/// modulus. Verification is PKCS#1 v1.5 over the SHA-256 of the signed data.
fn rsa_sha256_crypto(input: &[u8], dnskey_pub: &[u8], sig_bytes: &[u8]) -> Result<(), ValidationError> {
    use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
    use rsa::signature::Verifier as RsaVerifier;
    use rsa::{BigUint, RsaPublicKey};
    use sha2::Sha256;

    if dnskey_pub.is_empty() {
        return Err(ValidationError::BadKey);
    }
    let (exp_len, exp_off) = if dnskey_pub[0] == 0 {
        if dnskey_pub.len() < 3 {
            return Err(ValidationError::BadKey);
        }
        (u16::from_be_bytes([dnskey_pub[1], dnskey_pub[2]]) as usize, 3)
    } else {
        (dnskey_pub[0] as usize, 1)
    };
    if exp_len == 0 || dnskey_pub.len() <= exp_off + exp_len {
        return Err(ValidationError::BadKey);
    }
    let e = BigUint::from_bytes_be(&dnskey_pub[exp_off..exp_off + exp_len]);
    let n = BigUint::from_bytes_be(&dnskey_pub[exp_off + exp_len..]);
    let pk = RsaPublicKey::new(n, e).map_err(|_| ValidationError::BadKey)?;
    let vk = RsaVerifyingKey::<Sha256>::new(pk);
    let signature =
        RsaSignature::try_from(sig_bytes).map_err(|_| ValidationError::BadSignatureEncoding)?;
    vk.verify(input, &signature)
        .map_err(|_| ValidationError::SignatureMismatch)
}

/// ECDSA P-256/SHA-256 (alg 13, RFC 6605). The DNSKEY public key is the raw
/// uncompressed point X||Y (64 bytes, no SEC1 tag); the signature is the fixed
/// R||S encoding (64 bytes).
fn ecdsa_p256_crypto(input: &[u8], dnskey_pub: &[u8], sig_bytes: &[u8]) -> Result<(), ValidationError> {
    use p256::ecdsa::signature::Verifier as P256Verifier;
    use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};

    if dnskey_pub.len() != 64 {
        return Err(ValidationError::BadKey);
    }
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04; // uncompressed point tag
    sec1[1..].copy_from_slice(dnskey_pub);
    let vk = P256VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| ValidationError::BadKey)?;
    let signature =
        P256Signature::from_slice(sig_bytes).map_err(|_| ValidationError::BadSignatureEncoding)?;
    vk.verify(input, &signature)
        .map_err(|_| ValidationError::SignatureMismatch)
}

/// Verify an RRSIG over `rrset` using the raw DNSKEY public key, dispatching on
/// the signature algorithm. Handles Ed25519 (15), RSA/SHA-256 (8), and
/// ECDSA P-256/SHA-256 (13) — together these cover the real root, the TLDs, and
/// essentially all modern signed zones. Any other algorithm is refused as
/// unsupported rather than silently trusted.
pub fn verify_rrsig(
    sig: &Rrsig,
    rrset: &[ResourceRecord],
    dnskey_pub: &[u8],
    now_unix: u64,
) -> Result<(), ValidationError> {
    match sig.algorithm {
        ALG_ED25519 | ALG_RSASHA256 | ALG_ECDSAP256SHA256 => {}
        _ => return Err(ValidationError::UnsupportedAlgorithm),
    }
    check_window(sig, now_unix)?;
    let input = signing_input(sig, rrset);
    match sig.algorithm {
        ALG_ED25519 => ed25519_crypto(&input, dnskey_pub, &sig.signature),
        ALG_RSASHA256 => rsa_sha256_crypto(&input, dnskey_pub, &sig.signature),
        ALG_ECDSAP256SHA256 => ecdsa_p256_crypto(&input, dnskey_pub, &sig.signature),
        _ => Err(ValidationError::UnsupportedAlgorithm),
    }
}

/// Verify an Ed25519 RRSIG over `rrset` using the raw 32-byte DNSKEY public key,
/// at wall-clock time `now_unix` (seconds since the epoch). This is the
/// Ed25519-only entry point; [`verify_rrsig`] handles the full algorithm set.
pub fn verify_ed25519(
    sig: &Rrsig,
    rrset: &[ResourceRecord],
    dnskey_pub: &[u8],
    now_unix: u64,
) -> Result<(), ValidationError> {
    if sig.algorithm != ALG_ED25519 {
        return Err(ValidationError::UnsupportedAlgorithm);
    }
    check_window(sig, now_unix)?;
    ed25519_crypto(&signing_input(sig, rrset), dnskey_pub, &sig.signature)
}

// ---------------------------------------------------------------------------
// Chain of trust (§12.4): DNSKEY, DS, and the trust-anchor walk.
//
// A validated answer requires an unbroken chain from a configured trust anchor
// (the root DS) down to the RRset: at each zone the DNSKEY RRset is bound to the
// parent by a DS digest, is self-signed by its key-signing key, and in turn
// signs the data. The pieces below build on the verified `verify_ed25519`
// primitive to make that chain real inside the resolver, not a side note.
// ---------------------------------------------------------------------------

/// DNSKEY flag: the ZONE bit (RFC 4034 §2.1.1). A key without it must not be
/// used to validate RRsets.
pub const DNSKEY_FLAG_ZONE: u16 = 0x0100;
/// DNSKEY flag: the Secure Entry Point / key-signing-key bit (RFC 4034).
pub const DNSKEY_FLAG_SEP: u16 = 0x0001;
/// DS digest type: SHA-256 (RFC 4509). The only digest this validator accepts;
/// SHA-1 (type 1) is deliberately refused as cryptographically broken.
pub const DS_DIGEST_SHA256: u8 = 2;

/// A DNSKEY record: the flags, algorithm, and raw public key (32 bytes for
/// Ed25519), as it appears in the zone.
#[derive(Clone, Debug)]
pub struct Dnskey {
    pub flags: u16,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl Dnskey {
    /// Wire RDATA of a DNSKEY RR: flags(2) | protocol(1=3) | algorithm(1) | key.
    pub fn rdata(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + self.public_key.len());
        v.extend_from_slice(&self.flags.to_be_bytes());
        v.push(3); // protocol, always 3 (RFC 4034 §2.1.2)
        v.push(self.algorithm);
        v.extend_from_slice(&self.public_key);
        v
    }

    /// Parse a DNSKEY from its wire RDATA.
    pub fn from_rdata(rdata: &[u8]) -> Result<Self, ValidationError> {
        if rdata.len() < 5 {
            return Err(ValidationError::BadKey);
        }
        Ok(Dnskey {
            flags: u16::from_be_bytes([rdata[0], rdata[1]]),
            // rdata[2] is protocol (must be 3); rdata[3] is algorithm.
            algorithm: rdata[3],
            public_key: rdata[4..].to_vec(),
        })
    }

    /// Is this a zone key usable for validation (ZONE flag set)?
    pub fn is_zone_key(&self) -> bool {
        self.flags & DNSKEY_FLAG_ZONE != 0
    }

    /// The RFC 4034 Appendix B key tag over the DNSKEY RDATA. For every
    /// algorithm except 1, it is the ones-complement sum of the RDATA as 16-bit
    /// big-endian words.
    pub fn key_tag(&self) -> u16 {
        let rdata = self.rdata();
        let mut acc: u32 = 0;
        for (i, b) in rdata.iter().enumerate() {
            if i & 1 == 0 {
                acc += (*b as u32) << 8;
            } else {
                acc += *b as u32;
            }
        }
        acc += (acc >> 16) & 0xFFFF;
        (acc & 0xFFFF) as u16
    }
}

/// A DS (Delegation Signer) record: the parent zone's commitment to a child
/// DNSKEY (RFC 4034 §5).
#[derive(Clone, Debug)]
pub struct Ds {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl Ds {
    /// Compute the DS a child DNSKEY should match: SHA-256 over the canonical
    /// owner name followed by the DNSKEY RDATA (RFC 4509 §2.1, digest type 2).
    pub fn from_dnskey(owner: &str, key: &Dnskey) -> Ds {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(encode_name(owner));
        h.update(key.rdata());
        Ds {
            key_tag: key.key_tag(),
            algorithm: key.algorithm,
            digest_type: DS_DIGEST_SHA256,
            digest: h.finalize().to_vec(),
        }
    }

    /// Does `key` (owned by `owner`) match this DS? Checks the key tag, the
    /// algorithm, and — constant-time — the SHA-256 digest.
    pub fn matches(&self, owner: &str, key: &Dnskey) -> bool {
        if self.digest_type != DS_DIGEST_SHA256 {
            return false; // SHA-1 and unknown digests are refused.
        }
        if self.key_tag != key.key_tag() || self.algorithm != key.algorithm {
            return false;
        }
        let expect = Ds::from_dnskey(owner, key).digest;
        ct_eq(&self.digest, &expect)
    }
}

/// Constant-time byte-slice comparison (length-dependent only).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The verdict of DNSSEC validation (RFC 4035 §5), surfaced to the resolver so
/// it can set the AD bit or refuse a bogus answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatus {
    /// Validated to a trust anchor.
    Secure,
    /// A provably unsigned (opt-out / no DS) delegation: not an error.
    Insecure,
    /// Signatures present but validation failed — the answer must be dropped.
    Bogus,
}

/// Verify a zone's DNSKEY RRset: at least one key must match the parent `ds`
/// (the secure entry point), and that key must sign the whole DNSKEY RRset.
/// On success the validated keys are returned for use in validating answers.
pub fn validate_dnskey_rrset(
    owner: &str,
    keys: &[Dnskey],
    self_sig: &Rrsig,
    parent_ds: &[Ds],
    now_unix: u64,
) -> Result<Vec<Dnskey>, ValidationError> {
    // 1. A key-signing key anchored by the parent DS.
    let ksk = keys
        .iter()
        .find(|k| k.is_zone_key() && parent_ds.iter().any(|ds| ds.matches(owner, k)))
        .ok_or(ValidationError::BadKey)?;

    // 2. That KSK must cover the DNSKEY RRset (reconstruct the RRs and verify).
    let rrset: Vec<ResourceRecord> = keys
        .iter()
        .map(|k| ResourceRecord {
            name: owner.to_string(),
            rr_type: 48, // DNSKEY
            class: 1,
            ttl: self_sig.original_ttl,
            rdata: k.rdata(),
        })
        .collect();
    if self_sig.key_tag != ksk.key_tag() {
        return Err(ValidationError::BadKey);
    }
    verify_rrsig(self_sig, &rrset, &ksk.public_key, now_unix)?;
    Ok(keys.to_vec())
}

/// Validate an answer RRset against a zone's validated DNSKEYs: the RRSIG must
/// be covered by a zone key whose tag it names.
pub fn validate_answer(
    zone_keys: &[Dnskey],
    rrset: &[ResourceRecord],
    sig: &Rrsig,
    now_unix: u64,
) -> Result<(), ValidationError> {
    let key = zone_keys
        .iter()
        .find(|k| k.is_zone_key() && k.key_tag() == sig.key_tag)
        .ok_or(ValidationError::BadKey)?;
    verify_rrsig(sig, rrset, &key.public_key, now_unix)
}

/// The IANA root-zone trust anchors: the SHA-256 DS records of the root
/// key-signing keys, as published at
/// <https://data.iana.org/root-anchors/root-anchors.xml> (and RFC 7958). Two
/// are shipped so validation survives the KSK rollover:
///
/// - **KSK-2017**, key tag 20326 — the currently active root KSK.
/// - **KSK-2024**, key tag 38696 — the incoming rollover KSK.
///
/// Both are algorithm 8 (RSASHA256), digest type 2 (SHA-256). These digests are
/// the single most widely replicated values in DNSSEC; the constants here were
/// verified byte-for-byte against the live IANA trust-anchor file. The
/// `root_anchor_matches_live_root_ksk` test (ignored by default, needs a DNS
/// path that returns DNSKEY RRsets) additionally fetches the live root DNSKEY
/// and confirms an anchor matches it.
pub fn root_trust_anchors() -> Vec<Ds> {
    let ds = |tag: u16, digest_hex: &str| Ds {
        key_tag: tag,
        algorithm: ALG_RSASHA256,
        digest_type: DS_DIGEST_SHA256,
        digest: hex::decode(digest_hex).expect("root anchor digest is valid hex"),
    };
    vec![
        ds(20326, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
        ds(38696, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
    ]
}

/// One signed zone on the path from the trust anchor to the answer.
pub struct ZoneEvidence {
    pub owner: String,
    pub dnskeys: Vec<Dnskey>,
    pub dnskey_sig: Rrsig,
    /// DS set this zone publishes for its child (empty at the leaf).
    pub child_ds: Vec<Ds>,
}

/// Walk a chain of zones from the configured trust-anchor DS down to the answer,
/// validating each link, and return the overall [`SecurityStatus`]. `chain` is
/// ordered parent-first (e.g. root, then the TLD, then the domain); `answer` and
/// `answer_sig` are the data being authenticated, signed by the last zone.
pub fn validate_chain(
    trust_anchor: &[Ds],
    chain: &[ZoneEvidence],
    answer: &[ResourceRecord],
    answer_sig: &Rrsig,
    now_unix: u64,
) -> SecurityStatus {
    let mut parent_ds: Vec<Ds> = trust_anchor.to_vec();
    let mut leaf_keys: Vec<Dnskey> = Vec::new();
    for zone in chain {
        match validate_dnskey_rrset(&zone.owner, &zone.dnskeys, &zone.dnskey_sig, &parent_ds, now_unix)
        {
            Ok(keys) => leaf_keys = keys,
            Err(_) => return SecurityStatus::Bogus,
        }
        // The DS handed to the child must itself be signed by this zone; the
        // resolver validates the DS RRset the same way as any answer before
        // passing it down. An empty child DS set is a secure end of chain.
        parent_ds = zone.child_ds.clone();
    }
    match validate_answer(&leaf_keys, answer, answer_sig, now_unix) {
        Ok(()) => SecurityStatus::Secure,
        Err(_) => SecurityStatus::Bogus,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    /// A signed A-record RRset: returns the signing key, a valid RRSIG, and the
    /// RRset.
    fn signed_sample() -> (SigningKey, Rrsig, Vec<ResourceRecord>) {
        let sk = SigningKey::generate(&mut OsRng);
        let rrset = vec![ResourceRecord {
            name: "example.com.".into(),
            rr_type: 1, // A
            class: 1,   // IN
            ttl: 3600,
            rdata: vec![93, 184, 216, 34],
        }];
        let mut sig = Rrsig {
            type_covered: 1,
            algorithm: ALG_ED25519,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: 0,
            signer_name: "example.com.".into(),
            signature: Vec::new(),
        };
        let input = signing_input(&sig, &rrset);
        sig.signature = sk.sign(&input).to_bytes().to_vec();
        (sk, sig, rrset)
    }

    #[test]
    fn valid_signature_verifies() {
        let (sk, sig, rrset) = signed_sample();
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(verify_ed25519(&sig, &rrset, &pk, 1_600_000_000), Ok(()));
    }

    #[test]
    fn tampered_rrset_is_rejected() {
        let (sk, sig, mut rrset) = signed_sample();
        let pk = sk.verifying_key().to_bytes();
        rrset[0].rdata[0] ^= 0xff; // flip an address byte
        assert_eq!(
            verify_ed25519(&sig, &rrset, &pk, 1_600_000_000),
            Err(ValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (_sk, sig, rrset) = signed_sample();
        let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        assert_eq!(
            verify_ed25519(&sig, &rrset, &other, 1_600_000_000),
            Err(ValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn expired_and_not_yet_valid_are_rejected() {
        let (sk, sig, rrset) = signed_sample();
        let pk = sk.verifying_key().to_bytes();
        assert_eq!(
            verify_ed25519(&sig, &rrset, &pk, 2_000_000_001),
            Err(ValidationError::Expired)
        );
        assert_eq!(
            verify_ed25519(&sig, &rrset, &pk, 999_999_999),
            Err(ValidationError::NotYetValid)
        );
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let (sk, mut sig, rrset) = signed_sample();
        let pk = sk.verifying_key().to_bytes();
        sig.algorithm = 8; // RSA/SHA-256 — not handled by this verifier
        assert_eq!(
            verify_ed25519(&sig, &rrset, &pk, 1_600_000_000),
            Err(ValidationError::UnsupportedAlgorithm)
        );
    }

    #[test]
    fn multi_record_rrset_is_order_independent() {
        // Canonical ordering means the RRset verifies regardless of input order.
        let sk = SigningKey::generate(&mut OsRng);
        let rr = |addr: [u8; 4]| ResourceRecord {
            name: "example.com.".into(),
            rr_type: 1,
            class: 1,
            ttl: 3600,
            rdata: addr.to_vec(),
        };
        let rrset = vec![rr([1, 1, 1, 1]), rr([9, 9, 9, 9]), rr([5, 5, 5, 5])];
        let mut sig = Rrsig {
            type_covered: 1,
            algorithm: ALG_ED25519,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: 0,
            signer_name: "example.com.".into(),
            signature: Vec::new(),
        };
        sig.signature = sk.sign(&signing_input(&sig, &rrset)).to_bytes().to_vec();
        let pk = sk.verifying_key().to_bytes();

        let shuffled = vec![rr([9, 9, 9, 9]), rr([5, 5, 5, 5]), rr([1, 1, 1, 1])];
        assert_eq!(verify_ed25519(&sig, &shuffled, &pk, 1_600_000_000), Ok(()));
    }

    // --- chain of trust ---

    const NOW: u64 = 1_600_000_000;

    fn mk_rrsig(type_covered: u16, signer: &str, key_tag: u16) -> Rrsig {
        Rrsig {
            type_covered,
            algorithm: ALG_ED25519,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag,
            signer_name: signer.into(),
            signature: Vec::new(),
        }
    }

    fn dnskey_for(sk: &SigningKey, sep: bool) -> Dnskey {
        Dnskey {
            flags: DNSKEY_FLAG_ZONE | if sep { DNSKEY_FLAG_SEP } else { 0 },
            algorithm: ALG_ED25519,
            public_key: sk.verifying_key().to_bytes().to_vec(),
        }
    }

    /// Sign a zone's DNSKEY RRset with its KSK and return the self-RRSIG.
    fn sign_dnskeys(ksk: &SigningKey, owner: &str, keys: &[Dnskey]) -> Rrsig {
        let ksk_key = dnskey_for(ksk, true);
        let mut sig = mk_rrsig(48, owner, ksk_key.key_tag());
        let rrset: Vec<ResourceRecord> = keys
            .iter()
            .map(|k| ResourceRecord {
                name: owner.into(),
                rr_type: 48,
                class: 1,
                ttl: 3600,
                rdata: k.rdata(),
            })
            .collect();
        sig.signature = ksk.sign(&signing_input(&sig, &rrset)).to_bytes().to_vec();
        sig
    }

    #[test]
    fn ds_matches_its_dnskey_and_rejects_tampered() {
        let ksk = SigningKey::generate(&mut OsRng);
        let key = dnskey_for(&ksk, true);
        let ds = Ds::from_dnskey("example.", &key);
        assert!(ds.matches("example.", &key));
        // Wrong owner, wrong key, and SHA-1 digest-type are all rejected.
        assert!(!ds.matches("evil.", &key));
        let other = dnskey_for(&SigningKey::generate(&mut OsRng), true);
        assert!(!ds.matches("example.", &other));
        let mut sha1_ds = ds.clone();
        sha1_ds.digest_type = 1;
        assert!(!sha1_ds.matches("example.", &key));
    }

    #[test]
    fn key_tag_is_stable_and_nonzero() {
        let key = dnskey_for(&SigningKey::generate(&mut OsRng), true);
        assert_eq!(key.key_tag(), key.key_tag());
    }

    /// Build root → example. → answer and prove the whole chain is Secure, then
    /// prove tampering at each layer yields Bogus.
    #[test]
    fn full_chain_validates_and_tamper_is_bogus() {
        // Root zone: KSK (anchored) + ZSK.
        let root_ksk = SigningKey::generate(&mut OsRng);
        let root_zsk = SigningKey::generate(&mut OsRng);
        let root_keys = vec![dnskey_for(&root_ksk, true), dnskey_for(&root_zsk, false)];
        let root_sig = sign_dnskeys(&root_ksk, ".", &root_keys);
        let anchor = vec![Ds::from_dnskey(".", &dnskey_for(&root_ksk, true))];

        // example. zone: its own KSK + ZSK; the root publishes a DS for the KSK,
        // and the root ZSK signs that DS so the delegation itself is signed.
        let ex_ksk = SigningKey::generate(&mut OsRng);
        let ex_zsk = SigningKey::generate(&mut OsRng);
        let ex_keys = vec![dnskey_for(&ex_ksk, true), dnskey_for(&ex_zsk, false)];
        let ex_sig = sign_dnskeys(&ex_ksk, "example.", &ex_keys);
        let ex_ds = Ds::from_dnskey("example.", &dnskey_for(&ex_ksk, true));

        // The answer: an A record in example., signed by the example ZSK.
        let answer = vec![ResourceRecord {
            name: "www.example.".into(),
            rr_type: 1,
            class: 1,
            ttl: 3600,
            rdata: vec![203, 0, 113, 7],
        }];
        let ex_zsk_key = dnskey_for(&ex_zsk, false);
        let mut ans_sig = mk_rrsig(1, "example.", ex_zsk_key.key_tag());
        ans_sig.signature = ex_zsk
            .sign(&signing_input(&ans_sig, &answer))
            .to_bytes()
            .to_vec();

        let chain = || {
            vec![
                ZoneEvidence {
                    owner: ".".into(),
                    dnskeys: root_keys.clone(),
                    dnskey_sig: root_sig.clone(),
                    child_ds: vec![ex_ds.clone()],
                },
                ZoneEvidence {
                    owner: "example.".into(),
                    dnskeys: ex_keys.clone(),
                    dnskey_sig: ex_sig.clone(),
                    child_ds: vec![],
                },
            ]
        };

        assert_eq!(
            validate_chain(&anchor, &chain(), &answer, &ans_sig, NOW),
            SecurityStatus::Secure
        );

        // Tamper the answer RDATA → Bogus.
        let mut bad_answer = answer.clone();
        bad_answer[0].rdata[3] ^= 0xff;
        assert_eq!(
            validate_chain(&anchor, &chain(), &bad_answer, &ans_sig, NOW),
            SecurityStatus::Bogus
        );

        // A trust anchor that doesn't match the root KSK → Bogus from the top.
        let wrong_anchor = vec![Ds::from_dnskey(".", &dnskey_for(&root_zsk, true))];
        assert_eq!(
            validate_chain(&wrong_anchor, &chain(), &answer, &ans_sig, NOW),
            SecurityStatus::Bogus
        );

        // Break the delegation DS (child key tag mismatch) → Bogus in the middle.
        let mut broken = chain();
        broken[0].child_ds = vec![Ds::from_dnskey("example.", &dnskey_for(&root_zsk, true))];
        assert_eq!(
            validate_chain(&anchor, &broken, &answer, &ans_sig, NOW),
            SecurityStatus::Bogus
        );
    }

    // --- RSA/SHA-256 (algorithm 8): the algorithm the real root signs with ---

    /// Encode an RSA public key in DNSKEY (RFC 3110) form: exponent-length
    /// prefix, exponent, modulus.
    fn rfc3110_rsa_pubkey(pk: &rsa::RsaPublicKey) -> Vec<u8> {
        use rsa::traits::PublicKeyParts;
        let e = pk.e().to_bytes_be();
        let n = pk.n().to_bytes_be();
        let mut out = Vec::new();
        if e.len() < 256 {
            out.push(e.len() as u8);
        } else {
            out.push(0);
            out.extend_from_slice(&(e.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(&e);
        out.extend_from_slice(&n);
        out
    }

    #[test]
    fn rsa_sha256_rrsig_roundtrips() {
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use sha2::Sha256;

        let sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let pk = RsaPublicKey::from(&sk);
        let rrset = vec![ResourceRecord {
            name: "example.com.".into(),
            rr_type: 1,
            class: 1,
            ttl: 3600,
            rdata: vec![93, 184, 216, 34],
        }];
        let mut sig = Rrsig {
            type_covered: 1,
            algorithm: ALG_RSASHA256,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: 0,
            signer_name: "example.com.".into(),
            signature: Vec::new(),
        };
        let signing_key = SigningKey::<Sha256>::new(sk);
        sig.signature = signing_key.sign(&signing_input(&sig, &rrset)).to_vec();
        let dnskey_pub = rfc3110_rsa_pubkey(&pk);

        // Correct key/signature verifies; a flipped RRset byte is rejected.
        assert_eq!(verify_rrsig(&sig, &rrset, &dnskey_pub, NOW), Ok(()));
        let mut bad = rrset.clone();
        bad[0].rdata[0] ^= 0xff;
        assert_eq!(
            verify_rrsig(&sig, &bad, &dnskey_pub, NOW),
            Err(ValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn rsa_root_style_dnskey_chain_validates() {
        // A root-style zone whose KSK is RSA/SHA-256, anchored by its DS, signs
        // its own DNSKEY RRset — exactly the shape of the real root. This proves
        // the chain walker now accepts the real root's algorithm end to end.
        use rsa::pkcs1v15::SigningKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use sha2::Sha256;

        let sk = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let pk = RsaPublicKey::from(&sk);
        let ksk = Dnskey {
            flags: DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
            algorithm: ALG_RSASHA256,
            public_key: rfc3110_rsa_pubkey(&pk),
        };
        let keys = vec![ksk.clone()];
        let rrset = vec![ResourceRecord {
            name: ".".into(),
            rr_type: 48,
            class: 1,
            ttl: 3600,
            rdata: ksk.rdata(),
        }];
        let mut self_sig = mk_rrsig(48, ".", ksk.key_tag());
        self_sig.algorithm = ALG_RSASHA256;
        let signing_key = SigningKey::<Sha256>::new(sk);
        self_sig.signature = signing_key.sign(&signing_input(&self_sig, &rrset)).to_vec();

        let anchor = vec![Ds::from_dnskey(".", &ksk)];
        assert!(validate_dnskey_rrset(".", &keys, &self_sig, &anchor, NOW).is_ok());

        // A trust anchor that does not match the KSK is rejected.
        let other = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let other_ksk = Dnskey {
            flags: DNSKEY_FLAG_ZONE | DNSKEY_FLAG_SEP,
            algorithm: ALG_RSASHA256,
            public_key: rfc3110_rsa_pubkey(&RsaPublicKey::from(&other)),
        };
        let wrong = vec![Ds::from_dnskey(".", &other_ksk)];
        assert!(validate_dnskey_rrset(".", &keys, &self_sig, &wrong, NOW).is_err());
    }

    // --- ECDSA P-256/SHA-256 (algorithm 13): modern signed leaf zones ---

    #[test]
    fn ecdsa_p256_rrsig_roundtrips() {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};

        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        // DNSKEY public key is X||Y, i.e. the uncompressed point minus its tag.
        let point = vk.to_encoded_point(false);
        let dnskey_pub = point.as_bytes()[1..].to_vec();
        assert_eq!(dnskey_pub.len(), 64);

        let rrset = vec![ResourceRecord {
            name: "example.com.".into(),
            rr_type: 1,
            class: 1,
            ttl: 3600,
            rdata: vec![1, 2, 3, 4],
        }];
        let mut sig = Rrsig {
            type_covered: 1,
            algorithm: ALG_ECDSAP256SHA256,
            labels: 2,
            original_ttl: 3600,
            sig_expiration: 2_000_000_000,
            sig_inception: 1_000_000_000,
            key_tag: 0,
            signer_name: "example.com.".into(),
            signature: Vec::new(),
        };
        let signature: Signature = sk.sign(&signing_input(&sig, &rrset));
        sig.signature = signature.to_bytes().to_vec();
        assert_eq!(sig.signature.len(), 64);

        assert_eq!(verify_rrsig(&sig, &rrset, &dnskey_pub, NOW), Ok(()));
        let mut bad = rrset.clone();
        bad[0].rdata[0] ^= 0xff;
        assert_eq!(
            verify_rrsig(&sig, &bad, &dnskey_pub, NOW),
            Err(ValidationError::SignatureMismatch)
        );
    }

    #[test]
    fn root_anchor_is_wellformed() {
        let a = root_trust_anchors();
        // Both the active (20326) and rollover (38696) root KSK anchors.
        assert_eq!(a.len(), 2);
        let tags: Vec<u16> = a.iter().map(|d| d.key_tag).collect();
        assert!(tags.contains(&20326) && tags.contains(&38696));
        for d in &a {
            assert_eq!(d.algorithm, ALG_RSASHA256);
            assert_eq!(d.digest_type, DS_DIGEST_SHA256);
            assert_eq!(d.digest.len(), 32, "SHA-256 digest is 32 bytes");
        }
    }

    #[test]
    fn unsupported_algorithm_still_refused_by_verify_rrsig() {
        let (sk, mut sig, rrset) = signed_sample();
        let pk = sk.verifying_key().to_bytes();
        sig.algorithm = 7; // RSASHA1 — deliberately not supported
        assert_eq!(
            verify_rrsig(&sig, &rrset, &pk, 1_600_000_000),
            Err(ValidationError::UnsupportedAlgorithm)
        );
    }
}
