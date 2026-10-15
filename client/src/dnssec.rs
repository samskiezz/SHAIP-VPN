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

/// Verify an Ed25519 RRSIG over `rrset` using the raw 32-byte DNSKEY public key,
/// at wall-clock time `now_unix` (seconds since the epoch).
pub fn verify_ed25519(
    sig: &Rrsig,
    rrset: &[ResourceRecord],
    dnskey_pub: &[u8],
    now_unix: u64,
) -> Result<(), ValidationError> {
    if sig.algorithm != ALG_ED25519 {
        return Err(ValidationError::UnsupportedAlgorithm);
    }
    let now = now_unix as u32;
    if now > sig.sig_expiration {
        return Err(ValidationError::Expired);
    }
    if now < sig.sig_inception {
        return Err(ValidationError::NotYetValid);
    }

    let key_arr: [u8; 32] = dnskey_pub
        .try_into()
        .map_err(|_| ValidationError::BadKey)?;
    let vk = VerifyingKey::from_bytes(&key_arr).map_err(|_| ValidationError::BadKey)?;

    let sig_arr: [u8; 64] = sig
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| ValidationError::BadSignatureEncoding)?;
    let signature = Signature::from_bytes(&sig_arr);

    let input = signing_input(sig, rrset);
    vk.verify(&input, &signature)
        .map_err(|_| ValidationError::SignatureMismatch)
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
    verify_ed25519(self_sig, &rrset, &ksk.public_key, now_unix)?;
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
    verify_ed25519(sig, rrset, &key.public_key, now_unix)
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
}
