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
}
