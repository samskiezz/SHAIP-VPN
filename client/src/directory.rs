//! Client-side directory consensus verification.
//!
//! The control plane's authorities publish a signed, plain-text list of the
//! active nodes (see `control-plane/directory/directory.go`). This module
//! parses that document and verifies it: at least `threshold` of the pinned
//! authorities must have signed the exact canonical bytes with Ed25519. A
//! document that is expired, not yet valid, or short of the threshold — or that
//! carries a single bad signature — is rejected, so path selection only ever
//! consumes a node list a quorum of authorities agreed on.
//!
//! The canonical form and digest are defined so that a signature produced by
//! the Go authority verifies here unchanged; the `cross_language_vector` test
//! checks a document, digest, and signature produced by the Go side.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Required first line of every consensus document.
pub const FORMAT_VERSION: &str = "SHAIP-CONSENSUS-V1";

/// Why a consensus document was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum DirError {
    BadFormat(String),
    NotYetValid,
    Expired,
    UnknownAuthority(String),
    BadSignature(String),
    BelowThreshold { valid: usize, needed: usize },
}

impl std::fmt::Display for DirError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirError::BadFormat(s) => write!(f, "malformed consensus: {s}"),
            DirError::NotYetValid => write!(f, "consensus not yet valid"),
            DirError::Expired => write!(f, "consensus expired"),
            DirError::UnknownAuthority(a) => write!(f, "authority {a} not in pinned registry"),
            DirError::BadSignature(a) => write!(f, "signature from {a} is invalid"),
            DirError::BelowThreshold { valid, needed } => {
                write!(f, "only {valid} valid signatures, need {needed}")
            }
        }
    }
}

impl std::error::Error for DirError {}

/// An authority as listed in the document (its pinned key is supplied
/// separately, via the registry passed to [`verify`]).
#[derive(Clone, Debug)]
pub struct DirAuthority {
    pub name: String,
    pub key_tag: u16,
}

/// One node in the consensus.
#[derive(Clone, Debug)]
pub struct DirNode {
    pub name: String,
    pub address: String,
    pub role: String,
    pub x25519_hex: String,
    pub ed25519_hex: String,
    pub capacity_mbps: u32,
    pub region: String,
}

/// A parsed consensus document with the digest the authorities signed.
#[derive(Clone, Debug)]
pub struct Consensus {
    /// RFC 3339 UTC timestamp (canonical `...Z` form).
    pub published: String,
    pub valid_until: String,
    pub threshold: usize,
    pub authorities: Vec<DirAuthority>,
    pub nodes: Vec<DirNode>,
    pub signatures: BTreeMap<String, Vec<u8>>,
    /// SHA-256 of the canonical bytes (everything before the signature block).
    pub digest: [u8; 32],
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Parse a wire consensus document. Computes the digest over the canonical
/// prefix (the bytes before the first signature line) exactly as the signer
/// did. Does **not** verify signatures — call [`verify`].
pub fn parse(data: &[u8]) -> Result<Consensus, DirError> {
    // The digest covers everything up to (and including) the blank line that
    // ends the last node, i.e. everything before the first "signature " line.
    let sig_start = find_subslice(data, b"\nsignature ")
        .map(|p| p + 1)
        .unwrap_or(data.len());
    let digest: [u8; 32] = Sha256::digest(&data[..sig_start]).into();

    let text = std::str::from_utf8(data).map_err(|_| DirError::BadFormat("non-utf8".into()))?;

    let mut c = Consensus {
        published: String::new(),
        valid_until: String::new(),
        threshold: 0,
        authorities: Vec::new(),
        nodes: Vec::new(),
        signatures: BTreeMap::new(),
        digest,
    };

    let mut in_sig = false;
    let mut current: Option<usize> = None;

    for (idx, raw) in text.split('\n').enumerate() {
        let line = raw.trim_end_matches(['\r', ' ', '\t']);
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("signature ") {
            in_sig = true;
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() != 2 {
                return Err(DirError::BadFormat(format!("line {}: bad signature", idx + 1)));
            }
            let sig = hex::decode(parts[1])
                .map_err(|_| DirError::BadFormat(format!("line {}: bad signature hex", idx + 1)))?;
            c.signatures.insert(parts[0].to_string(), sig);
            continue;
        }
        if in_sig {
            return Err(DirError::BadFormat(format!(
                "line {}: content after signature block",
                idx + 1
            )));
        }
        if idx == 0 {
            if line != FORMAT_VERSION {
                return Err(DirError::BadFormat(format!("bad version line: {line:?}")));
            }
            continue;
        }
        if raw.starts_with("    ") {
            let node = current
                .and_then(|i| c.nodes.get_mut(i))
                .ok_or_else(|| DirError::BadFormat(format!("line {}: field outside node", idx + 1)))?;
            apply_node_field(node, line)
                .map_err(|e| DirError::BadFormat(format!("line {}: {e}", idx + 1)))?;
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        current = None;
        match parts[0] {
            "published" | "valid-until" => {
                let ts = parts
                    .get(1)
                    .ok_or_else(|| DirError::BadFormat(format!("line {}: missing time", idx + 1)))?;
                if parts[0] == "published" {
                    c.published = ts.to_string();
                } else {
                    c.valid_until = ts.to_string();
                }
            }
            "threshold" => {
                let k = parts
                    .get(1)
                    .and_then(|s| s.split('/').next())
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| DirError::BadFormat(format!("line {}: bad threshold", idx + 1)))?;
                c.threshold = k;
            }
            "authorities" => {}
            "authority-name" => {
                if parts.len() < 4 {
                    return Err(DirError::BadFormat(format!("line {}: short authority", idx + 1)));
                }
                let tag = u16::from_str_radix(parts[3].trim_start_matches("0x"), 16)
                    .map_err(|_| DirError::BadFormat(format!("line {}: bad key-tag", idx + 1)))?;
                c.authorities.push(DirAuthority {
                    name: parts[1].to_string(),
                    key_tag: tag,
                });
            }
            "node" => {
                if parts.len() < 6 {
                    return Err(DirError::BadFormat(format!("line {}: short node", idx + 1)));
                }
                c.nodes.push(DirNode {
                    name: parts[1].to_string(),
                    address: parts[3].to_string(),
                    role: parts[5].to_string(),
                    x25519_hex: String::new(),
                    ed25519_hex: String::new(),
                    capacity_mbps: 0,
                    region: String::new(),
                });
                current = Some(c.nodes.len() - 1);
            }
            other => {
                return Err(DirError::BadFormat(format!(
                    "line {}: unknown directive {other:?}",
                    idx + 1
                )));
            }
        }
    }
    Ok(c)
}

fn apply_node_field(node: &mut DirNode, line: &str) -> Result<(), String> {
    let mut it = line.split_whitespace();
    let key = it.next().ok_or("empty field")?;
    let val = it.collect::<Vec<_>>().join(" ");
    match key {
        "x25519" => node.x25519_hex = val,
        "ed25519" => node.ed25519_hex = val,
        "capacity-mbps" => {
            node.capacity_mbps = val.parse().map_err(|_| "bad capacity-mbps".to_string())?
        }
        "region" => node.region = val,
        other => return Err(format!("unknown node field {other:?}")),
    }
    Ok(())
}

/// Verify a parsed consensus against a pinned registry of authority keys at
/// wall-clock time `now_rfc3339` (a canonical `...Z` UTC timestamp). Returns the
/// number of valid signatures on success. Timestamps are compared
/// lexicographically, which is exact for canonical RFC 3339 UTC strings.
pub fn verify(
    c: &Consensus,
    registry: &BTreeMap<String, VerifyingKey>,
    now_rfc3339: &str,
) -> Result<usize, DirError> {
    if !c.published.is_empty() && now_rfc3339 < c.published.as_str() {
        return Err(DirError::NotYetValid);
    }
    if !c.valid_until.is_empty() && now_rfc3339 > c.valid_until.as_str() {
        return Err(DirError::Expired);
    }
    let mut valid = 0usize;
    for a in &c.authorities {
        let Some(sig_bytes) = c.signatures.get(&a.name) else {
            continue;
        };
        let vk = registry
            .get(&a.name)
            .ok_or_else(|| DirError::UnknownAuthority(a.name.clone()))?;
        let sig =
            Signature::from_slice(sig_bytes).map_err(|_| DirError::BadSignature(a.name.clone()))?;
        vk.verify(&c.digest, &sig)
            .map_err(|_| DirError::BadSignature(a.name.clone()))?;
        valid += 1;
    }
    if valid < c.threshold {
        return Err(DirError::BelowThreshold {
            valid,
            needed: c.threshold,
        });
    }
    Ok(valid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exact document, pubkey, digest, and signature emitted by the Go
    // authority's TestCrossLanguageVector. If the canonical form ever changes,
    // the Go test's logged values and this block change together.
    const VECTOR_DOC: &str = concat!(
        "SHAIP-CONSENSUS-V1\n",
        "published 2026-01-15T00:00:00Z\n",
        "valid-until 2026-01-15T01:00:00Z\n",
        "threshold 1/1\n",
        "authorities 1\n",
        "authority-name Zurich-01 key-tag 0x7c4a\n",
        "\n",
        "node zrh-01-mix addr 203.0.113.5:8443 role mix\n",
        "    x25519 3a7f0000000000000000000000000000000000000000000000000000000000ff\n",
        "    ed25519 1f2e0000000000000000000000000000000000000000000000000000000000aa\n",
        "    capacity-mbps 500\n",
        "    region CH\n",
        "\n",
        "signature Zurich-01 dfea6f103ce2568fcf0aff2215b0b9309463972884d9adbc689d3a20f40364eda885988d9a59f79d9032f3f084772667d2a4f45e4c99fdb088975cd86e473704\n",
    );
    const VECTOR_PUBKEY: &str =
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const VECTOR_DIGEST: &str =
        "6b7795b230888e360ac63309b4d963da3f46b61f16904646f1b9779f0beaa39f";

    fn vector_registry() -> BTreeMap<String, VerifyingKey> {
        let pk: [u8; 32] = hex::decode(VECTOR_PUBKEY).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk).unwrap();
        let mut reg = BTreeMap::new();
        reg.insert("Zurich-01".to_string(), vk);
        reg
    }

    #[test]
    fn parses_fields() {
        let c = parse(VECTOR_DOC.as_bytes()).unwrap();
        assert_eq!(c.published, "2026-01-15T00:00:00Z");
        assert_eq!(c.threshold, 1);
        assert_eq!(c.authorities.len(), 1);
        assert_eq!(c.authorities[0].key_tag, 0x7c4a);
        assert_eq!(c.nodes.len(), 1);
        assert_eq!(c.nodes[0].name, "zrh-01-mix");
        assert_eq!(c.nodes[0].address, "203.0.113.5:8443");
        assert_eq!(c.nodes[0].capacity_mbps, 500);
        assert_eq!(c.nodes[0].region, "CH");
        assert_eq!(c.signatures.len(), 1);
    }

    #[test]
    fn cross_language_digest_matches_go() {
        // Rust hashes the received canonical prefix and must get the exact
        // digest the Go authority computed and signed.
        let c = parse(VECTOR_DOC.as_bytes()).unwrap();
        assert_eq!(hex::encode(c.digest), VECTOR_DIGEST);
    }

    #[test]
    fn cross_language_signature_verifies() {
        // The Ed25519 signature produced by Go verifies here unchanged.
        let c = parse(VECTOR_DOC.as_bytes()).unwrap();
        let reg = vector_registry();
        assert_eq!(verify(&c, &reg, "2026-01-15T00:30:00Z"), Ok(1));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let mut c = parse(VECTOR_DOC.as_bytes()).unwrap();
        c.signatures.get_mut("Zurich-01").unwrap()[0] ^= 0xff;
        let reg = vector_registry();
        assert_eq!(
            verify(&c, &reg, "2026-01-15T00:30:00Z"),
            Err(DirError::BadSignature("Zurich-01".into()))
        );
    }

    #[test]
    fn tampered_body_breaks_the_digest_and_fails() {
        // Change a node field in the wire bytes: the recomputed digest no longer
        // matches what was signed, so the (unchanged) signature fails.
        let doc = VECTOR_DOC.replace("capacity-mbps 500", "capacity-mbps 999");
        let c = parse(doc.as_bytes()).unwrap();
        assert_ne!(hex::encode(c.digest), VECTOR_DIGEST);
        let reg = vector_registry();
        assert!(matches!(
            verify(&c, &reg, "2026-01-15T00:30:00Z"),
            Err(DirError::BadSignature(_))
        ));
    }

    #[test]
    fn expiry_and_not_yet_valid() {
        let c = parse(VECTOR_DOC.as_bytes()).unwrap();
        let reg = vector_registry();
        assert_eq!(verify(&c, &reg, "2026-01-15T02:00:00Z"), Err(DirError::Expired));
        assert_eq!(
            verify(&c, &reg, "2026-01-14T23:00:00Z"),
            Err(DirError::NotYetValid)
        );
    }

    #[test]
    fn below_threshold_without_enough_signatures() {
        // Same document but require 2 signatures.
        let mut c = parse(VECTOR_DOC.as_bytes()).unwrap();
        c.threshold = 2;
        let reg = vector_registry();
        assert_eq!(
            verify(&c, &reg, "2026-01-15T00:30:00Z"),
            Err(DirError::BelowThreshold { valid: 1, needed: 2 })
        );
    }

    #[test]
    fn unknown_authority_in_registry_is_an_error() {
        let c = parse(VECTOR_DOC.as_bytes()).unwrap();
        let empty = BTreeMap::new();
        assert_eq!(
            verify(&c, &empty, "2026-01-15T00:30:00Z"),
            Err(DirError::UnknownAuthority("Zurich-01".into()))
        );
    }
}
