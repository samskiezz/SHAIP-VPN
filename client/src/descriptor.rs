//! Node descriptors (§ staking): the statement a node signs about itself each
//! epoch — its address and keys — and the signer `shaipd --sign-descriptor`
//! uses.
//!
//! A node publishes **one** descriptor per epoch. Two different descriptors for
//! the same epoch, both signed by the node's key, prove equivocation (showing
//! different keys or addresses to different clients), and anyone can submit
//! them to the control plane to have the node's stake slashed. The format
//! matches `control-plane/staking` byte-for-byte; the `cross_language_vector`
//! test reproduces the Go signer's output exactly.

use crate::handshake::Identity;
use anyhow::{bail, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};

/// Wire label of a descriptor.
pub const LABEL: &str = "PQD1";
const MAGIC: &[u8] = b"SHAIP-NODEDESC-V1";
const VERSION: u8 = 1;

/// What a node asserts about itself for one epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeDescriptor {
    /// The control plane's id for the node.
    pub node_id: String,
    pub epoch: u64,
    /// The address the node advertises.
    pub address: String,
    /// Mix onion key (zero if none).
    pub x25519: [u8; 32],
    /// The node key that signs the descriptor.
    pub ed25519: [u8; 32],
    pub capacity_mbps: u32,
    pub region: String,
}

fn put_lp(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    if b.len() > 255 {
        bail!("descriptor field too long");
    }
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

/// The bytes every descriptor body begins with — the domain separation the
/// identity checks before it will sign one.
pub(crate) fn body_prefix() -> Vec<u8> {
    let mut p = Vec::new();
    put_lp(&mut p, MAGIC).expect("short magic");
    p
}

impl NodeDescriptor {
    /// The signed body: deterministic and length-prefixed, beginning with the
    /// domain magic so it can never coincide with a handshake transcript or an
    /// enrollment proof signed by the same key.
    pub fn body(&self) -> Result<Vec<u8>> {
        let mut b = body_prefix();
        b.push(VERSION);
        put_lp(&mut b, self.node_id.as_bytes())?;
        b.extend_from_slice(&self.epoch.to_be_bytes());
        put_lp(&mut b, self.address.as_bytes())?;
        b.extend_from_slice(&self.x25519);
        b.extend_from_slice(&self.ed25519);
        b.extend_from_slice(&self.capacity_mbps.to_be_bytes());
        put_lp(&mut b, self.region.as_bytes())?;
        Ok(b)
    }
}

/// Sign a descriptor with the node's identity. The descriptor must name that
/// identity's Ed25519 key.
pub fn sign(identity: &Identity, d: &NodeDescriptor) -> Result<String> {
    if d.ed25519 != identity.public().ed_bytes() {
        bail!("the descriptor must name this identity's Ed25519 key");
    }
    let body = d.body()?;
    let sig = identity.sign_node_descriptor(&body)?;
    Ok(format!("{LABEL}.{}.{}", B64URL.encode(&body), B64URL.encode(sig)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exact descriptor the Go signer emits in control-plane/staking's
    // TestCrossLanguageVector (node key seed 0x44). If the format changes, both
    // sides change together.
    const GO_VECTOR: &str = "PQD1.ABJQUUFOT04tTk9ERURFU0MtVjEBAAZub2RlLTEAAAAAAAAAKgAPMjAzLjAuMTEzLjU6NDQzOgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADXWXk7vBOigZqCfHattvuopJruAH9J8tCZLZm4Ja0sSAAAAfQAAkNI.yNrgY1dGhx-779bAnCe6Q4Ne5n6Hi8JKBOJyEemndSjDg9qbxCny_VfGhBEJOdWzG65bF7HmYHIHiVvkvkH_Cg";

    fn vector_descriptor(id: &Identity) -> NodeDescriptor {
        let mut x = [0u8; 32];
        x[0] = 0x3a;
        NodeDescriptor {
            node_id: "node-1".into(),
            epoch: 42,
            address: "203.0.113.5:443".into(),
            x25519: x,
            ed25519: id.public().ed_bytes(),
            capacity_mbps: 500,
            region: "CH".into(),
        }
    }

    #[test]
    fn cross_language_vector() {
        let id = Identity::with_ed_seed_for_test([0x44; 32]);
        assert_eq!(sign(&id, &vector_descriptor(&id)).unwrap(), GO_VECTOR);
    }

    #[test]
    fn refuses_a_descriptor_naming_another_key() {
        let id = Identity::generate();
        let mut d = vector_descriptor(&id);
        d.ed25519 = Identity::generate().public().ed_bytes();
        assert!(sign(&id, &d).is_err());
    }

    #[test]
    fn identity_signs_only_descriptor_bodies() {
        // The narrow signing API refuses anything without the descriptor's
        // domain prefix, so it cannot be turned into a general-purpose oracle.
        let id = Identity::generate();
        assert!(id.sign_node_descriptor(b"\x00\x00\x04\xa0 a transcript").is_err());
        assert!(id.sign_node_descriptor(b"SHAIP-ENROLL-CLAIM-V1:x").is_err());
        assert!(id.sign_node_descriptor(&body_prefix()).is_ok());
    }
}
