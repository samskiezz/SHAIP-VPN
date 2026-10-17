//! SHAIP-THRESH/1 — threshold Ed25519 signatures (FROST) for the directory
//! authorities.
//!
//! The signed node directory ([`crate::directory`]) is today a list of `k`
//! independent authority signatures that a client verifies against `k` pinned
//! keys. That works, but it means the client pins and checks several keys, and
//! any single authority key, if stolen, is one of the `k`.
//!
//! FROST (Flexible Round-Optimized Schnorr Threshold signatures, RFC 9591) gives
//! a stronger shape for the same trust assumption: `n` authorities each hold a
//! *share* of **one** group key, and any `t` of them can jointly produce a
//! single signature — no single authority ever holds the whole key, and no `t-1`
//! of them can sign. Crucially for interoperability, a FROST(Ed25519, SHA-512)
//! signature is an ordinary RFC 8032 Ed25519 signature: every existing verifier
//! in this codebase (the directory client, `ed25519-dalek`) accepts it against
//! the 32-byte group key, with no new verification code.
//!
//! This module is a self-contained, tested wrapper over the real `frost-ed25519`
//! crate: trusted-dealer key generation, the two-round threshold signing flow,
//! and the group key / signature in the standard 32- and 64-byte encodings. It
//! is the primitive the directory's threshold-signing mode is built on; the
//! control-plane coordinator that runs the rounds across authorities is layered
//! on top.

use frost_ed25519 as frost;
use std::collections::BTreeMap;

/// One authority's secret key material plus the shared group public key package.
/// In production each `KeyPackage` is held by a different authority; the dealer
/// that produced them is used only at setup and then discarded.
pub struct ThresholdKeys {
    /// Per-authority signing key packages, keyed by participant identifier.
    pub shares: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    /// The public key package (the group verifying key + per-share verifying
    /// shares) every signer and verifier needs.
    pub public: frost::keys::PublicKeyPackage,
}

impl ThresholdKeys {
    /// The 32-byte group verifying key — pin this one key in place of the `k`
    /// per-authority keys. It is a standard Ed25519 public key.
    pub fn group_public_key(&self) -> anyhow::Result<[u8; 32]> {
        let bytes = self
            .public
            .verifying_key()
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize group key: {e}"))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("group key is not 32 bytes"))
    }
}

/// Trusted-dealer key generation: split one fresh group key into `max_signers`
/// shares such that any `min_signers` of them can sign. Returns each authority's
/// key package and the shared public package.
///
/// A trusted dealer is the simplest setup and fits an operator bootstrapping its
/// own authorities; a distributed key generation (DKG) that needs no trusted
/// dealer is the `frost::keys::dkg` flow and can replace this without changing
/// the signing or verifying code below.
pub fn generate(min_signers: u16, max_signers: u16) -> anyhow::Result<ThresholdKeys> {
    anyhow::ensure!(
        min_signers >= 1 && min_signers <= max_signers,
        "need 1 <= min_signers <= max_signers (got {min_signers}/{max_signers})"
    );
    // frost re-exports the rand_core it was built against; rand 0.8's OsRng
    // implements that RngCore + CryptoRng.
    let rng = rand::rngs::OsRng;
    let (shares, public) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        frost::keys::IdentifierList::Default,
        rng,
    )
    .map_err(|e| anyhow::anyhow!("frost dealer keygen: {e}"))?;

    let mut key_packages = BTreeMap::new();
    for (id, secret_share) in shares {
        let kp = frost::keys::KeyPackage::try_from(secret_share)
            .map_err(|e| anyhow::anyhow!("build key package: {e}"))?;
        key_packages.insert(id, kp);
    }
    Ok(ThresholdKeys {
        shares: key_packages,
        public,
    })
}

/// Run the full two-round FROST signing with a given `signers` subset (their
/// identifiers) over `message`, returning the 64-byte aggregate Ed25519
/// signature. Fails if fewer than the threshold sign.
///
/// In production the two rounds run across the authorities over authenticated
/// channels; here they are driven locally so the primitive is testable and so a
/// single-host coordinator (holding all shares) can also use it directly.
pub fn sign(
    keys: &ThresholdKeys,
    signers: &[frost::Identifier],
    message: &[u8],
) -> anyhow::Result<[u8; 64]> {
    let mut rng = rand::rngs::OsRng;

    // Round 1: each chosen signer commits (one fresh nonce pair).
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();
    for id in signers {
        let kp = keys
            .shares
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("unknown signer identifier"))?;
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
        nonces_map.insert(*id, nonces);
        commitments_map.insert(*id, commitments);
    }

    // The coordinator binds the message to the collected commitments.
    let signing_package = frost::SigningPackage::new(commitments_map, message);

    // Round 2: each signer produces its signature share.
    let mut signature_shares = BTreeMap::new();
    for id in signers {
        let kp = &keys.shares[id];
        let nonces = &nonces_map[id];
        let share = frost::round2::sign(&signing_package, nonces, kp)
            .map_err(|e| anyhow::anyhow!("round2 sign: {e}"))?;
        signature_shares.insert(*id, share);
    }

    // The coordinator aggregates the shares into one group signature.
    let group_sig = frost::aggregate(&signing_package, &signature_shares, &keys.public)
        .map_err(|e| anyhow::anyhow!("aggregate: {e}"))?;
    let bytes = group_sig
        .serialize()
        .map_err(|e| anyhow::anyhow!("serialize signature: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))
}

/// Verify an aggregate signature with the FROST group verifying key. Equivalent
/// to a standard Ed25519 verification against [`ThresholdKeys::group_public_key`]
/// (see the test), so verifiers need no FROST-specific code.
pub fn verify(group_public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Ok(vk) = VerifyingKey::from_bytes(group_public_key) else {
        return false;
    };
    vk.verify(message, &Signature::from_bytes(signature)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(keys: &ThresholdKeys) -> Vec<frost::Identifier> {
        keys.shares.keys().copied().collect()
    }

    #[test]
    fn threshold_quorum_signs_and_verifies() {
        // 2-of-3 authorities.
        let keys = generate(2, 3).unwrap();
        let gpk = keys.group_public_key().unwrap();
        let msg = b"SHAIP-CONSENSUS-V1 digest ...";

        let all = ids(&keys);
        let quorum = &all[..2]; // any 2 of the 3
        let sig = sign(&keys, quorum, msg).unwrap();

        assert!(verify(&gpk, msg, &sig), "a threshold quorum's signature must verify");
    }

    #[test]
    fn aggregate_is_a_standard_ed25519_signature() {
        // The whole point: no FROST-specific verifier is needed. A plain
        // ed25519-dalek verification against the 32-byte group key accepts it.
        let keys = generate(3, 5).unwrap();
        let gpk = keys.group_public_key().unwrap();
        let msg = b"interop: verifiable by any RFC 8032 Ed25519 verifier";
        let all = ids(&keys);
        let sig = sign(&keys, &all[..3], msg).unwrap();

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&gpk).unwrap();
        assert!(
            vk.verify(msg, &Signature::from_bytes(&sig)).is_ok(),
            "FROST(Ed25519) output must be a valid standard Ed25519 signature"
        );
    }

    #[test]
    fn below_threshold_cannot_sign() {
        let keys = generate(3, 5).unwrap();
        let all = ids(&keys);
        // Only 2 signers for a 3-of-5 group: aggregation must fail.
        let err = sign(&keys, &all[..2], b"not enough signers");
        assert!(err.is_err(), "fewer than the threshold must not produce a signature");
    }

    #[test]
    fn wrong_message_does_not_verify() {
        let keys = generate(2, 2).unwrap();
        let gpk = keys.group_public_key().unwrap();
        let all = ids(&keys);
        let sig = sign(&keys, &all, b"the signed message").unwrap();
        assert!(!verify(&gpk, b"a different message", &sig));
    }

    #[test]
    fn a_different_group_key_rejects() {
        let keys = generate(2, 3).unwrap();
        let other = generate(2, 3).unwrap();
        let msg = b"bound to its own group";
        let sig = sign(&keys, &ids(&keys)[..2], msg).unwrap();
        // The signature must not verify under a different group's key.
        assert!(!verify(&other.group_public_key().unwrap(), msg, &sig));
    }
}
