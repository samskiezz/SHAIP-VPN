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
//! and the group key / signature in the standard 32- and 64-byte encodings.
//!
//! Two ways to drive the signing are provided:
//!   * [`sign`] runs both rounds in one process holding every share — the
//!     single-host convenience, and what the tests exercise the primitive with.
//!   * [`Authority`] + [`Coordinator`] run the protocol as separate parties:
//!     each authority holds only its own share and its own single-use nonces, and
//!     the coordinator holds no secret material at all, so it can run on an
//!     untrusted host. This is the trustless multi-party flow a real authority
//!     set uses.
//!
//! Setup comes two ways: [`generate`] (a trusted dealer, simplest for an operator
//! bootstrapping its own authorities) or [`generate_dkg`] (distributed key
//! generation — no party ever holds the whole group secret, not even at setup).
//! Both yield the same [`ThresholdKeys`], and the signing and verifying code is
//! identical either way.
//!
//! What remains is deployment, not cryptography: standing up each [`Authority`]
//! behind an authenticated channel and running the [`Coordinator`] against the
//! live authority set. Verifiers already need nothing new — the aggregate is an
//! ordinary RFC 8032 Ed25519 signature under the pinned group key.

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

/// Dealer-free setup via distributed key generation (DKG): no party — not even a
/// setup dealer — ever holds the whole group secret. Each party contributes to
/// the group key, which exists only as the combination of all contributions.
///
/// This drives all `max_signers` parties' three DKG rounds locally (as [`sign`]
/// drives signing locally), which fits a single operator bootstrapping its own
/// authorities and keeps it testable. In a real deployment the three rounds run
/// across the authorities over authenticated channels (round 2's per-recipient
/// packages over confidential ones); each party's resulting
/// [`frost::keys::KeyPackage`] is identical to what this produces. The output is
/// an ordinary [`ThresholdKeys`] — it signs via [`ThresholdKeys::into_parties`]
/// and verifies exactly like a dealt key, with no change to the signing or
/// verifying code. Requires `min_signers >= 2` (a 1-of-n DKG is degenerate).
pub fn generate_dkg(min_signers: u16, max_signers: u16) -> anyhow::Result<ThresholdKeys> {
    anyhow::ensure!(
        min_signers >= 2 && min_signers <= max_signers,
        "DKG needs 2 <= min_signers <= max_signers (got {min_signers}/{max_signers})"
    );
    // OsRng is a zero-sized, Copy, stateless handle to the OS CSPRNG, so each
    // `part1` call takes its own copy.
    let rng = rand::rngs::OsRng;

    let ids: Vec<frost::Identifier> = (1..=max_signers)
        .map(|i| frost::Identifier::try_from(i).map_err(|e| anyhow::anyhow!("identifier {i}: {e}")))
        .collect::<anyhow::Result<_>>()?;

    // Round 1: each party keeps a secret package and broadcasts a public one.
    let mut r1_secret: BTreeMap<frost::Identifier, frost::keys::dkg::round1::SecretPackage> =
        BTreeMap::new();
    let mut r1_public: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::new();
    for id in &ids {
        let (sp, pp) = frost::keys::dkg::part1(*id, max_signers, min_signers, rng)
            .map_err(|e| anyhow::anyhow!("dkg part1: {e}"))?;
        r1_secret.insert(*id, sp);
        r1_public.insert(*id, pp);
    }

    // Round 2: each party processes everyone else's round-1 package, keeping a
    // secret package and emitting one round-2 package addressed to each other
    // party. `incoming[recipient][sender]` collects the packages a party receives.
    let mut r2_secret: BTreeMap<frost::Identifier, frost::keys::dkg::round2::SecretPackage> =
        BTreeMap::new();
    let mut incoming: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    > = BTreeMap::new();
    for id in &ids {
        let others: BTreeMap<_, _> = r1_public
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let sp = r1_secret
            .remove(id)
            .ok_or_else(|| anyhow::anyhow!("missing round-1 secret"))?;
        let (r2sp, outgoing) =
            frost::keys::dkg::part2(sp, &others).map_err(|e| anyhow::anyhow!("dkg part2: {e}"))?;
        r2_secret.insert(*id, r2sp);
        for (recipient, pkg) in outgoing {
            incoming.entry(recipient).or_default().insert(*id, pkg);
        }
    }

    // Round 3: each party combines its received packages into its key package and
    // the shared public package. Every party must derive the same public package.
    let mut key_packages = BTreeMap::new();
    let mut group_public: Option<(frost::keys::PublicKeyPackage, Vec<u8>)> = None;
    for id in &ids {
        let others_r1: BTreeMap<_, _> = r1_public
            .iter()
            .filter(|(k, _)| *k != id)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let my_r2 = incoming.remove(id).unwrap_or_default();
        let (kp, pp) = frost::keys::dkg::part3(&r2_secret[id], &others_r1, &my_r2)
            .map_err(|e| anyhow::anyhow!("dkg part3: {e}"))?;
        key_packages.insert(*id, kp);
        let pp_bytes = pp
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize public package: {e}"))?;
        match &group_public {
            None => group_public = Some((pp, pp_bytes)),
            Some((_, existing)) => anyhow::ensure!(
                *existing == pp_bytes,
                "DKG parties disagree on the group public key"
            ),
        }
    }

    Ok(ThresholdKeys {
        shares: key_packages,
        public: group_public
            .ok_or_else(|| anyhow::anyhow!("no parties"))?
            .0,
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

// ---------------------------------------------------------------------------
// Multi-party signing: the authorities each hold ONE share, the coordinator
// holds NONE.
//
// [`sign`] above drives both rounds in one process holding every share — handy
// for a single-host operator and for tests, but not how a real authority set is
// meant to run. In deployment each authority is a separate party that holds only
// its own secret share and its own secret nonces, and a coordinator (which may
// run on an untrusted host) orchestrates the two rounds and aggregates the
// public shares. No secret key material and no signing nonce ever reaches the
// coordinator, and no `t-1` authorities can sign.
//
// The one sharp edge of threshold Schnorr is nonce reuse: signing twice with the
// same round-1 nonces leaks the secret share. [`Authority`] therefore keeps each
// session's nonces internally and consumes them on use, so a nonce is signed
// with at most once (a second round-2 for the same session is refused).
// ---------------------------------------------------------------------------

/// One directory authority. Holds exactly its own secret share — never the group
/// secret, never another authority's share — plus, between rounds, the secret
/// nonces it committed to. A [`Coordinator`] only ever sees this authority's
/// public commitment and public signature share.
pub struct Authority {
    id: frost::Identifier,
    key_package: frost::keys::KeyPackage,
    /// Per-session single-use nonces: produced in [`Authority::commit`],
    /// consumed in [`Authority::sign`]. Keyed by the caller's session id so an
    /// authority can take part in several independent signings at once.
    pending: BTreeMap<u64, frost::round1::SigningNonces>,
}

impl Authority {
    /// Wrap one authority's key package. In production this package is delivered
    /// to the authority at setup (e.g. from [`ThresholdKeys::into_parties`]) and
    /// the dealer's copy is destroyed.
    pub fn new(id: frost::Identifier, key_package: frost::keys::KeyPackage) -> Self {
        Self {
            id,
            key_package,
            pending: BTreeMap::new(),
        }
    }

    /// This authority's identifier, as it appears in the coordinator's maps.
    pub fn id(&self) -> frost::Identifier {
        self.id
    }

    /// Round 1. Produce this authority's public commitment for `session`; the
    /// matching secret nonces are retained internally for [`Authority::sign`] and
    /// never leave the authority. Committing again for a session that still has
    /// pending nonces replaces them (abandoning that earlier attempt) — it is a
    /// fresh nonce, never a reuse.
    pub fn commit(&mut self, session: u64) -> frost::round1::SigningCommitments {
        let mut rng = rand::rngs::OsRng;
        let (nonces, commitments) =
            frost::round1::commit(self.key_package.signing_share(), &mut rng);
        self.pending.insert(session, nonces);
        commitments
    }

    /// Round 2. Sign `signing_package` with the nonces committed for `session`.
    /// The nonces are consumed here: a second call for the same session fails, so
    /// a given nonce is used in at most one signature (reuse would leak the
    /// secret share). Fails if no round-1 commitment was made for this session.
    pub fn sign(
        &mut self,
        session: u64,
        signing_package: &frost::SigningPackage,
    ) -> anyhow::Result<frost::round2::SignatureShare> {
        // Remove, not borrow: the nonces are spent by this call whether it
        // succeeds or fails, so they can never be signed with twice.
        let nonces = self
            .pending
            .remove(&session)
            .ok_or_else(|| anyhow::anyhow!("no round-1 commitment for this session (or already signed)"))?;
        frost::round2::sign(signing_package, &nonces, &self.key_package)
            .map_err(|e| anyhow::anyhow!("round2 sign: {e}"))
    }
}

/// The signing coordinator. Holds only the public key package — no secret share
/// and no nonce — so it can run on an untrusted host: the worst a dishonest
/// coordinator can do is refuse to produce a signature, never forge one. It
/// binds the message to the quorum's commitments and aggregates their shares.
pub struct Coordinator {
    public: frost::keys::PublicKeyPackage,
}

impl Coordinator {
    /// A coordinator over `public` — the same public package every authority and
    /// verifier holds.
    pub fn new(public: frost::keys::PublicKeyPackage) -> Self {
        Self { public }
    }

    /// The 32-byte group verifying key clients pin (a standard Ed25519 key).
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

    /// Bind `message` to the quorum's round-1 commitments, producing the signing
    /// package every participating authority then signs in round 2.
    pub fn signing_package(
        commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
        message: &[u8],
    ) -> frost::SigningPackage {
        frost::SigningPackage::new(commitments, message)
    }

    /// Aggregate the quorum's round-2 shares into one 64-byte Ed25519 signature.
    /// Fails if fewer than the threshold signed, or if any share does not match
    /// its commitment — a dishonest or corrupt share cannot be folded in
    /// unnoticed.
    pub fn aggregate(
        &self,
        signing_package: &frost::SigningPackage,
        shares: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    ) -> anyhow::Result<[u8; 64]> {
        let group_sig = frost::aggregate(signing_package, shares, &self.public)
            .map_err(|e| anyhow::anyhow!("aggregate: {e}"))?;
        let bytes = group_sig
            .serialize()
            .map_err(|e| anyhow::anyhow!("serialize signature: {e}"))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature is not 64 bytes"))
    }
}

impl ThresholdKeys {
    /// Split a freshly dealt key set into the parties that run the protocol: one
    /// [`Authority`] per share (each holding only its own), and a [`Coordinator`]
    /// holding only the public package. After this the caller should drop any
    /// other copy of the shares — the dealer exists only at setup.
    pub fn into_parties(self) -> (Vec<Authority>, Coordinator) {
        let authorities = self
            .shares
            .into_iter()
            .map(|(id, kp)| Authority::new(id, kp))
            .collect();
        (authorities, Coordinator::new(self.public))
    }
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

    // --- multi-party coordinator (authorities hold one share each) -----------

    /// Drive the full two-round protocol across separate [`Authority`] parties
    /// via a [`Coordinator`] that never touches a secret, and confirm the result
    /// is an ordinary Ed25519 signature under the pinned group key.
    #[test]
    fn multi_party_quorum_signs_and_verifies() {
        let keys = generate(3, 5).unwrap();
        let gpk = keys.group_public_key().unwrap();
        let (mut authorities, coord) = keys.into_parties();
        assert_eq!(coord.group_public_key().unwrap(), gpk);

        let msg = b"SHAIP-CONSENSUS-V1 digest over the signed node directory";
        let session = 42u64;
        // Any 3 of the 5 authorities — a non-contiguous subset on purpose.
        let quorum = [0usize, 2, 4];

        // Round 1: each participating authority commits; only the public
        // commitment is handed to the coordinator.
        let mut commitments = BTreeMap::new();
        for &i in &quorum {
            let a = &mut authorities[i];
            commitments.insert(a.id(), a.commit(session));
        }

        // The coordinator binds the message to those commitments.
        let pkg = Coordinator::signing_package(commitments, msg);

        // Round 2: each authority signs; only the public share is handed back.
        let mut shares = BTreeMap::new();
        for &i in &quorum {
            let a = &mut authorities[i];
            shares.insert(a.id(), a.sign(session, &pkg).unwrap());
        }

        let sig = coord.aggregate(&pkg, &shares).unwrap();
        assert!(verify(&gpk, msg, &sig), "a cross-authority quorum must produce a valid signature");
    }

    /// Nonce reuse leaks the secret share in Schnorr threshold signing, so an
    /// authority must sign with a given round-1 nonce at most once.
    #[test]
    fn a_nonce_is_consumed_and_cannot_be_reused() {
        let keys = generate(2, 3).unwrap();
        let (mut authorities, _coord) = keys.into_parties();
        let session = 7u64;

        let c0 = authorities[0].commit(session);
        let c1 = authorities[1].commit(session);
        let mut commitments = BTreeMap::new();
        commitments.insert(authorities[0].id(), c0);
        commitments.insert(authorities[1].id(), c1);
        let pkg = Coordinator::signing_package(commitments, b"once");

        // First round-2 for this session succeeds...
        assert!(authorities[0].sign(session, &pkg).is_ok());
        // ...a second must be refused: the nonce was consumed.
        assert!(
            authorities[0].sign(session, &pkg).is_err(),
            "a round-1 nonce must never be signed with twice"
        );
    }

    /// Signing round 2 without having committed in round 1 for that session must
    /// fail rather than reach for some other session's nonce.
    #[test]
    fn signing_without_committing_fails() {
        let keys = generate(2, 2).unwrap();
        let (mut authorities, _coord) = keys.into_parties();
        // Build a well-formed package from a real round 1 so only the missing
        // commitment on authority 0 is under test.
        let c0 = authorities[0].commit(1);
        let c1 = authorities[1].commit(1);
        let mut commitments = BTreeMap::new();
        commitments.insert(authorities[0].id(), c0);
        commitments.insert(authorities[1].id(), c1);
        let pkg = Coordinator::signing_package(commitments, b"m");
        // Session 999 was never committed on this authority.
        assert!(authorities[0].sign(999, &pkg).is_err());
    }

    /// Below the threshold, the coordinator must not be able to produce a valid
    /// signature — whether `frost` errors or returns bytes that fail to verify.
    #[test]
    fn coordinator_below_threshold_yields_no_valid_signature() {
        let keys = generate(3, 5).unwrap();
        let gpk = keys.group_public_key().unwrap();
        let (mut authorities, coord) = keys.into_parties();
        let msg = b"only two of three";
        let session = 1u64;
        let quorum = [0usize, 1]; // 2 of the required 3

        let mut commitments = BTreeMap::new();
        for &i in &quorum {
            commitments.insert(authorities[i].id(), authorities[i].commit(session));
        }
        let pkg = Coordinator::signing_package(commitments, msg);
        // A sub-threshold quorum may already be refused at round 2; if it is,
        // the property holds (no signature is produced). Otherwise, prove the
        // aggregate it does produce is not a valid signature under the group key.
        let mut shares = BTreeMap::new();
        let mut all_signed = true;
        for &i in &quorum {
            match authorities[i].sign(session, &pkg) {
                Ok(share) => {
                    shares.insert(authorities[i].id(), share);
                }
                Err(_) => {
                    all_signed = false;
                    break;
                }
            }
        }
        let produced_valid = all_signed
            && matches!(coord.aggregate(&pkg, &shares), Ok(sig) if verify(&gpk, msg, &sig));
        assert!(!produced_valid, "a sub-threshold quorum must not yield a valid signature");
    }

    /// Dealer-free setup: keys produced by DKG (no party ever holds the whole
    /// secret) must sign through the same multi-party coordinator and verify as a
    /// standard Ed25519 signature — proving the trusted dealer can be dropped
    /// without touching the signing or verifying code.
    #[test]
    fn dkg_keys_sign_through_the_coordinator_and_verify() {
        let keys = generate_dkg(2, 3).unwrap();
        let gpk = keys.group_public_key().unwrap();
        // A real Ed25519 public key.
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&gpk).is_ok());

        let (mut authorities, coord) = keys.into_parties();
        let msg = b"produced by DKG, no trusted dealer";
        let session = 1u64;
        let quorum = [0usize, 2];

        let mut commitments = BTreeMap::new();
        for &i in &quorum {
            commitments.insert(authorities[i].id(), authorities[i].commit(session));
        }
        let pkg = Coordinator::signing_package(commitments, msg);
        let mut shares = BTreeMap::new();
        for &i in &quorum {
            shares.insert(authorities[i].id(), authorities[i].sign(session, &pkg).unwrap());
        }
        let sig = coord.aggregate(&pkg, &shares).unwrap();
        assert!(verify(&gpk, msg, &sig), "DKG-produced keys must sign and verify");
    }

    /// A 1-of-n DKG is degenerate and must be refused.
    #[test]
    fn dkg_rejects_degenerate_threshold() {
        assert!(generate_dkg(1, 3).is_err());
    }
}
