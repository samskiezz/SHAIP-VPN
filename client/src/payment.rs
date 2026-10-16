//! Client side of the untraceable payment flow (§20).
//!
//! The buyer never identifies themselves. To get access they:
//!   1. fetch the mint's denominations (plans + RSA public keys),
//!   2. generate random token nonces and **blind** them,
//!   3. open an order and pay the quoted Monero to its one-time subaddress,
//!   4. once the payment confirms, **collect** the mint's blind signatures,
//!   5. **unblind** them into ordinary RSA signatures over their nonces, and
//!   6. later **redeem** a token (nonce + signature) for a VPN session.
//!
//! Because the mint only ever saw the blinded nonces, the tokens it signed can't
//! be linked back to the payment — the defining property of Chaumian e-cash.
//! Crypto is RFC 9474 RSA Blind Signatures (RSABSSA-SHA384-PSS-Deterministic) via
//! the `blind-rsa-signatures` crate, matched to the server's Cloudflare CIRCL.

use anyhow::{anyhow, Result};
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng,
    PublicKeySha384PSSDeterministic as BlindPublicKey, Secret, Signature,
};

/// 32 bytes of CSPRNG — a token's secret nonce. High entropy, so the
/// deterministic blind-RSA variant needs no message randomizer.
pub fn new_nonce() -> [u8; 32] {
    use rand::RngCore;
    let mut n = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

/// Load a denomination public key from the mint's SPKI PEM.
pub fn load_pubkey(pem: &str) -> Result<BlindPublicKey> {
    BlindPublicKey::from_pem(pem).map_err(|e| anyhow!("bad denomination public key: {e}"))
}

/// The persistable state for one token between blinding and finalizing. `secret`
/// is the blinding factor — it never leaves the client, and without it the mint
/// could not link a redeemed token to its order even if it wanted to.
#[derive(Clone)]
pub struct PendingToken {
    pub nonce: Vec<u8>,
    pub secret: Vec<u8>,
    pub blind_message: Vec<u8>,
}

/// Blind a nonce under `pk`. The returned `PendingToken` holds the wire bytes to
/// send the mint (`blind_message`) and the secret to keep for finalizing.
pub fn blind_nonce(pk: &BlindPublicKey, nonce: &[u8]) -> Result<PendingToken> {
    let r = pk
        .blind(&mut DefaultRng, nonce)
        .map_err(|e| anyhow!("blinding failed: {e}"))?;
    Ok(PendingToken {
        nonce: nonce.to_vec(),
        secret: r.secret.0,
        blind_message: r.blind_message.0,
    })
}

/// Finalize (unblind) the mint's blind signature into an ordinary RSA signature
/// over the nonce. `finalize` re-verifies internally, so a returned signature is
/// always valid under `pk`.
pub fn finalize_token(pk: &BlindPublicKey, pending: &PendingToken, blind_sig: &[u8]) -> Result<Vec<u8>> {
    let result = BlindingResult {
        blind_message: BlindMessage(pending.blind_message.clone()),
        secret: Secret(pending.secret.clone()),
        msg_randomizer: None, // deterministic variant
    };
    let sig = pk
        .finalize(&BlindSignature(blind_sig.to_vec()), &result, &pending.nonce)
        .map_err(|e| anyhow!("finalize failed (payment/signature mismatch?): {e}"))?;
    Ok(sig.0)
}

/// Verify a finalized token signature over its nonce (what the mint does at
/// redemption; also a client-side sanity check before storing).
pub fn verify_token(pk: &BlindPublicKey, nonce: &[u8], sig: &[u8]) -> Result<()> {
    pk.verify(&Signature(sig.to_vec()), None, nonce)
        .map_err(|e| anyhow!("token signature invalid: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blind_rsa_signatures::KeyPairSha384PSSDeterministic as BlindKeyPair;

    #[test]
    fn blind_unblind_verify_roundtrip() {
        // Stand in for the mint: generate a denomination keypair.
        let kp = BlindKeyPair::generate(&mut DefaultRng, 2048).unwrap();

        let nonce = new_nonce();
        let pending = blind_nonce(&kp.pk, &nonce).unwrap();

        // Mint blind-signs the blinded nonce (never sees the nonce).
        let blind_sig = kp.sk.blind_sign(&pending.blind_message).unwrap();

        let sig = finalize_token(&kp.pk, &pending, &blind_sig.0).unwrap();
        verify_token(&kp.pk, &nonce, &sig).unwrap();

        // A tampered nonce must not verify.
        let mut bad = nonce;
        bad[0] ^= 0xff;
        assert!(verify_token(&kp.pk, &bad, &sig).is_err());
    }

    #[test]
    fn pubkey_pem_roundtrips() {
        let kp = BlindKeyPair::generate(&mut DefaultRng, 2048).unwrap();
        let pem = kp.pk.to_pem().unwrap();
        let loaded = load_pubkey(&pem).unwrap();
        let nonce = new_nonce();
        assert!(blind_nonce(&loaded, &nonce).is_ok());
    }

    #[test]
    fn pending_token_is_persistable_and_resumable() {
        // Proves "pay now, collect later": we can reconstruct the blinding state
        // from stored bytes and still finalize.
        let kp = BlindKeyPair::generate(&mut DefaultRng, 2048).unwrap();
        let nonce = new_nonce();
        let pending = blind_nonce(&kp.pk, &nonce).unwrap();

        // Simulate persistence: keep only the raw bytes.
        let restored = PendingToken {
            nonce: pending.nonce.clone(),
            secret: pending.secret.clone(),
            blind_message: pending.blind_message.clone(),
        };
        let blind_sig = kp.sk.blind_sign(&restored.blind_message).unwrap();
        let sig = finalize_token(&kp.pk, &restored, &blind_sig.0).unwrap();
        verify_token(&kp.pk, &nonce, &sig).unwrap();
    }
}
