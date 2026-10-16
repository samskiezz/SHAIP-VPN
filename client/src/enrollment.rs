//! Device enrollment: verifying a signed enrollment token and a signed device
//! certificate.
//!
//! An operator issues a short-lived **enrollment token** (authorizing one device
//! to join an account) and delivers it to the device out of band — a QR code or
//! a `pqanon://enroll?t=...` deep link. The device verifies that token against a
//! **pinned enrollment-authority key** before trusting it, generates its own
//! Ed25519 identity keypair, and sends the public half back. The control plane
//! then issues a **device certificate** binding that key to the account, signed
//! by a **device-CA key** the servers pin; a server verifies the certificate
//! before admitting the device.
//!
//! Both artifacts share one wire shape — `<label>.<base64url(body)>.<base64url(sig)>`
//! — where `body` is a fully deterministic, length-prefixed binary structure
//! carrying a domain-separation magic, signed directly with Ed25519 (pure, the
//! body is the message). The format matches `control-plane/enrollment/enrollment.go`
//! byte-for-byte: a token or certificate signed there verifies here unchanged,
//! which the `cross_language_*` tests pin against the Go issuer's output.
//!
//! This module only ever **verifies** — issuance lives in the control plane.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Wire label of an enrollment token.
pub const LABEL_ENROLL: &str = "PQE1";
/// Wire label of a device certificate.
pub const LABEL_CERT: &str = "PQC1";

const MAGIC_ENROLL: &[u8] = b"PQANON-ENROLL-V1";
const MAGIC_CERT: &[u8] = b"PQANON-DEVCERT-V1";
const VERSION: u8 = 1;

/// Clock-skew tolerance (seconds) applied only to the not-yet-valid boundary.
/// Expiry is strict.
pub const MAX_CLOCK_SKEW_SECS: i64 = 120;

/// Why an enrollment token or device certificate was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum EnrollError {
    /// Structurally malformed (bad label, base64, lengths, or trailing bytes).
    BadFormat(String),
    /// The body's domain-separation magic is for the other artifact type.
    WrongType,
    /// Body format version this build does not understand.
    UnsupportedVersion(u8),
    /// The Ed25519 signature does not verify under the pinned key.
    BadSignature,
    /// `now` is before the validity window (beyond the skew tolerance).
    NotYetValid,
    /// `now` is after the validity window.
    Expired,
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::BadFormat(s) => write!(f, "malformed enrollment artifact: {s}"),
            EnrollError::WrongType => write!(f, "artifact is of the wrong type"),
            EnrollError::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            EnrollError::BadSignature => write!(f, "signature does not verify"),
            EnrollError::NotYetValid => write!(f, "artifact not yet valid"),
            EnrollError::Expired => write!(f, "artifact expired"),
        }
    }
}

impl std::error::Error for EnrollError {}

/// Claims carried by a verified enrollment token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrollClaims {
    pub token_id: [u8; 16],
    pub account: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub one_time: bool,
}

/// A verified device certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCert {
    pub device_id: [u8; 16],
    pub account: String,
    pub device_pub: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Bounds-checked reader over the signed body.
struct Reader<'a> {
    b: &'a [u8],
    off: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, off: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], EnrollError> {
        let end = self
            .off
            .checked_add(n)
            .ok_or_else(|| EnrollError::BadFormat("length overflow".into()))?;
        if end > self.b.len() {
            return Err(EnrollError::BadFormat("truncated body".into()));
        }
        let p = &self.b[self.off..end];
        self.off = end;
        Ok(p)
    }
    fn u8(&mut self) -> Result<u8, EnrollError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, EnrollError> {
        let p = self.take(2)?;
        Ok(u16::from_be_bytes([p[0], p[1]]))
    }
    fn u64(&mut self) -> Result<u64, EnrollError> {
        let p = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(p);
        Ok(u64::from_be_bytes(a))
    }
    fn lp(&mut self) -> Result<&'a [u8], EnrollError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    fn finished(&self) -> bool {
        self.off == self.b.len()
    }
}

/// Split `<label>.<body>.<sig>`, check the label, verify the Ed25519 signature
/// over the body, and return the decoded body for field parsing.
fn open(key: &VerifyingKey, label: &str, s: &str) -> Result<Vec<u8>, EnrollError> {
    let mut it = s.split('.');
    let (l, body_b64, sig_b64, extra) = (it.next(), it.next(), it.next(), it.next());
    let (Some(l), Some(body_b64), Some(sig_b64), None) = (l, body_b64, sig_b64, extra) else {
        return Err(EnrollError::BadFormat("expected label.body.sig".into()));
    };
    if l != label {
        return Err(EnrollError::BadFormat(format!("wrong label {l:?}")));
    }
    let body = B64URL
        .decode(body_b64)
        .map_err(|_| EnrollError::BadFormat("bad body base64".into()))?;
    let sig_bytes = B64URL
        .decode(sig_b64)
        .map_err(|_| EnrollError::BadFormat("bad sig base64".into()))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| EnrollError::BadSignature)?;
    key.verify(&body, &sig).map_err(|_| EnrollError::BadSignature)?;
    Ok(body)
}

fn check_window(now: i64, issued: i64, expires: i64) -> Result<(), EnrollError> {
    if now.saturating_add(MAX_CLOCK_SKEW_SECS) < issued {
        return Err(EnrollError::NotYetValid);
    }
    if now > expires {
        return Err(EnrollError::Expired);
    }
    Ok(())
}

/// Verify an enrollment token against the pinned authority key at `now_unix`
/// (seconds since the Unix epoch). The signature is checked first, then the
/// domain magic and version, then the validity window.
pub fn verify_enroll_token(
    authority: &VerifyingKey,
    token: &str,
    now_unix: i64,
) -> Result<EnrollClaims, EnrollError> {
    let body = open(authority, LABEL_ENROLL, token)?;
    let mut r = Reader::new(&body);
    if r.lp()? != MAGIC_ENROLL {
        return Err(EnrollError::WrongType);
    }
    let ver = r.u8()?;
    if ver != VERSION {
        return Err(EnrollError::UnsupportedVersion(ver));
    }
    let mut token_id = [0u8; 16];
    token_id.copy_from_slice(r.take(16)?);
    let account = std::str::from_utf8(r.lp()?)
        .map_err(|_| EnrollError::BadFormat("account not utf-8".into()))?
        .to_string();
    let issued_at = r.u64()? as i64;
    let expires_at = r.u64()? as i64;
    let flags = r.u8()?;
    if !r.finished() {
        return Err(EnrollError::BadFormat("trailing bytes".into()));
    }
    check_window(now_unix, issued_at, expires_at)?;
    Ok(EnrollClaims {
        token_id,
        account,
        issued_at,
        expires_at,
        one_time: flags & 0x01 != 0,
    })
}

/// Verify a device certificate against the pinned device-CA key at `now_unix`.
pub fn verify_device_cert(
    ca: &VerifyingKey,
    cert: &str,
    now_unix: i64,
) -> Result<DeviceCert, EnrollError> {
    let body = open(ca, LABEL_CERT, cert)?;
    let mut r = Reader::new(&body);
    if r.lp()? != MAGIC_CERT {
        return Err(EnrollError::WrongType);
    }
    let ver = r.u8()?;
    if ver != VERSION {
        return Err(EnrollError::UnsupportedVersion(ver));
    }
    let mut device_id = [0u8; 16];
    device_id.copy_from_slice(r.take(16)?);
    let account = std::str::from_utf8(r.lp()?)
        .map_err(|_| EnrollError::BadFormat("account not utf-8".into()))?
        .to_string();
    let mut device_pub = [0u8; 32];
    device_pub.copy_from_slice(r.take(32)?);
    let issued_at = r.u64()? as i64;
    let expires_at = r.u64()? as i64;
    if !r.finished() {
        return Err(EnrollError::BadFormat("trailing bytes".into()));
    }
    check_window(now_unix, issued_at, expires_at)?;
    Ok(DeviceCert {
        device_id,
        account,
        device_pub,
        issued_at,
        expires_at,
    })
}

/// Build the deep-link URL a device opens to start enrollment.
pub fn enroll_url(token: &str) -> String {
    format!("pqanon://enroll?t={token}&v=1")
}

/// Extract the token from a `pqanon://enroll?t=<token>&v=1` deep link. Only the
/// string wrapping is handled here; the caller still verifies the token with
/// [`verify_enroll_token`].
pub fn parse_enroll_url(url: &str) -> Result<String, EnrollError> {
    let rest = url
        .strip_prefix("pqanon://enroll?")
        .ok_or_else(|| EnrollError::BadFormat("not a pqanon enroll URL".into()))?;
    for kv in rest.split('&') {
        if let Some(tok) = kv.strip_prefix("t=") {
            if tok.is_empty() {
                return Err(EnrollError::BadFormat("empty token".into()));
            }
            return Ok(tok.to_string());
        }
    }
    Err(EnrollError::BadFormat("no t= parameter".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact artifacts emitted by the Go issuer's TestCrossLanguageVector
    // (control-plane/enrollment). If the wire format ever changes, the Go test's
    // logged values and this block change together.
    const ENROLL_AUTHORITY_PUB: &str =
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
    const DEVICE_CA_PUB: &str =
        "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
    const DEVICE_PUB: &str =
        "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce";
    const ENROLL_TOKEN: &str = "PQE1.ABBQUUFOT04tRU5ST0xMLVYxAaurq6urq6urq6urq6urq6sACWFjY3QtZGVtbwAAAABpfpeAAAAAAGl-pZAB.qIGlHJYqy6kVhg0uVyHYh3pLc2ODabsfkhqY9Z171w0kVa_X5v1RdcRJ-rl2TNBYjWFlvCGlTcgTngjGufVYBg";
    const DEVICE_CERT: &str = "PQC1.ABFQUUFOT04tREVWQ0VSVC1WMQHNzc3Nzc3Nzc3Nzc3Nzc3NAAlhY2N0LWRlbW8Xy3n7K0Eg8rHsZeQZjW4Iso6BP-sB5KQAg5uF4YCAzgAAAABpfpeAAAAAAGtfywA.e1JCJAxQI02HyB8eqVj6cGA029PVIYwUJm7BtRyBppSnFY_n195PDwUHwKXDfRAzbNy8lh1qfft5F2W7ozL8DQ";

    // "now" instants inside each window (Unix seconds).
    const TOKEN_NOW: i64 = 1_769_905_800; // 2026-02-01T00:30:00Z
    const CERT_NOW: i64 = 1_780_272_000; // 2026-06-01T00:00:00Z

    fn vk(hex_str: &str) -> VerifyingKey {
        let bytes: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn cross_language_enroll_token_verifies() {
        let claims = verify_enroll_token(&vk(ENROLL_AUTHORITY_PUB), ENROLL_TOKEN, TOKEN_NOW).unwrap();
        assert_eq!(claims.account, "acct-demo");
        assert_eq!(claims.token_id, [0xab; 16]);
        assert!(claims.one_time);
        assert_eq!(claims.issued_at, 1_769_904_000);
        assert_eq!(claims.expires_at, 1_769_907_600);
    }

    #[test]
    fn cross_language_device_cert_verifies() {
        let cert = verify_device_cert(&vk(DEVICE_CA_PUB), DEVICE_CERT, CERT_NOW).unwrap();
        assert_eq!(cert.account, "acct-demo");
        assert_eq!(cert.device_id, [0xcd; 16]);
        // The certificate binds exactly the device's identity public key.
        let dev: [u8; 32] = hex::decode(DEVICE_PUB).unwrap().try_into().unwrap();
        assert_eq!(cert.device_pub, dev);
    }

    #[test]
    fn wrong_authority_key_is_rejected() {
        // The device-CA key must not validate an enrollment token.
        assert_eq!(
            verify_enroll_token(&vk(DEVICE_CA_PUB), ENROLL_TOKEN, TOKEN_NOW),
            Err(EnrollError::BadSignature)
        );
    }

    #[test]
    fn expired_and_not_yet_valid() {
        assert_eq!(
            verify_enroll_token(&vk(ENROLL_AUTHORITY_PUB), ENROLL_TOKEN, 1_769_911_200),
            Err(EnrollError::Expired)
        );
        assert_eq!(
            verify_enroll_token(&vk(ENROLL_AUTHORITY_PUB), ENROLL_TOKEN, 1_769_900_000),
            Err(EnrollError::NotYetValid)
        );
    }

    #[test]
    fn tampered_body_fails_signature() {
        // Flip one base64url char in the body segment: the recovered bytes differ
        // from what was signed, so the unchanged signature no longer verifies.
        let (label, rest) = ENROLL_TOKEN.split_once('.').unwrap();
        let (body, sig) = rest.split_once('.').unwrap();
        let mut bbytes = body.as_bytes().to_vec();
        bbytes[3] ^= 0x01;
        let flipped = format!("{label}.{}.{sig}", std::str::from_utf8(&bbytes).unwrap());
        assert_eq!(
            verify_enroll_token(&vk(ENROLL_AUTHORITY_PUB), &flipped, TOKEN_NOW),
            Err(EnrollError::BadSignature)
        );
    }

    #[test]
    fn label_swap_is_rejected() {
        // An enrollment token relabelled as a certificate must not verify as one.
        let swapped = format!("{LABEL_CERT}{}", &ENROLL_TOKEN[LABEL_ENROLL.len()..]);
        assert!(verify_device_cert(&vk(ENROLL_AUTHORITY_PUB), &swapped, TOKEN_NOW).is_err());
    }

    #[test]
    fn malformed_inputs() {
        let k = vk(ENROLL_AUTHORITY_PUB);
        assert!(matches!(
            verify_enroll_token(&k, "nope", TOKEN_NOW),
            Err(EnrollError::BadFormat(_))
        ));
        assert!(matches!(
            verify_enroll_token(&k, "PQE1.@@@.@@@", TOKEN_NOW),
            Err(EnrollError::BadFormat(_))
        ));
    }

    #[test]
    fn deep_link_round_trip() {
        let url = enroll_url(ENROLL_TOKEN);
        assert_eq!(url, format!("pqanon://enroll?t={ENROLL_TOKEN}&v=1"));
        assert_eq!(parse_enroll_url(&url).unwrap(), ENROLL_TOKEN);
        assert!(parse_enroll_url("https://example.com/enroll?t=x").is_err());
        assert!(parse_enroll_url("pqanon://enroll?v=1").is_err());
    }
}
