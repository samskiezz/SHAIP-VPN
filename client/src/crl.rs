//! The control plane's signed revocation list (CRL), verified against a pinned
//! key (§7).
//!
//! `/api/crl` serves `{crl, crl_b64, ed25519_sig, ...}`, where `crl_b64` is
//! exactly the signed bytes, so verification never depends on re-serializing
//! JSON. A tunnel server pins the CRL key (distributed out of band, like the
//! device-CA key), refreshes the list periodically, and refuses revoked
//! identities and devices. A list is accepted only if it verifies under the
//! pinned key **and is fresh**: the control plane signs a new list, with
//! `issued_at` = now, on every request, so a stale one is an attacker replaying
//! a list from before a device was revoked.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashSet;
use std::io::Read;

/// Clock skew tolerated on `issued_at` being ahead of the verifier.
const MAX_FUTURE_SKEW_SECS: i64 = 300;
/// Upper bound on a CRL response body.
const MAX_CRL_BYTES: u64 = 4 << 20;

/// A verified revocation list.
#[derive(Debug, Default, Clone)]
pub struct Crl {
    /// When the control plane signed it (Unix seconds).
    pub issued_at: i64,
    pub revoked_identities: HashSet<String>,
    pub revoked_devices: HashSet<[u8; 16]>,
}

impl Crl {
    pub fn is_device_revoked(&self, device_id: &[u8; 16]) -> bool {
        self.revoked_devices.contains(device_id)
    }
}

/// Verify a `/api/crl` response body against the pinned CRL key at `now_unix`,
/// rejecting lists older than `max_age_secs`.
pub fn verify(response: &[u8], pinned: &VerifyingKey, now_unix: i64, max_age_secs: i64) -> Result<Crl> {
    let v: serde_json::Value = serde_json::from_slice(response).context("CRL response is not JSON")?;
    let signed = B64
        .decode(v["crl_b64"].as_str().ok_or_else(|| anyhow!("CRL response has no crl_b64"))?)
        .context("crl_b64 is not base64")?;
    let sig = hex::decode(v["ed25519_sig"].as_str().ok_or_else(|| anyhow!("CRL has no signature"))?)
        .context("CRL signature is not hex")?;
    let sig = Signature::from_slice(&sig).map_err(|_| anyhow!("bad CRL signature length"))?;
    pinned
        .verify_strict(&signed, &sig)
        .map_err(|_| anyhow!("CRL signature does not verify under the pinned key"))?;

    let body: serde_json::Value = serde_json::from_slice(&signed).context("signed CRL is not JSON")?;
    let issued_at = parse_rfc3339_utc(
        body["issued_at"].as_str().ok_or_else(|| anyhow!("CRL has no issued_at"))?,
    )?;
    if issued_at > now_unix + MAX_FUTURE_SKEW_SECS {
        bail!("CRL is issued in the future (clock skew?)");
    }
    if now_unix - issued_at > max_age_secs {
        bail!("CRL is stale: issued {}s ago, limit {max_age_secs}s", now_unix - issued_at);
    }

    let mut crl = Crl { issued_at, ..Default::default() };
    for e in body["revoked"].as_array().into_iter().flatten() {
        if let Some(id) = e["identity_id"].as_str() {
            crl.revoked_identities.insert(id.to_string());
        }
    }
    for e in body["revoked_devices"].as_array().into_iter().flatten() {
        let id = e["device_id"].as_str().ok_or_else(|| anyhow!("revoked device without an id"))?;
        let raw: [u8; 16] = hex::decode(id)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow!("bad revoked device id {id:?}"))?;
        crl.revoked_devices.insert(raw);
    }
    Ok(crl)
}

/// Fetch and verify the CRL at `url` (blocking).
pub fn fetch(url: &str, pinned: &VerifyingKey, max_age_secs: i64) -> Result<Crl> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(10))
        .call()
        .map_err(|e| anyhow!("GET {url}: {e}"))?;
    let mut body = Vec::new();
    resp.into_reader().take(MAX_CRL_BYTES).read_to_end(&mut body)?;
    verify(&body, pinned, unix_now(), max_age_secs)
}

pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parse the UTC `YYYY-MM-DDTHH:MM:SSZ` form Go's `time.RFC3339` emits for a
/// UTC time.
pub fn parse_rfc3339_utc(s: &str) -> Result<i64> {
    let b = s.as_bytes();
    let shape = b.len() == 20
        && b[4] == b'-' && b[7] == b'-' && b[10] == b'T'
        && b[13] == b':' && b[16] == b':' && b[19] == b'Z';
    if !shape {
        bail!("timestamp {s:?} is not RFC 3339 UTC (YYYY-MM-DDTHH:MM:SSZ)");
    }
    let num = |r: std::ops::Range<usize>| -> Result<i64> {
        s[r].parse::<i64>().map_err(|_| anyhow!("timestamp {s:?} has a non-numeric field"))
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        bail!("timestamp {s:?} is out of range");
    }
    Ok(days_from_civil(y, mo, d) * 86_400 + h * 3_600 + mi * 60 + se)
}

/// Format Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (the inverse of
/// [`parse_rfc3339_utc`]), e.g. for comparing against signed timestamps.
pub fn format_rfc3339_utc(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // civil_from_days (H. Hinnant).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn rfc3339(t: i64) -> String {
        format_rfc3339_utc(t)
    }

    /// A CRL response exactly as the Go control plane builds it.
    fn response(key: &SigningKey, issued_at: i64, device: &str) -> Vec<u8> {
        let payload = format!(
            r#"{{"issued_at":"{}","revoked":[{{"identity_id":"abcd","reason":"lost","revoked_at":"2026-01-01T00:00:00Z"}}],"revoked_devices":[{{"device_id":"{device}","revoked_at":"2026-01-01T00:00:00Z"}}]}}"#,
            rfc3339(issued_at)
        );
        let sig = key.sign(payload.as_bytes());
        serde_json::to_vec(&serde_json::json!({
            "crl": serde_json::from_str::<serde_json::Value>(&payload).unwrap(),
            "crl_b64": B64.encode(payload.as_bytes()),
            "ed25519_sig": hex::encode(sig.to_bytes()),
            "ed25519_pub": hex::encode(key.verifying_key().to_bytes()),
        }))
        .unwrap()
    }

    const DEV: &str = "0102030405060708090a0b0c0d0e0f10";

    #[test]
    fn rfc3339_parses_known_instants() {
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse_rfc3339_utc("2000-03-01T00:00:00Z").unwrap(), 951_868_800);
        assert_eq!(parse_rfc3339_utc("2026-02-01T00:00:00Z").unwrap(), 1_769_904_000);
        assert_eq!(parse_rfc3339_utc("2024-02-29T12:34:56Z").unwrap(), 1_709_210_096);
        for bad in ["2026-02-01", "2026-02-01T00:00:00+01:00", "2026-13-01T00:00:00Z", "abcd-02-01T00:00:00Z"] {
            assert!(parse_rfc3339_utc(bad).is_err(), "{bad}");
        }
        for t in [0, 951_868_800, 1_769_904_000, 1_709_210_096] {
            assert_eq!(parse_rfc3339_utc(&rfc3339(t)).unwrap(), t);
        }
    }

    #[test]
    fn verifies_a_fresh_signed_list() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let now = 1_769_904_000;
        let crl = verify(&response(&key, now - 5, DEV), &key.verifying_key(), now, 600).unwrap();
        let mut id = [0u8; 16];
        id.copy_from_slice(&hex::decode(DEV).unwrap());
        assert!(crl.is_device_revoked(&id));
        assert!(!crl.is_device_revoked(&[0xff; 16]));
        assert!(crl.revoked_identities.contains("abcd"));
    }

    #[test]
    fn rejects_wrong_key_tampering_staleness_and_future() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let other = SigningKey::from_bytes(&[8; 32]);
        let now = 1_769_904_000;

        // Signed by a key this verifier does not pin.
        assert!(verify(&response(&other, now, DEV), &key.verifying_key(), now, 600).is_err());

        // A device removed from the signed bytes after signing.
        let mut v: serde_json::Value = serde_json::from_slice(&response(&key, now, DEV)).unwrap();
        let signed = String::from_utf8(B64.decode(v["crl_b64"].as_str().unwrap()).unwrap()).unwrap();
        v["crl_b64"] = B64.encode(signed.replace(DEV, "ffffffffffffffffffffffffffffffff")).into();
        let err = verify(&serde_json::to_vec(&v).unwrap(), &key.verifying_key(), now, 600).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        // A replayed old list.
        let err = verify(&response(&key, now - 3_600, DEV), &key.verifying_key(), now, 600).unwrap_err();
        assert!(err.to_string().contains("stale"), "{err}");

        // A list from the future.
        assert!(verify(&response(&key, now + 3_600, DEV), &key.verifying_key(), now, 600).is_err());
    }
}
