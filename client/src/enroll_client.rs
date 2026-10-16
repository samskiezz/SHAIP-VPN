//! The device side of one-click enrollment (docs/enrollment.md).
//!
//! `pqanon enroll <pqanon://enroll?t=…>`:
//! 1. verifies the token against the **pinned** enrollment-authority key before
//!    contacting anyone — a forged or tampered link is refused locally;
//! 2. loads (or creates) this device's persistent identity;
//! 3. claims the token, proving possession of the identity's Ed25519 key;
//! 4. verifies the returned certificate against the **pinned** device-CA key,
//!    and that it binds exactly this device's key, before storing it (0600).
//!    The certificate names no account ([`enrollment::WITHHELD_ACCOUNT`]).
//!
//! The pins ship with the client build or config. Fetching them from the server
//! at enrollment time would let whoever answers that request vouch for itself.
//!
//! The only description of the device that is sent is a platform label
//! ([`platform_label`]): never a host name or a device name, which often carry
//! the owner's name.

use crate::enrollment::{self, DeviceCert, EnrollClaims};
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::VerifyingKey;
use std::path::{Path, PathBuf};

/// The outcome of a successful enrollment.
pub struct Enrolled {
    pub claims: EnrollClaims,
    pub cert: DeviceCert,
    pub cert_path: PathBuf,
}

/// Parse a hex Ed25519 public key (a pin).
pub fn parse_pin(hexkey: &str, what: &str) -> Result<VerifyingKey> {
    let raw: [u8; 32] = hex::decode(hexkey.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow!("{what} must be 64 hex characters (an Ed25519 public key)"))?;
    VerifyingKey::from_bytes(&raw).map_err(|_| anyhow!("{what} is not a valid Ed25519 key"))
}

/// The platform labels the control plane keeps for a device (see its
/// `deviceLabel`). Anything else is stored as "device".
const PLATFORM_LABELS: [&str; 6] = ["iPhone", "iPad", "Android", "Windows", "Linux", "Mac"];

/// Reduce a requested device name to the platform it names ("Alex's iPhone"
/// → "iPhone"), or "device". The name itself never leaves this machine.
pub fn platform_label(name: &str) -> &'static str {
    let name = name.to_lowercase();
    PLATFORM_LABELS
        .iter()
        .find(|l| name.contains(&l.to_lowercase()))
        .copied()
        .unwrap_or("device")
}

/// This machine's platform label (the default device name).
pub fn this_platform() -> &'static str {
    match std::env::consts::OS {
        "linux" => "Linux",
        "macos" => "Mac",
        "windows" => "Windows",
        "android" => "Android",
        "ios" => "iPhone",
        _ => "device",
    }
}

/// Where the certificate is stored by default: next to the identity file.
pub fn default_cert_path(identity_path: &Path) -> PathBuf {
    let mut p = identity_path.as_os_str().to_owned();
    p.push(".cert");
    PathBuf::from(p)
}

/// Run the enrollment flow; see the module docs.
pub fn enroll(
    link: &str,
    server: &str,
    authority: &VerifyingKey,
    ca: &VerifyingKey,
    identity_path: &Path,
    name: &str,
    cert_out: Option<&Path>,
) -> Result<Enrolled> {
    let token = if link.starts_with("pqanon://") {
        enrollment::parse_enroll_url(link).map_err(|e| anyhow!("not an enrollment link: {e}"))?
    } else {
        link.trim().to_string()
    };
    let now = crate::crl::unix_now();
    let claims = enrollment::verify_enroll_token(authority, &token, now)
        .map_err(|e| anyhow!("refusing this enrollment link: {e}"))?;

    let (identity, _) = crate::keystore::load_or_create_identity(identity_path)?;
    let device_pub = identity.public().ed_bytes();
    let body = serde_json::json!({
        "token": token,
        "device_pub": hex::encode(device_pub),
        "pop": hex::encode(identity.sign_enrollment_claim(&token)),
        "name": platform_label(name),
    });
    let url = format!("{}/api/enroll/claim", server.trim_end_matches('/'));
    let resp = match ureq::post(&url).send_json(body) {
        Ok(r) => r.into_json::<serde_json::Value>().context("claim response is not JSON")?,
        Err(ureq::Error::Status(code, r)) => {
            let msg = r
                .into_json::<serde_json::Value>()
                .ok()
                .and_then(|v| v["error"].as_str().map(str::to_string))
                .unwrap_or_default();
            bail!("enrollment refused ({code}): {msg}");
        }
        Err(e) => bail!("POST {url}: {e}"),
    };

    let cert_text = resp["cert"]
        .as_str()
        .ok_or_else(|| anyhow!("claim response has no certificate"))?;
    let cert = enrollment::verify_device_cert(ca, cert_text, now)
        .map_err(|e| anyhow!("the returned certificate is not valid under the pinned device CA: {e}"))?;
    if cert.device_pub != device_pub {
        bail!("the returned certificate binds a different key than this device's");
    }
    // Current control planes withhold the account; an older one names it, and
    // then it must be the token's.
    if cert.account != enrollment::WITHHELD_ACCOUNT && cert.account != claims.account {
        bail!("the returned certificate names a different account than the enrollment token");
    }

    let cert_path = cert_out.map(Path::to_path_buf).unwrap_or_else(|| default_cert_path(identity_path));
    crate::secure_write::write_private(&cert_path, cert_text.as_bytes())?;
    Ok(Enrolled { claims, cert, cert_path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_platform_label_is_ever_sent() {
        for (name, want) in [
            ("Alex's iPhone", "iPhone"),
            ("johns-macbook-pro", "Mac"),
            ("Pixel 8 (Android)", "Android"),
            ("linux", "Linux"),
            ("DESKTOP-4F2A9", "device"),
            ("alex-thinkpad", "device"),
            ("", "device"),
        ] {
            assert_eq!(platform_label(name), want, "{name}");
        }
        assert!(PLATFORM_LABELS.contains(&this_platform()) || this_platform() == "device");
    }
}
