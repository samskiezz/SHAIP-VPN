//! TLS 1.3 decoy ServerHello (§10.2 anti-probing).
//!
//! When an unrecognized datagram hits the tunnel port — a scanner, a DPI probe,
//! an active prober trying to classify the service — the daemon answers with a
//! **freshly randomized, well-formed TLS 1.3 ServerHello** instead of a static
//! blob or silence. Because the server random, the echoed session id and the
//! X25519 key_share are regenerated every time, the decoy carries no fixed
//! fingerprint a prober could match across connections; to a scanner the port
//! simply looks like an ordinary HTTPS server.

use rand::rngs::OsRng;
use rand::RngCore;

/// TLS record content type for handshake messages.
pub const TLS_RECORD_HANDSHAKE: u8 = 22;
/// `legacy_record_version` / `legacy_version` = TLS 1.2 (0x0303), per RFC 8446.
pub const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x03];
/// The real negotiated version, carried in the supported_versions extension.
pub const TLS_1_3: [u8; 2] = [0x03, 0x04];
/// `TLS_AES_128_GCM_SHA256`.
pub const CIPHER_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
/// Named group x25519 (0x001d).
pub const GROUP_X25519: [u8; 2] = [0x00, 0x1d];

/// Build a fresh, randomized TLS 1.3 ServerHello record echoing `session_id`
/// (truncated to the 32-byte legacy maximum). Every call differs.
pub fn server_hello(session_id: &[u8]) -> Vec<u8> {
    let mut rng = OsRng;
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut key_share);

    let sid = &session_id[..session_id.len().min(32)];

    // --- extensions ---
    let mut exts = Vec::new();
    // supported_versions (server selected): type 0x002b, len 2, TLS 1.3.
    exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02]);
    exts.extend_from_slice(&TLS_1_3);
    // key_share: type 0x0033, then group + key_exchange(32).
    exts.extend_from_slice(&[0x00, 0x33]);
    let ks_body_len: u16 = 2 /* group */ + 2 /* key len */ + 32 /* key */;
    exts.extend_from_slice(&ks_body_len.to_be_bytes());
    exts.extend_from_slice(&GROUP_X25519);
    exts.extend_from_slice(&32u16.to_be_bytes());
    exts.extend_from_slice(&key_share);

    // --- ServerHello body ---
    let mut body = Vec::new();
    body.extend_from_slice(&TLS_LEGACY_VERSION);
    body.extend_from_slice(&random);
    body.push(sid.len() as u8);
    body.extend_from_slice(sid);
    body.extend_from_slice(&CIPHER_AES_128_GCM_SHA256);
    body.push(0x00); // legacy_compression_method = null
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // --- handshake header (type + 24-bit length) ---
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(0x02); // ServerHello
    let blen = body.len();
    hs.push((blen >> 16) as u8);
    hs.push((blen >> 8) as u8);
    hs.push(blen as u8);
    hs.extend_from_slice(&body);

    // --- record header (type + legacy version + 16-bit length) ---
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(TLS_RECORD_HANDSHAKE);
    rec.extend_from_slice(&TLS_LEGACY_VERSION);
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

/// A decoy response with a randomized legacy session id, for when there is no
/// real client session id to echo.
pub fn probe_response() -> Vec<u8> {
    let mut sid = [0u8; 32];
    OsRng.fill_bytes(&mut sid);
    server_hello(&sid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_is_well_formed_tls13_server_hello() {
        let r = server_hello(&[1, 2, 3, 4]);
        assert_eq!(r[0], TLS_RECORD_HANDSHAKE);
        assert_eq!(&r[1..3], &TLS_LEGACY_VERSION);
        let rec_len = u16::from_be_bytes([r[3], r[4]]) as usize;
        assert_eq!(rec_len, r.len() - 5, "record length prefix must match body");
        assert_eq!(r[5], 0x02, "handshake type must be ServerHello");
        let hs_len = ((r[6] as usize) << 16) | ((r[7] as usize) << 8) | (r[8] as usize);
        assert_eq!(hs_len, r.len() - 9, "handshake length prefix must match body");
        assert_eq!(&r[9..11], &TLS_LEGACY_VERSION, "body legacy_version");
        assert!(
            r.windows(2).any(|w| w == CIPHER_AES_128_GCM_SHA256),
            "cipher suite present"
        );
        assert!(
            r.windows(2).any(|w| w == TLS_1_3),
            "TLS 1.3 selected in supported_versions"
        );
    }

    #[test]
    fn successive_decoys_differ() {
        assert_ne!(
            probe_response(),
            probe_response(),
            "decoys must be randomized per connection"
        );
    }

    #[test]
    fn echoes_the_session_id() {
        let sid = [0xABu8; 16];
        let r = server_hello(&sid);
        assert!(
            r.windows(16).any(|w| w == sid),
            "client session id must be echoed"
        );
    }

    #[test]
    fn oversized_session_id_is_truncated() {
        // A >32-byte session id must not corrupt the single-byte length field.
        let r = server_hello(&[7u8; 64]);
        // body starts at offset 9: legacy_version(2) + random(32) then sid len.
        let sid_len = r[9 + 2 + 32] as usize;
        assert_eq!(sid_len, 32, "session id must be clamped to 32 bytes");
    }
}
