//! Small hex helpers used across config parsing and logging.

/// Decode exactly 32 hex-encoded bytes.
pub fn decode_32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|e| e.to_string())?;
    b.as_slice()
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())
}

pub fn encode(b: &[u8]) -> String {
    hex::encode(b)
}

/// Encode, truncating long values with an ellipsis (for logs).
pub fn encode_short(b: &[u8], n: usize) -> String {
    let s = hex::encode(b);
    if s.len() <= n {
        s
    } else {
        format!("{}…", &s[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_32() {
        let k = [7u8; 32];
        assert_eq!(decode_32(&encode(&k)).unwrap(), k);
    }

    #[test]
    fn rejects_short() {
        assert!(decode_32("abcd").is_err());
    }
}
