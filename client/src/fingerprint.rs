//! Config fingerprint: operators verify a running server's effective config
//! without reading the file.

use sha2::{Digest, Sha256};

pub fn fingerprint<T: serde::Serialize>(config: &T) -> String {
    let mut hasher = Sha256::new();
    if let Ok(bytes) = serde_json::to_vec(config) {
        hasher.update(&bytes);
    }
    hex::encode(&hasher.finalize()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Serialize)]
    struct C {
        a: u32,
        b: String,
    }
    #[test]
    fn stable_and_sensitive() {
        let c1 = C { a: 1, b: "x".into() };
        let c2 = C { a: 2, b: "x".into() };
        assert_eq!(fingerprint(&c1), fingerprint(&c1));
        assert_ne!(fingerprint(&c1), fingerprint(&c2));
    }
}
