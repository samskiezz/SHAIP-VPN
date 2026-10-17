//! Persistent key storage for the daemons and the client.
//!
//! A long-term key has to survive restarts: clients pin a server's public keys,
//! servers allow-list client identities, and the directory lists each mix's
//! X25519 key, so a key that changes on every boot silently breaks all three.
//! Keys live in files created 0600 (atomically, via [`crate::secure_write`]) and
//! are refused if group- or world-accessible ([`crate::perm_check`]).

use crate::handshake::Identity;
use anyhow::{bail, Context, Result};
use std::path::Path;
use zeroize::Zeroizing;

/// Leading magic of a stored X25519 static secret (a mix node's onion key).
const X25519_MAGIC: &[u8] = b"SHAIP-X25519-V1";

/// Load a stored identity, refusing a file others can read.
pub fn load_identity(path: &Path) -> Result<Identity> {
    crate::perm_check::require_owner_only(path)?;
    let raw = Zeroizing::new(
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    );
    Identity::from_secret_bytes(&raw).with_context(|| format!("loading {}", path.display()))
}

/// Store an identity (atomic write, mode 0600).
pub fn save_identity(path: &Path, id: &Identity) -> Result<()> {
    ensure_private_parent(path)?;
    crate::secure_write::write_private(path, &id.to_secret_bytes())
}

/// Load the identity at `path`, generating and storing one on first use.
/// Returns the identity and whether it was just created.
pub fn load_or_create_identity(path: &Path) -> Result<(Identity, bool)> {
    if path.exists() {
        return Ok((load_identity(path)?, false));
    }
    save_identity(path, &Identity::generate())?;
    // Re-read from disk so the identity in use is exactly the one persisted.
    Ok((load_identity(path)?, true))
}

/// Load (or create) a 32-byte X25519 static secret.
pub fn load_or_create_x25519(path: &Path) -> Result<(Zeroizing<[u8; 32]>, bool)> {
    if !path.exists() {
        ensure_private_parent(path)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, secret.as_mut());
        let mut file = Zeroizing::new(X25519_MAGIC.to_vec());
        file.extend_from_slice(secret.as_ref());
        crate::secure_write::write_private(path, &file)?;
        let (s, _) = load_or_create_x25519(path)?;
        return Ok((s, true));
    }
    crate::perm_check::require_owner_only(path)?;
    let raw = Zeroizing::new(
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
    );
    let Some(body) = raw.strip_prefix(X25519_MAGIC) else {
        bail!("{} is not a SHAIP X25519 key file", path.display());
    };
    let Ok(arr) = <[u8; 32]>::try_from(body) else {
        bail!("{} has the wrong length", path.display());
    };
    Ok((Zeroizing::new(arr), false))
}

fn ensure_private_parent(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "shaip-ks-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn identity_is_created_once_then_reloaded() {
        let dir = tmpdir("id");
        let path = dir.join("keys").join("server.id");
        let (a, created) = load_or_create_identity(&path).unwrap();
        assert!(created);
        let (b, created) = load_or_create_identity(&path).unwrap();
        assert!(!created);
        assert_eq!(a.identity_id(), b.identity_id(), "reload must yield the same identity");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn readable_identity_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("perm");
        let path = dir.join("server.id");
        load_or_create_identity(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_identity(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn x25519_key_persists_and_type_is_checked() {
        let dir = tmpdir("x");
        let path = dir.join("mix.key");
        let (a, created) = load_or_create_x25519(&path).unwrap();
        assert!(created);
        let (b, _) = load_or_create_x25519(&path).unwrap();
        assert_eq!(*a, *b);
        // An identity file must not load as an X25519 key.
        let idp = dir.join("server.id");
        load_or_create_identity(&idp).unwrap();
        assert!(load_or_create_x25519(&idp).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
