//! Verify a private-key file is not group/other readable (Unix).

use anyhow::{bail, Result};
use std::path::Path;

pub fn require_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = std::fs::metadata(path)?.mode() & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} has permissions {:o}; expected 0600 (chmod 600 it)",
                path.display(),
                mode
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
