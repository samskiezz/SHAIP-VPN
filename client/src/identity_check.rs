//! Verify node identity files exist and have owner-only permissions (Unix).

use anyhow::{bail, Result};
use std::path::Path;

pub fn verify_identity_files(files: &[&Path]) -> Result<()> {
    for f in files {
        if !f.exists() {
            bail!("identity file missing: {}", f.display());
        }
        crate::perm_check::require_owner_only(f)?;
    }
    Ok(())
}
