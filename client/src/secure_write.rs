//! Atomic private file write: write to a temp file (mode 0600 on Unix), fsync,
//! then rename into place.

use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("pqanon-sw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("k");
        write_private(&f, b"secret").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"secret");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
