//! Atomic private file write: write to a temp file (mode 0600 on Unix), fsync,
//! then rename into place.

use anyhow::Result;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    // Never follow a predictable temporary-file symlink. Create exclusively
    // with private permissions from the first instant, then replace atomically.
    let name = path.file_name().ok_or_else(|| anyhow::anyhow!("private file needs a filename"))?;
    let mut selected = None;
    for _ in 0..32 {
        let mut name = name.to_os_string();
        name.push(format!(".{}.{}.tmp", std::process::id(), NEXT_FILE.fetch_add(1, Ordering::Relaxed)));
        let tmp = path.with_file_name(name);
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(file) => { selected = Some((tmp, file)); break; }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let (tmp, mut f) = selected.ok_or_else(|| anyhow::anyhow!("cannot allocate private temporary file"))?;
    let result = (|| -> Result<()> {
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() { let _ = std::fs::remove_file(&tmp); }
    result
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

    #[cfg(unix)]
    #[test]
    fn predictable_symlink_is_untouched_and_result_is_private() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("pqanon-sw-symlink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("status");
        let victim = dir.join("other-file");
        std::fs::write(&victim, b"must not change").unwrap();
        symlink(&victim, destination.with_extension("tmp")).unwrap();
        write_private(&destination, b"private snapshot").unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"must not change");
        assert_eq!(std::fs::metadata(destination).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
