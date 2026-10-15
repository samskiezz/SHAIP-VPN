//! Pre-keygen entropy check. On Linux, verify the kernel CSPRNG is seeded
//! before generating long-term keys.

use anyhow::{bail, Result};

#[cfg(target_os = "linux")]
pub fn require_entropy(bits: u32) -> Result<()> {
    let s = std::fs::read_to_string("/proc/sys/kernel/random/entropy_avail")?;
    let have: u32 = s.trim().parse().unwrap_or(0);
    if have < bits {
        bail!("insufficient entropy: {have} < {bits} required");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn require_entropy(_bits: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modern_system_has_entropy() {
        assert!(require_entropy(64).is_ok());
    }
}
