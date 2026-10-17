//! Launch-at-login registration (platform-specific).

#[cfg(target_os = "linux")]
pub fn enable(path: &std::path::Path) -> std::io::Result<()> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    let dir = std::path::PathBuf::from(home).join(".config/autostart");
    std::fs::create_dir_all(&dir)?;
    let unit = format!(
        "[Desktop Entry]\nType=Application\nName=SHAIP VPN\nExec={}\n\
         X-GNOME-Autostart-enabled=true\nHidden=false\n",
        path.display()
    );
    std::fs::write(dir.join("shaip.desktop"), unit)
}

#[cfg(not(target_os = "linux"))]
pub fn enable(_path: &std::path::Path) -> std::io::Result<()> {
    // macOS: LaunchAgent plist; Windows: HKCU\...\Run entry.
    Ok(())
}
