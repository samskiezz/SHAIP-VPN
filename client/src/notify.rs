//! Desktop notifications (platform-specific).

pub enum NotifyLevel {
    Info,
    Warning,
    Error,
}

pub fn notify(level: NotifyLevel, title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    {
        let urgency = match level {
            NotifyLevel::Info | NotifyLevel::Warning => "normal",
            NotifyLevel::Error => "critical",
        };
        let _ = std::process::Command::new("notify-send")
            .args(["-u", urgency, title, body])
            .status();
    }
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            body.replace('"', "\\\""),
            title.replace('"', "\\\"")
        );
        let _ = std::process::Command::new("osascript").args(["-e", &script]).status();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (level, title, body);
    }
}
