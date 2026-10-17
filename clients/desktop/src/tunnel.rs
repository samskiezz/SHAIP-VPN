//! Own the real engine process. An installed binary or a stale status file is
//! never evidence of a protected connection. No status is sent to the API.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State { Off, Starting, Connected, Reconnecting, Unverified, Stopping, Failed }

pub struct Controller {
    pub state: State,
    pub note: String,
    child: Option<Child>,
    dir: Option<PathBuf>,
    started: Option<std::time::Instant>,
}

impl Default for Controller {
    fn default() -> Self {
        Self { state: State::Off, note: "Not connected; ordinary traffic is not protected by SHAIP.".into(), child: None, dir: None, started: None }
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// Parse only a fresh snapshot from the child we launched. Unknown/old engine
/// formats fail closed. The CLI writes it only after routes/DNS/firewall exist.
fn verified_state(text: &str, pid: u32, now: u128) -> Result<State, &'static str> {
    if text.len() > 16_384 { return Err("Engine status is too large."); }
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("Malformed engine status.")?;
        if fields.insert(key, value).is_some() { return Err("Duplicate engine status field."); }
    }
    let number = |key: &str| fields.get(key).and_then(|s| s.parse::<u128>().ok());
    if number("pid") != Some(pid as u128) { return Err("Engine status belongs to another process."); }
    let age = number("updated_unix_ms").and_then(|t| now.checked_sub(t))
        .ok_or("Engine status has no valid timestamp.")?;
    if age > 6_000 { return Err("Engine status expired; protection is unverified."); }
    for key in ["full_tunnel", "dns_tunnel", "ipv6_blocked", "kill_switch"] {
        if fields.get(key) != Some(&"true") { return Err("Full routing, tunnel DNS, IPv6 blocking and the kill switch must all be enabled."); }
    }
    let identity = fields.get("server_identity").ok_or("No authenticated server identity.")?;
    if identity.len() != 32 || !identity.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("Invalid authenticated server identity.");
    }
    match fields.get("state").copied() {
        Some("Connected") => Ok(State::Connected),
        Some("Reconnecting") => Ok(State::Reconnecting),
        _ => Err("The engine has no active or reconnecting session."),
    }
}

impl Controller {
    pub fn active(&self) -> bool { self.child.is_some() }

    pub fn start(&mut self, config: &str) {
        if self.active() { return; }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            self.state = State::Failed;
            self.note = "The native tunnel backend is not implemented on this platform. This app cannot protect traffic here.".into();
        }
        #[cfg(target_os = "linux")]
        if let Err(e) = self.start_linux(config) {
            self.state = State::Failed;
            self.note = e;
            self.cleanup();
        }
    }

    #[cfg(target_os = "linux")]
    fn start_linux(&mut self, config: &str) -> Result<(), String> {
        use std::os::unix::fs::DirBuilderExt;
        if !std::path::Path::new(config).is_file() {
            return Err("Select an existing operator-issued client.toml before connecting.".into());
        }
        // create_dir is exclusive; never reuse an attacker-precreated path.
        let mut private = None;
        for attempt in 0..16 {
            let dir = std::env::temp_dir().join(format!("shaip-engine-{}-{}-{attempt}", std::process::id(), now_ms()));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => { private = Some(dir); break; }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("Cannot create a private engine status directory.".into()),
            }
        }
        self.dir = Some(private.ok_or("Cannot allocate a private engine status directory.")?);
        let engine = std::env::var_os("PQANON_ENGINE").unwrap_or_else(|| "pqanon".into());
        let child = Command::new(engine).args(["run", "--config", config, "--kill-switch"])
            .env("PQANON_STATUS_FILE", self.dir.as_ref().unwrap().join("status"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn()
            .map_err(|_| "Cannot launch pqanon. Install the updated engine and configure its required network privileges.".to_string())?;
        self.child = Some(child);
        self.started = Some(std::time::Instant::now());
        self.state = State::Starting;
        self.note = "Waiting for the engine to authenticate the server and configure routing, DNS and firewall.".into();
        Ok(())
    }

    pub fn poll(&mut self) {
        let Some(child) = self.child.as_mut() else { return; };
        match child.try_wait() {
            Ok(Some(code)) => {
                let stopping = self.state == State::Stopping;
                self.child = None;
                self.cleanup();
                self.state = if stopping && code.success() { State::Off } else { State::Failed };
                self.note = if self.state == State::Off {
                    "Disconnected; ordinary traffic is no longer protected by SHAIP.".into()
                } else {
                    format!("Engine exited ({code}). Protection is unavailable. If the kill switch remains closed, inspect the cause; `pqanon down` explicitly restores networking.")
                };
                return;
            }
            Err(_) => {
                self.state = State::Unverified;
                self.note = "Cannot verify whether the tunnel engine is running.".into();
                return;
            }
            Ok(None) => {}
        }
        if self.state == State::Stopping { return; }
        // The directory is 0700 and the engine uses atomic 0600 writes.
        let snapshot = self.dir.as_ref().and_then(|d| std::fs::read_to_string(d.join("status")).ok());
        match snapshot.as_deref().map(|s| verified_state(s, child.id(), now_ms())) {
            Some(Ok(state)) => {
                self.state = state;
                self.note = if state == State::Connected {
                    "Engine confirms full IPv4 routing, tunnel DNS, IPv6 blocking and kill switch. This is a single-hop VPN, not an anonymity guarantee.".into()
                } else { "Reconnecting. The engine's kill switch remains enabled.".into() };
            }
            Some(Err(reason)) => {
                self.state = State::Unverified;
                self.note = reason.into();
            }
            None => {
                self.state = if self.started.is_some_and(|t| t.elapsed() < Duration::from_secs(30)) { State::Starting } else { State::Unverified };
                self.note = "No fresh protection status from the engine; traffic protection is not confirmed.".into();
            }
        }
    }

    pub fn stop(&mut self) {
        let Some(child) = self.child.as_mut() else { return; };
        if matches!(child.try_wait(), Ok(Some(_))) { self.poll(); return; }
        #[cfg(target_os = "linux")]
        {
            unsafe extern "C" { fn kill(pid: i32, signal: i32) -> i32; }
            // SAFETY: a live, unreaped child owned by this controller; SIGTERM
            // invokes the engine's normal network cleanup. No shell or sudo.
            let result = unsafe { kill(child.id() as i32, 15) };
            if result != 0 {
                self.state = State::Unverified;
                self.note = "Could not stop the engine; check it before assuming the tunnel is disconnected.".into();
                return;
            }
        }
        self.state = State::Stopping;
        self.note = "Waiting for the engine to stop and restore networking.".into();
    }

    fn cleanup(&mut self) {
        if let Some(dir) = self.dir.take() {
            let _ = std::fs::remove_file(dir.join("status"));
            let _ = std::fs::remove_dir(dir);
        }
        self.started = None;
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
        // Reap and remove our private snapshot once the engine has exited.
        if let Some(mut child) = self.child.take() {
            let dir = self.dir.take();
            std::thread::spawn(move || {
                let _ = child.wait();
                if let Some(dir) = dir {
                    let _ = std::fs::remove_file(dir.join("status"));
                    let _ = std::fs::remove_dir(dir);
                }
            });
        } else { self.cleanup(); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> String {
        "pid=123\nupdated_unix_ms=10000\nstate=Connected\nfull_tunnel=true\ndns_tunnel=true\nipv6_blocked=true\nkill_switch=true\nserver_identity=0123456789abcdef0123456789abcdef\n".into()
    }
    #[test]
    fn only_fresh_own_process_full_protection_can_show_connected() {
        assert_eq!(verified_state(&snapshot(), 123, 12000), Ok(State::Connected));
        assert!(verified_state(&snapshot(), 124, 12000).is_err());
        assert!(verified_state(&snapshot(), 123, 17000).is_err());
        assert!(verified_state(&snapshot(), 123, 9999).is_err());
        for key in ["full_tunnel", "dns_tunnel", "ipv6_blocked", "kill_switch"] {
            assert!(verified_state(&snapshot().replace(&format!("{key}=true"), &format!("{key}=false")), 123, 12000).is_err());
        }
    }
    #[test]
    fn old_malformed_and_duplicate_status_is_not_protection() {
        for s in ["state=Connected\n".into(), "pqanon 0.1.0".into(), format!("{}state=Connected\n", snapshot())] {
            assert!(verified_state(&s, 123, 12000).is_err());
        }
        assert_eq!(verified_state(&snapshot().replace("state=Connected", "state=Reconnecting"), 123, 12000), Ok(State::Reconnecting));
    }
    #[test]
    fn installed_binary_alone_is_never_connected() {
        let mut c = Controller::default();
        c.start("/this/config/does/not/exist");
        assert_eq!(c.state, State::Failed);
        assert!(!c.active());
    }
}
