//! Drives the real `pqanond` binary: a persistent identity is created once,
//! reloaded on every later run, and printed in the exact form a client pins.

use std::process::Command;

fn pqanond() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pqanond"))
}

fn tmpdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "pqanond-id-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Parse `key = "value"` lines from --print-public.
fn field<'a>(out: &'a str, key: &str) -> &'a str {
    out.lines()
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim().trim_matches('"'))
        })
        .unwrap_or_else(|| panic!("missing {key} in:\n{out}"))
}

#[test]
fn print_public_is_stable_and_pinnable() {
    let dir = tmpdir();
    let id_path = dir.join("pqanond.id");

    let run = || {
        let out = pqanond()
            .args(["--identity", id_path.to_str().unwrap(), "--print-public"])
            .output()
            .expect("run pqanond");
        assert!(out.status.success(), "pqanond failed: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap()
    };
    let first = run();
    let second = run();
    assert_eq!(first, second, "a persistent identity must print identically across runs");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&id_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "identity file must be private");
    }

    // The printed keys are exactly what a client pins, and they reconstruct to
    // the printed identity_id.
    let pq = hex_decode(field(&first, "server_ml_dsa_pub"));
    let ed = hex_decode(field(&first, "server_ed_pub"));
    assert_eq!(pq.len(), 1952, "ML-DSA-65 verifying key");
    assert_eq!(ed.len(), 32, "Ed25519 verifying key");
    let pinned = pqanon::handshake::PeerPublic::from_bytes(&pq, &ed).unwrap();
    assert_eq!(hex_encode(&pinned.identity_id()), field(&first, "identity_id"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn print_public_without_identity_is_refused() {
    let out = pqanond().arg("--print-public").output().expect("run pqanond");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--identity"));
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
