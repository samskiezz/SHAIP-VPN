//! JNI bridge: lets the Android app call the real pqanon post-quantum core.
//!
//! These symbols are exported with JNI names so Kotlin's
//! `external fun` declarations in `net.shaip.pqanon.vpn.PqNative` resolve to
//! them after `System.loadLibrary("pqanon_jni")`. The same code builds for the
//! host (for the JVM round-trip test) and for every Android ABI.

use jni::objects::JClass;
use jni::sys::jstring;
use jni::JNIEnv;

use pqanon::handshake::Identity;

/// Version string of the post-quantum core the app is linked against.
#[no_mangle]
pub extern "system" fn Java_net_shaip_pqanon_vpn_PqNative_version(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let v = format!("pqanon-core {}", env!("CARGO_PKG_VERSION"));
    new_jstring(&mut env, &v)
}

/// Run a real post-quantum self-test: generate a PQANON/1 identity (ML-DSA-65 +
/// Ed25519 keygen) and report the key size and identity id. Proves the PQ core
/// actually executes on the device, not a stub.
#[no_mangle]
pub extern "system" fn Java_net_shaip_pqanon_vpn_PqNative_selfTest(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let report = self_test();
    new_jstring(&mut env, &report)
}

fn self_test() -> String {
    let id = Identity::generate();
    let pk = id.public();
    let pq_len = pk.pq_bytes().len();
    let id_hex = hex::encode(pk.identity_id());
    format!(
        "PQ core OK — ML-DSA-65 verifying key {} bytes, identity {}",
        pq_len, id_hex
    )
}

fn new_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(j) => j.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// A plain Rust test proves the self-test logic runs the real crypto on the host,
// independent of the JVM.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_runs_real_pq_keygen() {
        let r = self_test();
        assert!(r.contains("PQ core OK"), "{r}");
        // ML-DSA-65 verifying key is 1952 bytes.
        assert!(r.contains("1952 bytes"), "{r}");
    }
}
