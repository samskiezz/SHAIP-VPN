# shaip-android-jni

The JNI bridge that lets the Android app call the real **shaip** post-quantum
core (the same Rust crate as the CLI, the desktop app and the netns lab). Built
to `libshaip_jni.so` per Android ABI and loaded by the app via
`System.loadLibrary("shaip_jni")` (see `clients/android/.../vpn/PqNative.kt`).

## What it exposes

- `PqNative.version()` — the linked core's version.
- `PqNative.selfTest()` — runs a **real** post-quantum keygen on the device
  (SHAIP/1 identity: ML-DSA-65 + Ed25519) and returns a one-line report. The
  Dashboard shows this, so the app proves the PQ core executes on the phone.

The full tunnel data path (passing the VpnService TUN fd into the core and
running the encrypted tunnel) builds on this bridge and the existing C ABI in
`ffi/`; it needs a deployed server to carry traffic end to end.

## Build

```sh
# host round-trip test (JVM → JNI → Rust → real keygen):
cargo test --release

# Android .so for every ABI, into the app's jniLibs:
./build-android.sh
```

`build-android.sh` runs cargo-ndk; the committed `clients/android/app/src/main/
jniLibs/*/libshaip_jni.so` are its output, so the APK builds with just the
Android SDK. Re-run it after changing this crate.
