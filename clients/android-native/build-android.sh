#!/usr/bin/env bash
# Cross-compile the JNI bridge (libpqanon_jni.so) for the Android ABIs and drop
# the result into the app's jniLibs. Requires: the Android NDK, the Rust Android
# targets, and cargo-ndk.
#
#   rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi
#   cargo install cargo-ndk
#   export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
#
set -euo pipefail
cd "$(dirname "$0")"
cargo ndk \
  -t arm64-v8a -t x86_64 -t armeabi-v7a \
  -o ../android/app/src/main/jniLibs \
  build --release
echo "jniLibs updated:"
find ../android/app/src/main/jniLibs -name '*.so'
