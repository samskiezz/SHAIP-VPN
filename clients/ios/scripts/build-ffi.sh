#!/usr/bin/env bash
# Build the Rust core (crate shaip-ffi: the same code `shaip run` uses on
# Linux) for iOS and package it as Frameworks/ShaipFFI.xcframework, which the
# app and the tunnel extension link. The C header and module map come from
# ffi/include, so Swift can `import ShaipFFI`.
#
# Run on a Mac with Xcode and rustup (https://rustup.rs). Also runs as the
# tunnel target's pre-build phase; cargo only rebuilds what changed.
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)        # clients/ios
ROOT=$(cd "$HERE/../.." && pwd)                # the repository
OUT="$HERE/Frameworks"
# Xcode's build phases don't inherit the login shell's PATH.
export PATH="$HOME/.cargo/bin:$PATH"
export IPHONEOS_DEPLOYMENT_TARGET=26.0

command -v cargo >/dev/null || { echo "error: cargo not found; install Rust from https://rustup.rs" >&2; exit 1; }

DEVICE=aarch64-apple-ios
SIMS=(aarch64-apple-ios-sim x86_64-apple-ios)
rustup target add "$DEVICE" "${SIMS[@]}" >/dev/null

for t in "$DEVICE" "${SIMS[@]}"; do
  cargo rustc --manifest-path "$ROOT/Cargo.toml" -p shaip-ffi --lib --release --target "$t" --crate-type staticlib
done

mkdir -p "$OUT/sim"
lipo -create "$ROOT/target/aarch64-apple-ios-sim/release/libshaip_ffi.a" \
             "$ROOT/target/x86_64-apple-ios/release/libshaip_ffi.a" \
     -output "$OUT/sim/libshaip_ffi.a"

rm -rf "$OUT/ShaipFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$ROOT/target/$DEVICE/release/libshaip_ffi.a" -headers "$ROOT/ffi/include" \
  -library "$OUT/sim/libshaip_ffi.a" -headers "$ROOT/ffi/include" \
  -output "$OUT/ShaipFFI.xcframework" >/dev/null
echo "built $OUT/ShaipFFI.xcframework"
