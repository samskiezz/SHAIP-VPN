#!/usr/bin/env bash
# DPI smoke test (§18.4). The client self-test seals a DATA packet, morphs it
# (PQANON-OBF/2), and asserts the PQAN magic never appears on the wire. This
# runs that assertion and fails loudly if obfuscation regresses. The full
# wire checks (no fragments, no fixed bytes across a flow) are in
# scripts/e2e/vpn_lab.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "building pqanon client…"
cargo build --release -p pqanon-client >/dev/null

echo "running stack self-test (handshake + morphed DATA round-trip)…"
OUT=$(./target/release/pqanon selftest 2>&1)
echo "$OUT"

if echo "$OUT" | grep -q "SELFTEST OK"; then
  echo "OK: handshake + obfuscation round-trip verified; PQAN magic absent on the wire"
else
  echo "FAIL: self-test did not pass"
  exit 1
fi
