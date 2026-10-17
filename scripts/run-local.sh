#!/usr/bin/env bash
# Start the control plane (in-memory store), web UI, and both daemons locally.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release
( cd control-plane && go build -o bin/control-plane . )

echo "starting control plane on :8080 (in-memory store)…"
( cd control-plane && ./bin/control-plane ) &
echo "starting shaip-mixd on :8443…"
./target/release/shaip-mixd --listen 0.0.0.0:8443 &
echo "starting shaipd on :4430 (unprivileged demo port)…"
./target/release/shaipd --listen 0.0.0.0:4430 &

echo
echo "control plane:  http://localhost:8080/health"
echo "web UI:         cd web-ui && npm run dev   (http://localhost:3000)"
echo "press Ctrl-C to stop the background daemons"
wait
