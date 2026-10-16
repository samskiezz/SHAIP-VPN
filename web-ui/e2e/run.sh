#!/usr/bin/env bash
# Hermetic end-to-end sandbox for the web product. Starts a fresh control plane
# (in-memory store, dev payment rail, seeded discount codes) and a Next.js dev
# server, drives every screen and flow in a headless browser (e2e/flows.cjs),
# and tears the control plane down. The web server is reused if one is already
# serving WEB_URL.
#
# Needs: Go, Node + the web-ui deps installed, and Chromium (at
# /opt/pw-browsers/chromium or wherever Playwright finds it). Self-skips with a
# clear message if Chromium or the global playwright package is missing.
#
# Exit status is the browser suite's: 0 = every step and assertion passed.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WEBDIR=$(cd "$HERE/.." && pwd)
ROOT=$(cd "$WEBDIR/.." && pwd)
API_PORT=${API_PORT:-8080}
WEB_PORT=${WEB_PORT:-3000}
WEB_URL=${WEB_URL:-http://127.0.0.1:$WEB_PORT}
OUT=${OUT:-$(mktemp -d /tmp/shaip-e2e.XXXXXX)}
PW_ROOT=${PW_ROOT:-$(npm root -g)}
mkdir -p "$OUT"

if [ ! -d "$PW_ROOT/playwright" ]; then echo "SKIP: playwright not installed globally (npm i -g playwright)"; exit 0; fi

CP_PID=0 WEB_PID=0 STARTED_WEB=0
cleanup() {
  [ "$CP_PID" != 0 ] && kill "$CP_PID" 2>/dev/null
  [ "$STARTED_WEB" = 1 ] && [ "$WEB_PID" != 0 ] && kill "$WEB_PID" 2>/dev/null
}
trap cleanup EXIT

echo "building control plane…"
CP_BIN="$OUT/cp"
( cd "$ROOT/control-plane" && go build -o "$CP_BIN" . ) || { echo "control-plane build failed"; exit 2; }

echo "starting control plane on :$API_PORT (fresh store, dev rail, seeded codes)…"
PAY_DEV_SETTLE=1 \
  COMP_CODES="SHAIPFREEYEAR:pro:365:50,SHAIPONCE:trial:30:1" \
  LISTEN_ADDR=127.0.0.1:$API_PORT METRICS_ADDR=127.0.0.1:9109 \
  "$CP_BIN" > "$OUT/cp.log" 2>&1 &
CP_PID=$!
for _ in $(seq 1 30); do curl -s -m2 -o /dev/null "http://127.0.0.1:$API_PORT/api/pay/denominations" && break; sleep 0.5; done

if ! curl -s -m2 -o /dev/null "$WEB_URL/login"; then
  echo "starting Next.js dev server on :$WEB_PORT…"
  ( cd "$WEBDIR" && NEXT_TELEMETRY_DISABLED=1 NEXT_PUBLIC_API_URL="http://127.0.0.1:$API_PORT" \
    node_modules/.bin/next dev -p "$WEB_PORT" > "$OUT/web.log" 2>&1 ) &
  WEB_PID=$!
  STARTED_WEB=1
  for _ in $(seq 1 60); do [ "$(curl -s -m2 -o /dev/null -w '%{http_code}' "$WEB_URL/login")" = "200" ] && break; sleep 1; done
fi

echo "driving the browser (screenshots → $OUT)…"
OUT="$OUT" WEB_URL="$WEB_URL" PW_ROOT="$PW_ROOT" node "$HERE/flows.cjs"
rc=$?
echo "screenshots in $OUT"
exit $rc
