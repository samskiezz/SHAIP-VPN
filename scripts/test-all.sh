#!/usr/bin/env bash
# PQ-ANON master test battery.
#
# Runs every class of test across the whole stack and prints a pass/fail
# summary: build, lint (clippy -D warnings), Rust unit + integration + fuzz +
# stress + authenticity + replay-brute, the end-to-end `selftest`, a live TUN
# smoke test, Go build/vet/test (incl. token fuzz, hostile-input brute, and a
# race-checked concurrency test), the web UI type-check + production build, and
# a live control-plane sign-up → login → use → restart end-to-end.
#
# Exit code is non-zero if any stage fails. Optional stages self-skip when their
# prerequisites are absent (root/TUN, node_modules, python3).
set -uo pipefail
cd "$(dirname "$0")/.."

declare -a NAMES STATUSES
PASS=0 FAIL=0 SKIP=0

stage() {
  local name="$1"; shift
  printf '\n════════════════════════════════════════════════════════\n▶ %s\n────────────────────────────────────────────────────────\n' "$name"
  if "$@"; then
    echo "✅ PASS: $name"; NAMES+=("$name"); STATUSES+=("PASS"); PASS=$((PASS+1))
  else
    echo "❌ FAIL: $name"; NAMES+=("$name"); STATUSES+=("FAIL"); FAIL=$((FAIL+1))
  fi
}
skip() { echo "⏭  SKIP: $1 ($2)"; NAMES+=("$1"); STATUSES+=("SKIP"); SKIP=$((SKIP+1)); }

# --- Rust ---
rust_build()   { cargo build --workspace; }
rust_clippy()  { cargo clippy --workspace --all-targets -- -D warnings; }
rust_tests()   { cargo test --release --workspace -- --nocapture; }
rust_selftest(){ cargo build --release -q -p pqanon-client --bin pqanon && ./target/release/pqanon selftest; }
rust_tunsmoke(){ ./target/release/pqanon tun-test; }

# --- Go ---
go_all() { ( cd control-plane && go build ./... && go vet ./... && go test ./... ); }

# --- Web UI ---
web_build() { ( cd web-ui && npx tsc --noEmit && npm run build >/dev/null ); }

# --- Live control-plane end-to-end (sign up → login → use → restart) ---
cp_e2e() {
  ( cd control-plane && go build -o bin/control-plane . ) || return 1
  local BIN=control-plane/bin/control-plane B=http://127.0.0.1:8097 ok=0 bad=0
  local KEY; KEY=$(openssl rand -base64 32)
  TOKEN_SIGNING_KEY="$KEY" LISTEN_ADDR=:8097 "$BIN" >/tmp/cp_e2e.log 2>&1 &
  local PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; return 1; }
  chk() { if [ "$1" = "$2" ]; then ok=$((ok+1)); else echo "  ✗ $3: got $1 want $2"; bad=$((bad+1)); fi; }

  chk "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api/auth/register" -H 'Content-Type: application/json' -d '{"email":"e2e@x.co","password":"password123"}')" 201 "register"
  local TOK; TOK=$(curl -s -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d '{"email":"e2e@x.co","password":"password123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])" 2>/dev/null)
  [ -n "$TOK" ] && ok=$((ok+1)) || { echo "  ✗ login: no token"; bad=$((bad+1)); }
  chk "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d '{"email":"e2e@x.co","password":"wrongpass1"}')" 401 "wrong password rejected"
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/me")" 200 "/api/me"
  chk "$(curl -s -o /dev/null -w '%{http_code}' "$B/api/me")" 401 "unauth rejected"
  local RID; RID=$(curl -s -X POST "$B/api/routing" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"domain":"*.x.co","route":"anon"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])" 2>/dev/null)
  [ -n "$RID" ] && ok=$((ok+1)) || { echo "  ✗ routing create"; bad=$((bad+1)); }
  chk "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/api/routing/$RID" -H "Authorization: Bearer $TOK")" 200 "routing delete"
  curl -s -X PUT "$B/api/settings" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"default_route":"anon"}' >/dev/null
  chk "$(curl -s -H "Authorization: Bearer $TOK" "$B/api/settings" | python3 -c "import sys,json;print(json.load(sys.stdin)['default_route'])" 2>/dev/null)" "anon" "settings persist"

  # Public status needs no auth.
  chk "$(curl -s "$B/api/public/status" | python3 -c "import sys,json;print(json.load(sys.stdin)['protocol'])" 2>/dev/null)" "PQANON/1" "public status (unauth)"
  # API key lifecycle: create (secret shown once) → list (hidden) → delete.
  local AKEY AKID
  AKEY=$(curl -s -X POST "$B/api/apikeys" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"name":"e2e"}')
  AKID=$(echo "$AKEY" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])" 2>/dev/null)
  case "$(echo "$AKEY" | python3 -c "import sys,json;print(json.load(sys.stdin)['key'][:4])" 2>/dev/null)" in
    pqa_) ok=$((ok+1));; *) echo "  ✗ apikey secret not returned"; bad=$((bad+1));; esac
  chk "$(curl -s -H "Authorization: Bearer $TOK" "$B/api/apikeys" | python3 -c "import sys,json;d=json.load(sys.stdin);print('leak' if any('key' in k for k in d) else 'ok')" 2>/dev/null)" "ok" "apikey list hides secret"
  chk "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/api/apikeys/$AKID" -H "Authorization: Bearer $TOK")" 200 "apikey delete"
  # Admin-only endpoint is forbidden for a normal user.
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/admin/stats")" 403 "admin stats gated"
  kill $PID 2>/dev/null; wait $PID 2>/dev/null

  # Restart with the same key: the old token must still verify.
  TOKEN_SIGNING_KEY="$KEY" LISTEN_ADDR=:8097 "$BIN" >/tmp/cp_e2e2.log 2>&1 &
  PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; return 1; }
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/routing")" 200 "token survives restart"
  kill $PID 2>/dev/null; wait $PID 2>/dev/null

  echo "  control-plane E2E: $ok checks passed, $bad failed"
  [ "$bad" -eq 0 ]
}

# --- Untraceable payments: real Rust client ↔ real Go mint (cross-language) ---
pay_e2e() {
  cargo build --release -q -p pqanon-client --bin pqanon || return 1
  ( cd control-plane && go build -o bin/control-plane . ) || return 1
  local BIN=control-plane/bin/control-plane B=http://127.0.0.1:8098 ok=0 bad=0
  local W; W=$(mktemp); local KEY; KEY=$(openssl rand -base64 32)
  PAY_DEV_SETTLE=1 TOKEN_SIGNING_KEY="$KEY" LISTEN_ADDR=:8098 "$BIN" >/tmp/pay_e2e.log 2>&1 &
  local PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -f "$W"; return 1; }
  pass() { ok=$((ok+1)); }; fail() { echo "  ✗ $1"; bad=$((bad+1)); }

  ./target/release/pqanon plans --server "$B" | grep -q month && pass || fail "plans"
  local BUY OID
  BUY=$(./target/release/pqanon buy --plan month --count 2 --server "$B" --store "$W")
  OID=$(echo "$BUY" | sed -n 's/^Order \([a-f0-9-]*\) .*/\1/p')
  [ -n "$OID" ] && pass || fail "buy (no order id)"
  # Collecting before payment must not hand out tokens.
  ./target/release/pqanon collect --order "$OID" --server "$B" --store "$W" | grep -q awaiting_payment && pass || fail "collect-before-pay"
  curl -s -X POST "$B/api/pay/dev/settle" -H 'Content-Type: application/json' -d "{\"order_id\":\"$OID\"}" >/dev/null
  # Rust unblinds a signature the Go CIRCL mint produced.
  ./target/release/pqanon collect --order "$OID" --server "$B" --store "$W" | grep -q "Collected 2" && pass || fail "collect/unblind"
  # Go verifies a Rust-produced RFC 9474 signature and grants access.
  ./target/release/pqanon redeem --plan month --server "$B" --store "$W" | grep -q "access granted" && pass || fail "redeem (interop)"
  # Second token still spends; a third does not (wallet now empty).
  ./target/release/pqanon redeem --plan month --server "$B" --store "$W" | grep -q "access granted" && pass || fail "redeem 2nd token"
  # The empty-wallet case exits non-zero by design, so capture output first
  # (a bare `cmd | grep` would trip `set -o pipefail` on the intended error).
  local EMPTY; EMPTY=$(./target/release/pqanon redeem --plan month --server "$B" --store "$W" 2>&1 || true)
  echo "$EMPTY" | grep -q "no month tokens" && pass || fail "empty wallet refused"

  kill $PID 2>/dev/null; wait $PID 2>/dev/null; rm -f "$W"
  echo "  pay E2E: $ok checks passed, $bad failed"
  [ "$bad" -eq 0 ]
}

echo "PQ-ANON master test battery — $(date -u +%FT%TZ)"

stage "rust: build (workspace)"              rust_build
stage "rust: clippy -D warnings"             rust_clippy
stage "rust: unit+integration+fuzz+stress"   rust_tests
stage "rust: selftest (end-to-end stack)"    rust_selftest
if [ "$(id -u)" = "0" ] && [ -e /dev/net/tun ]; then
  stage "rust: live TUN smoke test"          rust_tunsmoke
else
  skip  "rust: live TUN smoke test"          "needs root + /dev/net/tun"
fi
stage "go: build+vet+test (fuzz/brute/race)" go_all
if [ -d web-ui/node_modules ]; then
  stage "web: typecheck + production build"  web_build
else
  skip  "web: typecheck + production build"  "run 'npm ci' in web-ui first"
fi
if command -v python3 >/dev/null && command -v openssl >/dev/null; then
  stage "control-plane: live sign-up E2E"    cp_e2e
else
  skip  "control-plane: live sign-up E2E"    "needs python3 + openssl"
fi
if command -v openssl >/dev/null; then
  stage "pay: untraceable buy→redeem (x-lang)" pay_e2e
else
  skip  "pay: untraceable buy→redeem (x-lang)" "needs openssl"
fi

printf '\n════════════════════════════════════════════════════════\n SUMMARY\n────────────────────────────────────────────────────────\n'
for i in "${!NAMES[@]}"; do
  case "${STATUSES[$i]}" in
    PASS) icon="✅";; FAIL) icon="❌";; *) icon="⏭ ";;
  esac
  printf ' %s  %s\n' "$icon" "${NAMES[$i]}"
done
printf '────────────────────────────────────────────────────────\n %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
