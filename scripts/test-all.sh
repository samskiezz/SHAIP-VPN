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

# --- HSM: control-plane signing keys inside a real PKCS#11 token (SoftHSM2) ---
SOFTHSM_MODULE=/usr/lib/softhsm/libsofthsm2.so
hsm_pkcs11() {
  local D OUT ok=0 bad=0 B=http://127.0.0.1:8099 BIN=control-plane/bin/control-plane
  D=$(mktemp -d)
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$D" > "$D/softhsm2.conf"
  export SOFTHSM2_CONF="$D/softhsm2.conf"
  softhsm2-util --init-token --free --label pqanon-ci --pin 1234 --so-pin 5678 >/dev/null \
    || { rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  chk() { if [ "$1" = "$2" ]; then ok=$((ok+1)); else echo "  ✗ $3: got $1 want $2"; bad=$((bad+1)); fi; }

  # 1. The keystore's PKCS#11 test must actually run against the token.
  OUT=$(cd control-plane && PQANON_TEST_PKCS11_MODULE="$SOFTHSM_MODULE" PQANON_TEST_PKCS11_TOKEN=pqanon-ci \
    PQANON_TEST_PKCS11_PIN=1234 go test -count=1 -run 'TestPKCS11' -v ./keystore/ 2>&1)
  echo "$OUT" | grep -E '^(--- |ok|FAIL)'
  if echo "$OUT" | grep -q -- '--- PASS: TestPKCS11SoftHSM' && ! echo "$OUT" | grep -q -- '--- SKIP'; then
    ok=$((ok+1)); else echo "  ✗ PKCS#11 test did not run and pass"; bad=$((bad+1)); fi

  # 2. The live control plane signs its auth tokens and CRL inside the token.
  ( cd control-plane && go build -o bin/control-plane . ) || { rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  local P11="?module-path=$SOFTHSM_MODULE&pin-env=PQANON_HSM_PIN&create=1"
  local ENVS=(PQANON_HSM_PIN=1234 LISTEN_ADDR=:8099
    "TOKEN_SIGNER=pkcs11:token=pqanon-ci;object=cp-token$P11"
    "CRL_SIGNER=pkcs11:token=pqanon-ci;object=cp-crl$P11")
  env "${ENVS[@]}" "$BIN" >/tmp/hsm_cp.log 2>&1 &
  local PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  grep -q "signing keys: token=pkcs11:" /tmp/hsm_cp.log && ok=$((ok+1)) || { echo "  ✗ token key not from the HSM"; bad=$((bad+1)); }
  chk "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api/auth/register" -H 'Content-Type: application/json' -d '{"email":"hsm@x.co","password":"password123"}')" 201 "register"
  local TOK CRLPUB
  TOK=$(curl -s -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d '{"email":"hsm@x.co","password":"password123"}' | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])" 2>/dev/null)
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/me")" 200 "HSM-signed token accepted"
  CRLPUB=$(curl -s "$B/api/crl" | python3 -c "import sys,json;print(json.load(sys.stdin)['ed25519_pub'])" 2>/dev/null)
  [ ${#CRLPUB} -eq 64 ] && ok=$((ok+1)) || { echo "  ✗ CRL pub missing"; bad=$((bad+1)); }
  kill $PID 2>/dev/null; wait $PID 2>/dev/null

  # 3. Restart: both keys persist inside the token (the old token still
  #    verifies; the CRL key is unchanged — no more per-boot CRL keys).
  env "${ENVS[@]}" "$BIN" >/tmp/hsm_cp2.log 2>&1 &
  PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  # /api/routing needs only a valid token (the in-memory user table is wiped by
  # the restart, so /api/me would 404 even though auth passed).
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/routing")" 200 "token survives restart (HSM key persisted)"
  chk "$(curl -s "$B/api/crl" | python3 -c "import sys,json;print(json.load(sys.stdin)['ed25519_pub'])" 2>/dev/null)" "$CRLPUB" "CRL key stable across restart"
  kill $PID 2>/dev/null; wait $PID 2>/dev/null

  rm -rf "$D"; unset SOFTHSM2_CONF
  echo "  HSM: $ok checks passed, $bad failed"
  [ "$bad" -eq 0 ]
}

# --- Postgres: the Store contract against a real, throwaway PostgreSQL cluster ---
PG_BIN=$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)
pg_contract() {
  local D OUT RUN=()
  D=$(mktemp -d)
  # initdb refuses to run as root; use the postgres account when we are root.
  if [ "$(id -u)" = "0" ]; then chown postgres:postgres "$D"; RUN=(runuser -u postgres --); fi
  ${RUN[@]+"${RUN[@]}"} "$PG_BIN/initdb" -D "$D/data" -A trust -U pqanon >/dev/null 2>&1 || { rm -rf "$D"; return 1; }
  ${RUN[@]+"${RUN[@]}"} "$PG_BIN/pg_ctl" -D "$D/data" -o "-k $D -p 55432 -c listen_addresses=''" \
    -l "$D/log" -w start >/dev/null || { rm -rf "$D"; return 1; }
  ${RUN[@]+"${RUN[@]}"} "$PG_BIN/createdb" -h "$D" -p 55432 -U pqanon pqanon_test
  OUT=$(cd control-plane && PQANON_TEST_DATABASE_URL="postgres:///pqanon_test?host=$D&port=55432&user=pqanon" \
    go test -count=1 -race -run 'TestStoreContractPostgres' -v . 2>&1)
  ${RUN[@]+"${RUN[@]}"} "$PG_BIN/pg_ctl" -D "$D/data" -m fast -w stop >/dev/null 2>&1
  rm -rf "$D"
  echo "$OUT" | grep -E '^(--- |    --- |ok|FAIL)'
  # The Postgres run must have happened: a skip is not a pass.
  echo "$OUT" | grep -q -- '--- PASS: TestStoreContractPostgres' && ! echo "$OUT" | grep -q -- '--- SKIP: TestStoreContractPostgres'
}

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

# --- One-click enrollment: real Rust device ↔ real Go control plane ---
enroll_e2e() {
  cargo build --release -q -p pqanon-client --bin pqanon || return 1
  ( cd control-plane && go build -o bin/control-plane . ) || return 1
  local BIN=control-plane/bin/control-plane CLI=./target/release/pqanon B=http://127.0.0.1:8095 ok=0 bad=0
  local KD W; KD=$(mktemp -d); W=$(mktemp -d)
  KEY_DIR="$KD" LISTEN_ADDR=:8095 "$BIN" >/tmp/enroll_e2e.log 2>&1 &
  local PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -rf "$KD" "$W"; return 1; }
  pass() { ok=$((ok+1)); }; fail() { echo "  ✗ $1"; bad=$((bad+1)); }
  j() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)" 2>/dev/null; }

  # The pins a client build ships with (read once here, standing in for out-of-band distribution).
  local KEYS AUTH CA CRLPUB TOK URL FORGED OUT DEV
  KEYS=$(curl -s "$B/api/enroll/keys")
  AUTH=$(echo "$KEYS" | j "['enroll_authority_pub']"); CA=$(echo "$KEYS" | j "['device_ca_pub']"); CRLPUB=$(echo "$KEYS" | j "['crl_pub']")
  [ ${#AUTH} -eq 64 ] && [ ${#CA} -eq 64 ] && [ ${#CRLPUB} -eq 64 ] && pass || fail "pinned keys"

  curl -s -X POST "$B/api/auth/register" -H 'Content-Type: application/json' -d '{"email":"enroll@x.co","password":"password123"}' >/dev/null
  TOK=$(curl -s -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d '{"email":"enroll@x.co","password":"password123"}' | j "['token']")
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api/enroll/issue")" = 401 ] && pass || fail "issue must need auth"
  URL=$(curl -s -X POST "$B/api/enroll/issue" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{}' | j "['url']")
  case "$URL" in "pqanon://enroll?t=PQE1."*) pass;; *) fail "deep link: $URL";; esac

  # A tampered link and a mis-pinned authority are both refused locally.
  FORGED=$(python3 -c "import sys;u=sys.argv[1];i=u.index('PQE1.')+8;print(u[:i]+('B' if u[i]!='B' else 'C')+u[i+1:])" "$URL")
  OUT=$($CLI enroll "$FORGED" --server "$B" --authority-key "$AUTH" --ca-key "$CA" --identity "$W/x.id" 2>&1 || true)
  echo "$OUT" | grep -q "refusing this enrollment link" && pass || fail "tampered link accepted: $OUT"
  OUT=$($CLI enroll "$URL" --server "$B" --authority-key "$CA" --ca-key "$CA" --identity "$W/x.id" 2>&1 || true)
  echo "$OUT" | grep -q "refusing this enrollment link" && pass || fail "link accepted under the wrong pin: $OUT"

  # The real enrollment: certificate verified against the pinned CA, stored 0600.
  OUT=$($CLI enroll "$URL" --server "$B" --authority-key "$AUTH" --ca-key "$CA" --identity "$W/laptop.id" --name e2e-laptop 2>&1)
  DEV=$(echo "$OUT" | sed -n 's/^Enrolled device \([0-9a-f]\{32\}\) .*/\1/p')
  [ -n "$DEV" ] && pass || fail "enroll: $OUT"
  [ "$(stat -c %a "$W/laptop.id.cert" 2>/dev/null)" = 600 ] && pass || fail "certificate not stored 0600"

  # One-time: the same link cannot enroll a second device.
  OUT=$($CLI enroll "$URL" --server "$B" --authority-key "$AUTH" --ca-key "$CA" --identity "$W/phone.id" 2>&1 || true)
  echo "$OUT" | grep -q "already been used" && pass || fail "token reused: $OUT"

  # Listed, revoked, and the revocation is in the Go-signed CRL as verified by Rust.
  curl -s "$B/api/devices" -H "Authorization: Bearer $TOK" | grep -q "\"$DEV\"" && pass || fail "device not listed"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/api/devices/$DEV" -H "Authorization: Bearer $TOK")" = 200 ] && pass || fail "revoke"
  OUT=$($CLI crl --url "$B/api/crl" --pubkey "$CRLPUB" 2>&1 || true)
  echo "$OUT" | grep -q "revoked device $DEV" && pass || fail "revocation missing from the verified CRL: $OUT"
  if $CLI crl --url "$B/api/crl" --pubkey "$CA" >/dev/null 2>&1; then fail "CRL accepted under the wrong pinned key"; else pass; fi

  kill $PID 2>/dev/null; wait $PID 2>/dev/null; rm -rf "$KD" "$W"
  echo "  enroll E2E: $ok checks passed, $bad failed"
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
if command -v softhsm2-util >/dev/null && [ -e "$SOFTHSM_MODULE" ] && command -v python3 >/dev/null; then
  stage "hsm: PKCS#11 signing keys (SoftHSM2)" hsm_pkcs11
else
  skip  "hsm: PKCS#11 signing keys (SoftHSM2)" "needs softhsm2 (apt install softhsm2) + python3"
fi
if [ -n "$PG_BIN" ] && [ -x "$PG_BIN/initdb" ] && { [ "$(id -u)" != "0" ] || id postgres >/dev/null 2>&1; }; then
  stage "postgres: store contract (real PostgreSQL)" pg_contract
else
  skip  "postgres: store contract (real PostgreSQL)" "needs PostgreSQL server binaries (apt install postgresql)"
fi
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
if command -v python3 >/dev/null; then
  stage "enroll: one-click enrollment + revocation (x-lang)" enroll_e2e
else
  skip  "enroll: one-click enrollment + revocation (x-lang)" "needs python3"
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
