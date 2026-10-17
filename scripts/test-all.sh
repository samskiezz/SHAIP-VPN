#!/usr/bin/env bash
# SHAIP VPN master test battery.
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
rust_selftest(){ cargo build --release -q -p shaip-client --bin shaip && ./target/release/shaip selftest; }
rust_tunsmoke(){ ./target/release/shaip tun-test; }

# --- Go ---
go_all() { ( cd control-plane && go build ./... && go vet ./... && go test ./... ); }

# Accounts are anonymous: register takes only a password and answers with a
# random account number, which is the login.
cp_register() { # BASE → prints the new account number
  curl -s -X POST "$1/api/auth/register" -H 'Content-Type: application/json' -d '{"password":"password123"}' \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['account_number'])" 2>/dev/null
}
cp_login() { # BASE ACCOUNT [PASSWORD] → prints a bearer token
  curl -s -X POST "$1/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"account_number\":\"$2\",\"password\":\"${3:-password123}\"}" \
    | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])" 2>/dev/null
}

# --- HSM: control-plane signing keys inside a real PKCS#11 token (SoftHSM2) ---
SOFTHSM_MODULE=/usr/lib/softhsm/libsofthsm2.so
hsm_pkcs11() {
  local D OUT ok=0 bad=0 B=http://127.0.0.1:8099 BIN=control-plane/bin/control-plane
  D=$(mktemp -d)
  printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "$D" > "$D/softhsm2.conf"
  export SOFTHSM2_CONF="$D/softhsm2.conf"
  softhsm2-util --init-token --free --label shaip-ci --pin 1234 --so-pin 5678 >/dev/null \
    || { rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  chk() { if [ "$1" = "$2" ]; then ok=$((ok+1)); else echo "  ✗ $3: got $1 want $2"; bad=$((bad+1)); fi; }

  # 1. The keystore's PKCS#11 test must actually run against the token.
  OUT=$(cd control-plane && SHAIP_TEST_PKCS11_MODULE="$SOFTHSM_MODULE" SHAIP_TEST_PKCS11_TOKEN=shaip-ci \
    SHAIP_TEST_PKCS11_PIN=1234 go test -count=1 -timeout 120s -run 'TestPKCS11' -v ./keystore/ 2>&1)
  echo "$OUT" | grep -E '^(--- |ok|FAIL)'
  if echo "$OUT" | grep -q -- '--- PASS: TestPKCS11SoftHSM' && ! echo "$OUT" | grep -q -- '--- SKIP'; then
    ok=$((ok+1)); else echo "  ✗ PKCS#11 test did not run and pass"; bad=$((bad+1)); fi

  # 2. The live control plane signs its auth tokens and CRL inside the token.
  ( cd control-plane && go build -o bin/control-plane . ) || { rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  local P11="?module-path=$SOFTHSM_MODULE&pin-env=SHAIP_HSM_PIN&create=1"
  local ENVS=(SHAIP_HSM_PIN=1234 LISTEN_ADDR=:8099
    "TOKEN_SIGNER=pkcs11:token=shaip-ci;object=cp-token$P11"
    "CRL_SIGNER=pkcs11:token=shaip-ci;object=cp-crl$P11")
  env "${ENVS[@]}" "$BIN" >/tmp/hsm_cp.log 2>&1 &
  local PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  grep -q "signing keys: token=pkcs11:" /tmp/hsm_cp.log && ok=$((ok+1)) || { echo "  ✗ token key not from the HSM"; bad=$((bad+1)); }
  local TOK CRLPUB ACCT
  ACCT=$(cp_register "$B")
  [ ${#ACCT} -eq 19 ] && ok=$((ok+1)) || { echo "  ✗ register: no account number"; bad=$((bad+1)); }
  TOK=$(cp_login "$B" "$ACCT")
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/me")" 200 "HSM-signed token accepted"
  CRLPUB=$(curl -s "$B/api/crl" | python3 -c "import sys,json;print(json.load(sys.stdin)['ed25519_pub'])" 2>/dev/null)
  [ ${#CRLPUB} -eq 64 ] && ok=$((ok+1)) || { echo "  ✗ CRL pub missing"; bad=$((bad+1)); }
  kill $PID 2>/dev/null; wait $PID 2>/dev/null

  # 3. Restart: both keys persist inside the token (the old token still
  #    verifies; the CRL key is unchanged — no more per-boot CRL keys).
  env "${ENVS[@]}" "$BIN" >/tmp/hsm_cp2.log 2>&1 &
  PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -rf "$D"; unset SOFTHSM2_CONF; return 1; }
  # /api/apikeys needs only a valid token (the in-memory user table is wiped by
  # the restart, so /api/me would 404 even though auth passed).
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/apikeys")" 200 "token survives restart (HSM key persisted)"
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
  ${RUN[@]+"${RUN[@]}"} "$PG_BIN/initdb" -D "$D/data" -A trust -U shaip >/dev/null 2>&1 || { rm -rf "$D"; return 1; }
  ${RUN[@]+"${RUN[@]}"} "$PG_BIN/pg_ctl" -D "$D/data" -o "-k $D -p 55432 -c listen_addresses=''" \
    -l "$D/log" -w start >/dev/null || { rm -rf "$D"; return 1; }
  ${RUN[@]+"${RUN[@]}"} "$PG_BIN/createdb" -h "$D" -p 55432 -U shaip shaip_test
  OUT=$(cd control-plane && SHAIP_TEST_DATABASE_URL="postgres:///shaip_test?host=$D&port=55432&user=shaip" \
    go test -count=1 -race -timeout 180s -run 'TestStoreContractPostgres' -v . 2>&1)
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

  # Sign-up asks for nothing but a password; an email sent anyway is ignored.
  local REG ACCT TOK
  REG=$(curl -s -X POST "$B/api/auth/register" -H 'Content-Type: application/json' -H 'X-Forwarded-For: 198.51.100.88' \
    -d '{"email":"e2e@example.com","password":"password123"}')
  ACCT=$(echo "$REG" | python3 -c "import sys,json;print(json.load(sys.stdin)['account_number'])" 2>/dev/null)
  [ ${#ACCT} -eq 19 ] && ok=$((ok+1)) || { echo "  ✗ register: no account number in $REG"; bad=$((bad+1)); }
  TOK=$(cp_login "$B" "$ACCT")
  [ -n "$TOK" ] && ok=$((ok+1)) || { echo "  ✗ login: no token"; bad=$((bad+1)); }
  chk "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d "{\"account_number\":\"$ACCT\",\"password\":\"wrongpass1\"}")" 401 "wrong password rejected"
  chk "$(curl -s -H "Authorization: Bearer $TOK" "$B/api/me" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['account_number'], 'email' in d)" 2>/dev/null)" "$ACCT False" "/api/me: the account number, no email"
  chk "$(curl -s -o /dev/null -w '%{http_code}' "$B/api/me")" 401 "unauth rejected"
  # The per-customer record endpoints are gone.
  for P in connections routing settings; do
    chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/$P")" 404 "/api/$P removed"
  done
  chk "$(curl -s -o /dev/null -w '%{http_code}' "$B/metrics")" 404 "metrics not on the public API"

  # Public status needs no auth.
  chk "$(curl -s "$B/api/public/status" | python3 -c "import sys,json;print(json.load(sys.stdin)['protocol'])" 2>/dev/null)" "SHAIP/1" "public status (unauth)"
  # API key lifecycle: create (secret shown once) → list (hidden) → delete.
  local AKEY AKID
  AKEY=$(curl -s -X POST "$B/api/apikeys" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"name":"e2e"}')
  AKID=$(echo "$AKEY" | python3 -c "import sys,json;print(json.load(sys.stdin)['id'])" 2>/dev/null)
  case "$(echo "$AKEY" | python3 -c "import sys,json;print(json.load(sys.stdin)['key'][:4])" 2>/dev/null)" in
    pqa_) ok=$((ok+1));; *) echo "  ✗ apikey secret not returned"; bad=$((bad+1));; esac
  chk "$(curl -s -H "Authorization: Bearer $TOK" "$B/api/apikeys" | python3 -c "import sys,json;d=json.load(sys.stdin);print('leak' if any('key' in k for k in d) else 'ok')" 2>/dev/null)" "ok" "apikey list hides secret"
  local ASECRET; ASECRET=$(echo "$AKEY" | python3 -c "import sys,json;print(json.load(sys.stdin)['key'])" 2>/dev/null)
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ASECRET" "$B/api/me")" 200 "the API key authenticates"
  chk "$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "$B/api/apikeys/$AKID" -H "Authorization: Bearer $TOK")" 200 "apikey delete"
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ASECRET" "$B/api/me")" 401 "a deleted API key stops working"
  # Admin-only endpoint is forbidden for a normal user.
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/admin/stats")" 403 "admin stats gated"
  kill $PID 2>/dev/null; wait $PID 2>/dev/null
  # Nothing was logged about any request: not the address (curl came from
  # 127.0.0.1, and claimed 198.51.100.88), not a path, not the account.
  if grep -q -E "127\.0\.0\.1|198\.51\.100\.88|/api/|${ACCT// /}" /tmp/cp_e2e.log; then
    echo "  ✗ the control-plane log names a request:"; grep -E "127\.0\.0\.1|198\.51\.100|/api/" /tmp/cp_e2e.log | head -5; bad=$((bad+1))
  else ok=$((ok+1)); fi

  # Restart with the same key: the old token must still verify.
  TOKEN_SIGNING_KEY="$KEY" LISTEN_ADDR=:8097 "$BIN" >/tmp/cp_e2e2.log 2>&1 &
  PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; return 1; }
  chk "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$B/api/apikeys")" 200 "token survives restart"
  kill $PID 2>/dev/null; wait $PID 2>/dev/null

  echo "  control-plane E2E: $ok checks passed, $bad failed"
  [ "$bad" -eq 0 ]
}

# --- Unlinkable-token payments: real Rust client ↔ real Go mint (cross-language) ---
pay_e2e() {
  cargo build --release -q -p shaip-client --bin shaip || return 1
  ( cd control-plane && go build -o bin/control-plane . ) || return 1
  local BIN=control-plane/bin/control-plane B=http://127.0.0.1:8098 ok=0 bad=0
  local W; W=$(mktemp); local KEY; KEY=$(openssl rand -base64 32)
  PAY_DEV_SETTLE=1 TOKEN_SIGNING_KEY="$KEY" LISTEN_ADDR=:8098 "$BIN" >/tmp/pay_e2e.log 2>&1 &
  local PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -f "$W"; return 1; }
  pass() { ok=$((ok+1)); }; fail() { echo "  ✗ $1"; bad=$((bad+1)); }

  ./target/release/shaip plans --server "$B" | grep -q month && pass || fail "plans"
  local BUY OID
  BUY=$(./target/release/shaip buy --plan month --count 2 --server "$B" --store "$W")
  OID=$(echo "$BUY" | sed -n 's/^Order \([a-f0-9-]*\) .*/\1/p')
  [ -n "$OID" ] && pass || fail "buy (no order id)"
  # Collecting before payment must not hand out tokens.
  ./target/release/shaip collect --order "$OID" --server "$B" --store "$W" | grep -q awaiting_payment && pass || fail "collect-before-pay"
  curl -s -X POST "$B/api/pay/dev/settle" -H 'Content-Type: application/json' -d "{\"order_id\":\"$OID\"}" >/dev/null
  # Rust unblinds a signature the Go CIRCL mint produced.
  ./target/release/shaip collect --order "$OID" --server "$B" --store "$W" | grep -q "Collected 2" && pass || fail "collect/unblind"
  # Go verifies a Rust-produced RFC 9474 signature and grants access.
  ./target/release/shaip redeem --plan month --server "$B" --store "$W" | grep -q "access granted" && pass || fail "redeem (interop)"
  # Second token still spends; a third does not (wallet now empty).
  ./target/release/shaip redeem --plan month --server "$B" --store "$W" | grep -q "access granted" && pass || fail "redeem 2nd token"
  # The empty-wallet case exits non-zero by design, so capture output first
  # (a bare `cmd | grep` would trip `set -o pipefail` on the intended error).
  local EMPTY; EMPTY=$(./target/release/shaip redeem --plan month --server "$B" --store "$W" 2>&1 || true)
  echo "$EMPTY" | grep -q "no month tokens" && pass || fail "empty wallet refused"

  kill $PID 2>/dev/null; wait $PID 2>/dev/null; rm -f "$W"
  echo "  pay E2E: $ok checks passed, $bad failed"
  [ "$bad" -eq 0 ]
}

# --- One-click enrollment: real Rust device ↔ real Go control plane ---
enroll_e2e() {
  cargo build --release -q -p shaip-client --bin shaip || return 1
  ( cd control-plane && go build -o bin/control-plane . ) || return 1
  local BIN=control-plane/bin/control-plane CLI=./target/release/shaip B=http://127.0.0.1:8095 ok=0 bad=0
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

  TOK=$(cp_login "$B" "$(cp_register "$B")")
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$B/api/enroll/issue")" = 401 ] && pass || fail "issue must need auth"
  URL=$(curl -s -X POST "$B/api/enroll/issue" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{}' | j "['url']")
  case "$URL" in "shaip://enroll?t=PQE1."*) pass;; *) fail "deep link: $URL";; esac

  # A tampered link and a mis-pinned authority are both refused locally.
  FORGED=$(python3 -c "import sys;u=sys.argv[1];i=u.index('PQE1.')+8;print(u[:i]+('B' if u[i]!='B' else 'C')+u[i+1:])" "$URL")
  OUT=$($CLI enroll "$FORGED" --server "$B" --authority-key "$AUTH" --ca-key "$CA" --identity "$W/x.id" 2>&1 || true)
  echo "$OUT" | grep -q "refusing this enrollment link" && pass || fail "tampered link accepted: $OUT"
  OUT=$($CLI enroll "$URL" --server "$B" --authority-key "$CA" --ca-key "$CA" --identity "$W/x.id" 2>&1 || true)
  echo "$OUT" | grep -q "refusing this enrollment link" && pass || fail "link accepted under the wrong pin: $OUT"

  # The real enrollment: certificate verified against the pinned CA, stored 0600.
  # The device is named after its owner, as OS device names often are: only the
  # platform label may reach the server.
  OUT=$($CLI enroll "$URL" --server "$B" --authority-key "$AUTH" --ca-key "$CA" --identity "$W/laptop.id" --name "Alex Example's Linux laptop" 2>&1)
  DEV=$(echo "$OUT" | sed -n 's/^Enrolled device \([0-9a-f]\{32\}\).*/\1/p')
  [ -n "$DEV" ] && pass || fail "enroll: $OUT"
  case "$(curl -s "$B/api/devices" -H "Authorization: Bearer $TOK")" in
    *Alex*|*laptop*) fail "the device name reached the server";;
    *'"name":"Linux"'*) pass;;
    *) fail "device not labelled Linux";;
  esac
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

# --- The client facade + C ABI against a live, device-bound shaipd ---
tunnel_e2e() {
  cargo build --release -q -p shaip-client -p shaip-server -p shaip-ffi || return 1
  ( cd control-plane && go build -o bin/control-plane . ) || return 1
  local BIN=control-plane/bin/control-plane CLI=./target/release/shaip D=./target/release/shaipd
  local B=http://127.0.0.1:8093 KD W ok=0 bad=0 CP=0 SRV=0
  KD=$(mktemp -d); W=$(mktemp -d)
  pass() { ok=$((ok+1)); }; fail() { echo "  ✗ $1"; bad=$((bad+1)); }
  j() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)" 2>/dev/null; }
  stop() { [ "$1" != 0 ] && { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }; return 0; }
  up() { for _ in $(seq 50); do grep -q "listening" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }
  mkcfg() { # <name> <port> <identity> [<cert>]
    { echo '[client]'; echo "identity = \"$3\""; [ -n "${4:-}" ] && echo "device_cert = \"$4\""
      echo '[server]'; echo "address = \"127.0.0.1:$2\""
      echo "server_ml_dsa_pub = \"$PQ\""; echo "server_ed_pub = \"$ED\""; } > "$W/$1.toml"
  }

  # The C program, compiled against the header and linked with the static library.
  cc -std=c11 -Wall -Wextra -Werror -O2 -Iffi/include ffi/tests/smoke.c target/release/libshaip_ffi.a \
     -lgcc_s -lutil -lrt -lpthread -lm -ldl -lc -o "$W/smoke" && pass || fail "C smoke test did not compile/link"

  KEY_DIR="$KD" LISTEN_ADDR=:8093 "$BIN" >/tmp/tunnel_cp.log 2>&1 & CP=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { stop $CP; rm -rf "$KD" "$W"; return 1; }
  local KEYS AUTH CA CRLPUB TOK URL DEV PQ ED OUT
  KEYS=$(curl -s "$B/api/enroll/keys")
  AUTH=$(echo "$KEYS" | j "['enroll_authority_pub']"); CA=$(echo "$KEYS" | j "['device_ca_pub']"); CRLPUB=$(echo "$KEYS" | j "['crl_pub']")
  TOK=$(cp_login "$B" "$(cp_register "$B")")
  URL=$(curl -s -X POST "$B/api/enroll/issue" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{}' | j "['url']")
  $CLI enroll "$URL" --server "$B" --authority-key "$AUTH" --ca-key "$CA" --identity "$W/dev.id" --name e2e >/dev/null 2>&1 && pass || fail "enroll"
  DEV=$(curl -s "$B/api/devices" -H "Authorization: Bearer $TOK" | j "[0]['id']")

  # A device-bound shaipd: admits only certificates from this CA, refuses CRL-listed devices.
  $D --identity "$W/srv.id" --print-public > "$W/pins" 2>/dev/null
  PQ=$(sed -n 's/^server_ml_dsa_pub *= *"\(.*\)"/\1/p' "$W/pins"); ED=$(sed -n 's/^server_ed_pub *= *"\(.*\)"/\1/p' "$W/pins")
  $D --identity "$W/srv.id" --listen 127.0.0.1:47201 --device-ca "$CA" --crl-url "$B/api/crl" --crl-pub "$CRLPUB" \
     --crl-refresh-secs 1 >/tmp/tunnel_srv.log 2>&1 & SRV=$!
  up /tmp/tunnel_srv.log || fail "device-bound shaipd did not start"
  mkcfg enrolled 47201 "$W/dev.id" "$W/dev.id.cert"
  mkcfg stranger 47201 "$W/stranger.id"

  # 1. The enrolled device is admitted and packets flow (Rust facade).
  $CLI probe --config "$W/enrolled.toml" --count 3 2>/dev/null | grep -q "probe OK: 3/3" && pass || fail "enrolled device not admitted"
  # 2. The same through the C ABI (also verifies the enrollment link locally).
  OUT=$("$W/smoke" 127.0.0.1:47201 "$PQ" "$ED" "$W/dev.id" "$W/dev.id.cert" "$URL" "$AUTH" 2>&1 || true)
  echo "$OUT" | grep -q "FFI OK" && pass || fail "C ABI: $OUT"
  # 3. An unenrolled identity is not admitted.
  OUT=$($CLI probe --config "$W/stranger.toml" --count 1 --timeout-ms 1500 2>&1 || true)
  echo "$OUT" | grep -q "did not confirm the session" && pass || fail "unenrolled identity admitted: $OUT"
  # 4. Revoke the device: once shaipd refreshes the signed CRL, it is refused.
  curl -s -X DELETE "$B/api/devices/$DEV" -H "Authorization: Bearer $TOK" >/dev/null
  sleep 2.5
  OUT=$($CLI probe --config "$W/enrolled.toml" --count 1 --timeout-ms 1500 2>&1 || true)
  echo "$OUT" | grep -q "did not confirm the session" && pass || fail "revoked device still admitted: $OUT"
  stop $SRV; SRV=0

  # 5. TUN mode: the server's kernel answers ICMP sent through the tunnel.
  if [ "$(id -u)" = "0" ] && [ -e /dev/net/tun ]; then
    $D --identity "$W/srv.id" --listen 127.0.0.1:47202 --tun shaip-e2e0 --tun-addr 10.77.0.1/24 \
       >/tmp/tunnel_tun.log 2>&1 & SRV=$!
    up /tmp/tunnel_tun.log || fail "TUN-mode shaipd did not start"
    mkcfg tun 47202 "$W/tun.id"
    OUT=$($CLI probe --config "$W/tun.toml" --count 3 2>/dev/null || true)
    if echo "$OUT" | grep -q "assigned 10.77.0." && echo "$OUT" | grep -q "probe OK: 3/3" \
       && [ "$(echo "$OUT" | grep -c "ICMP echo reply from the server's kernel")" = 3 ]; then pass
    else fail "TUN-mode kernel ICMP: $OUT"; fi
    stop $SRV; SRV=0
  else
    echo "  (TUN-mode kernel ICMP check skipped: needs root + /dev/net/tun)"
  fi

  stop $CP; rm -rf "$KD" "$W"
  echo "  tunnel E2E: $ok checks passed, $bad failed"
  [ "$bad" -eq 0 ]
}

# --- Staking: paid bond → signed directory → equivocation slashed (real node key) ---
stake_e2e() {
  cargo build --release -q -p shaip-client -p shaip-server || return 1
  ( cd control-plane && go build -o bin/control-plane . ) || return 1
  local BIN=control-plane/bin/control-plane CLI=./target/release/shaip D=./target/release/shaipd
  local B=http://127.0.0.1:8091 KD W ok=0 bad=0 PID
  KD=$(mktemp -d); W=$(mktemp -d)
  pass() { ok=$((ok+1)); }; fail() { echo "  ✗ $1"; bad=$((bad+1)); }
  j() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)" 2>/dev/null; }
  code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
  PAY_DEV_SETTLE=1 KEY_DIR="$KD" LISTEN_ADDR=:8091 STAKE_MIN_SATS=100000 STAKE_SLASH_PERCENT=50 STAKE_WATCH_SECS=1 \
    "$BIN" >/tmp/stake_cp.log 2>&1 & PID=$!
  curl -fsS --retry 40 --retry-delay 1 --retry-connrefused "$B/health" >/dev/null || { kill $PID; rm -rf "$KD" "$W"; return 1; }

  local KEYS DIRNAME DIRPUB TOK TOK2 ED NODE BOND DA DB DF1 DF2 OUT ST
  KEYS=$(curl -s "$B/api/enroll/keys")
  DIRNAME=$(echo "$KEYS" | j "['directory_authority']"); DIRPUB=$(echo "$KEYS" | j "['directory_pub']")
  local H='Content-Type: application/json'
  TOK=$(cp_login "$B" "$(cp_register "$B")")
  TOK2=$(cp_login "$B" "$(cp_register "$B")")
  local A="Authorization: Bearer $TOK"

  # The node's key is the real shaipd identity's Ed25519 key.
  $D --identity "$W/node.id" --print-public > "$W/pins" 2>/dev/null
  ED=$(sed -n 's/^server_ed_pub *= *"\(.*\)"/\1/p' "$W/pins")
  [ "$(code -X POST "$B/api/nodes" -H "$A" -H "$H" -d "{\"name\":\"liar\",\"address\":\"x:1\",\"public_key\":\"$ED\",\"stake_sats\":5000000}")" = 400 ] \
    && pass || fail "self-declared stake accepted"
  NODE=$(curl -s -X POST "$B/api/nodes" -H "$A" -H "$H" -d "{\"name\":\"zrh-01\",\"address\":\"203.0.113.5:443\",\"public_key\":\"$ED\",\"ed_pub\":\"$ED\",\"role\":\"mix\",\"region\":\"CH\",\"capacity_mbps\":500}" | j "['id']")
  [ ${#NODE} -eq 36 ] && pass || fail "register node: $NODE"

  # Unbonded: absent from the directory, as verified by the Rust client.
  OUT=$($CLI directory --url "$B/api/directory" --authority "$DIRNAME=$DIRPUB" 2>&1 || true)
  echo "$OUT" | grep -q "directory verified: 0 node" && pass || fail "unbonded node listed: $OUT"
  [ "$(code -X POST "$B/api/stake/$NODE/bond" -H "Authorization: Bearer $TOK2" -H "$H" -d '{"amount_sats":200000,"rail":"dev"}')" = 403 ] \
    && pass || fail "non-operator bonded"

  # Bond, pay on the dev rail, and let the bond watcher (not a status poll) credit it.
  BOND=$(curl -s -X POST "$B/api/stake/$NODE/bond" -H "$A" -H "$H" -d '{"amount_sats":200000,"rail":"dev"}' | j "['bond_id']")
  curl -s -X POST "$B/api/stake/dev/settle" -H "$H" -d "{\"bond_id\":\"$BOND\"}" >/dev/null
  sleep 2.5
  OUT=$($CLI directory --url "$B/api/directory" --authority "$DIRNAME=$DIRPUB" 2>&1 || true)
  echo "$OUT" | grep -q "node zrh-01 addr 203.0.113.5:443 role mix region CH capacity 500 Mbit/s ed25519 $ED" \
    && pass || fail "bonded node not in the verified directory: $OUT"
  [ "$(code -X POST "$B/api/stake/$NODE/unbond" -H "$A" -H "$H" -d '{"amount_sats":50000}')" = 200 ] && pass || fail "unbond"

  # The operator equivocates: its node key signs two different descriptors for epoch 42.
  DA=$($D --identity "$W/node.id" --sign-descriptor --node-id "$NODE" --epoch 42 --advertise 203.0.113.5:443 --region CH --capacity-mbps 500 2>/dev/null)
  DB=$($D --identity "$W/node.id" --sign-descriptor --node-id "$NODE" --epoch 42 --advertise 198.51.100.9:443 --region CH --capacity-mbps 500 2>/dev/null)
  # Not evidence: the same descriptor twice, or descriptors signed by someone else's key.
  [ "$(code -X POST "$B/api/stake/slash" -H "$H" -d "{\"descriptor_a\":\"$DA\",\"descriptor_b\":\"$DA\"}")" = 400 ] && pass || fail "identical descriptors slashed"
  DF1=$($D --identity "$W/forger.id" --sign-descriptor --node-id "$NODE" --epoch 42 --advertise 192.0.2.1:1 2>/dev/null)
  DF2=$($D --identity "$W/forger.id" --sign-descriptor --node-id "$NODE" --epoch 42 --advertise 192.0.2.2:1 2>/dev/null)
  [ "$(code -X POST "$B/api/stake/slash" -H "$H" -d "{\"descriptor_a\":\"$DF1\",\"descriptor_b\":\"$DF2\"}")" = 400 ] && pass || fail "forged evidence slashed"

  # Real evidence, submitted by anyone (no auth): 50% of 150k bonded + 50k unbonding.
  OUT=$(curl -s -X POST "$B/api/stake/slash" -H "$H" -d "{\"descriptor_a\":\"$DA\",\"descriptor_b\":\"$DB\"}")
  [ "$(echo "$OUT" | j "['slashed_sats']")" = 100000 ] && pass || fail "slash: $OUT"
  [ "$(code -X POST "$B/api/stake/slash" -H "$H" -d "{\"descriptor_a\":\"$DB\",\"descriptor_b\":\"$DA\"}")" = 409 ] && pass || fail "repeat slash accepted"
  ST=$(curl -s "$B/api/stake/$NODE")
  [ "$(echo "$ST" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['bonded_sats'],d['unbonding_sats'],d['jailed'],sep=',')" 2>/dev/null)" = "75000,25000,True" ] \
    && pass || fail "stake after slash: $ST"
  # Jailed: gone from the directory; and the directory is refused under the wrong pin.
  OUT=$($CLI directory --url "$B/api/directory" --authority "$DIRNAME=$DIRPUB" 2>&1 || true)
  echo "$OUT" | grep -q "directory verified: 0 node" && pass || fail "jailed node still listed: $OUT"
  if $CLI directory --url "$B/api/directory" --authority "$DIRNAME=$ED" >/dev/null 2>&1; then
    fail "directory accepted under the wrong pinned key"; else pass; fi

  kill $PID 2>/dev/null; wait $PID 2>/dev/null; rm -rf "$KD" "$W"
  echo "  stake E2E: $ok checks passed, $bad failed"
  [ "$bad" -eq 0 ]
}

echo "SHAIP VPN master test battery — $(date -u +%FT%TZ)"

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
  stage "pay: unlinkable-token buy→redeem (x-lang)" pay_e2e
else
  skip  "pay: unlinkable-token buy→redeem (x-lang)" "needs openssl"
fi
if command -v python3 >/dev/null; then
  stage "enroll: one-click enrollment + revocation (x-lang)" enroll_e2e
else
  skip  "enroll: one-click enrollment + revocation (x-lang)" "needs python3"
fi
if command -v python3 >/dev/null && command -v cc >/dev/null; then
  stage "tunnel: client facade + C ABI vs device-bound shaipd" tunnel_e2e
else
  skip  "tunnel: client facade + C ABI vs device-bound shaipd" "needs python3 + a C compiler"
fi
# The VPN for real: client netns → ISP router → shaipd (TUN + NAT + DNS) → "internet" netns.
vpn_lab() {
  cargo build --release -q -p shaip-client -p shaip-server || return 1
  ./scripts/e2e/vpn_lab.sh
}
if [ "$(id -u)" = "0" ] && [ -e /dev/net/tun ] && command -v ip >/dev/null && command -v nft >/dev/null \
   && command -v conntrack >/dev/null && command -v curl >/dev/null && command -v python3 >/dev/null; then
  stage "vpn: full tunnel across 4 netns (NAT, DNS, reconnect, kill switch, no client logs)" vpn_lab
else
  skip  "vpn: full tunnel across 4 netns (NAT, DNS, reconnect, kill switch, no client logs)" "needs root, /dev/net/tun, iproute2, nftables, conntrack, curl, python3"
fi
if command -v python3 >/dev/null; then
  stage "stake: bond → directory → equivocation slash (x-lang)" stake_e2e
else
  skip  "stake: bond → directory → equivocation slash (x-lang)" "needs python3"
fi

# iOS core: the committed render vectors must still be what design/shaip-engine.js produces, and
# SHAIPCore's engines must reproduce them op for op; the config/status/Protection model is tested;
# and the app's own C-ABI Swift (clients/ios/FFI) drives the Rust core against a live shaipd.
ios_core() {
  local tmp; tmp=$(mktemp)
  node clients/ios/scripts/engine-vectors.mjs clients/ios/design/shaip-engine.js "$tmp" >/dev/null || return 1
  if ! cmp -s "$tmp" clients/ios/SHAIPCore/Tests/SHAIPCoreTests/Fixtures/engine-vectors.json; then
    echo "engine-vectors.json is stale: regenerate it with clients/ios/scripts/engine-vectors.mjs"; rm -f "$tmp"; return 1
  fi
  rm -f "$tmp"
  swift test --package-path clients/ios/SHAIPCore || return 1
  cargo build --release -q -p shaip-ffi -p shaip-server || return 1
  swift build --package-path clients/ios/FFIInterop >/dev/null || return 1
  local W PQ ED ID SP rc
  W=$(mktemp -d)
  ./target/release/shaipd --identity "$W/srv.id" --print-public > "$W/pins" 2>/dev/null
  PQ=$(sed -n 's/^server_ml_dsa_pub *= *"\(.*\)"/\1/p' "$W/pins")
  ED=$(sed -n 's/^server_ed_pub *= *"\(.*\)"/\1/p' "$W/pins")
  ID=$(sed -n 's/^identity_id *= *"\(.*\)"/\1/p' "$W/pins")
  ./target/release/shaipd --identity "$W/srv.id" --listen 127.0.0.1:47311 > "$W/srv.log" 2>&1 & SP=$!
  for _ in $(seq 50); do grep -q listening "$W/srv.log" && break; sleep 0.1; done
  clients/ios/FFIInterop/.build/debug/FFIInterop 127.0.0.1:47311 "$PQ" "$ED" "$W/dev.id" "$ID"; rc=$?
  kill $SP 2>/dev/null; wait $SP 2>/dev/null; rm -rf "$W"
  return $rc
}
# Swift 6.0's compiler crashes (signal 11) building the swift-testing suite; 6.1+ is needed.
swift_ok() { command -v swift >/dev/null && ! swift --version 2>&1 | grep -qE 'Swift version 6\.0(\.|[^0-9])'; }
if swift_ok && command -v node >/dev/null; then
  stage "ios: SHAIPCore + Swift↔Rust C ABI vs live shaipd" ios_core
else
  skip  "ios: SHAIPCore + Swift↔Rust C ABI vs live shaipd" "needs swift ≥ 6.1 + node"
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
