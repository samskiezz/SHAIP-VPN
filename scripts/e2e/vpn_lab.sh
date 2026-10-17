#!/usr/bin/env bash
# The VPN, end to end, across four network namespaces with real kernels doing
# the routing:
#
#   pqlab-cli ──────── pqlab-rtr ──────── pqlab-srv
#   192.168.77.2       (the ISP)          198.51.100.2
#   (shaip run)          │               (shaipd --tun --nat)
#                     pqlab-net 203.0.113.2
#                     ("the internet": a web server and a resolver)
#
# The public side uses the documentation ranges, so the server's default
# policy (clients may not reach private addresses) applies as in production.
#
# It proves, rather than assumes:
#  1. without the VPN the web host sees the client's own address and the
#     client's lookups go to its ISP's resolver;
#  2. with `shaip run`, every IPv4 packet and every lookup goes through the
#     tunnel: the web host sees only the VPN server's address, the ISP resolver
#     sees none of the lookups, and a 16 MiB download arrives byte-identical;
#  3. the client rides out a graceful server restart and a hard server crash,
#     keeping its tunnel address;
#  4. a clean disconnect restores routes, resolver and firewall exactly;
#  5. with --kill-switch, a crashed client leaks nothing until `shaip down`;
#  6. on the ISP's link the VPN is random bytes: no IP fragments, handshakes
#     in 1200-byte datagrams, no protocol magic, no byte position that holds
#     a fixed value across a flow's packets.
#
# Needs root, /dev/net/tun, iproute2, nftables, curl and python3, and release
# builds of shaip and shaipd. Exit status is the number of failed checks.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CLI=$ROOT/target/release/shaip
SRV=$ROOT/target/release/shaipd
H=$ROOT/scripts/e2e
W=$(mktemp -d /tmp/pqlab.XXXXXX)
C=pqlab-cli R=pqlab-rtr S=pqlab-srv N=pqlab-net
ok=0 bad=0 SRV_PID=0 CLI_PID=0
PIDS=()
pass() { echo "  ✓ $1"; ok=$((ok+1)); }
fail() { echo "  ✗ $1"; bad=$((bad+1)); }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
# waitfor FILE PATTERN TENTHS — wait for a line matching PATTERN.
waitfor() { local i; for i in $(seq "${3:-100}"); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  sleep 0.5
  for p in "${PIDS[@]}"; do kill -9 "$p" 2>/dev/null; done
  for n in $C $R $S $N; do ip netns del "$n" 2>/dev/null; done
  rm -rf "/etc/netns/$C" "$W"
}
trap cleanup EXIT

for n in $C $R $S $N; do ip netns del "$n" 2>/dev/null; done

# --- topology ---------------------------------------------------------------
for n in $C $R $S $N; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add c0 netns $C type veth peer name rc netns $R
ip link add s0 netns $S type veth peer name rs netns $R
ip link add n0 netns $N type veth peer name rn netns $R
ip -n $R addr add 192.168.77.1/24 dev rc
ip -n $R addr add 198.51.100.1/24 dev rs
ip -n $R addr add 203.0.113.1/24 dev rn
for l in rc rs rn; do ip -n $R link set "$l" up; done
ip netns exec $R sysctl -qw net.ipv4.ip_forward=1
ip -n $C addr add 192.168.77.2/24 dev c0; ip -n $C link set c0 up; ip -n $C route add default via 192.168.77.1
ip -n $S addr add 198.51.100.2/24 dev s0; ip -n $S link set s0 up; ip -n $S route add default via 198.51.100.1
ip -n $N addr add 203.0.113.2/24 dev n0; ip -n $N link set n0 up; ip -n $N route add default via 203.0.113.1

# The client's own resolver is its ISP's, on the router.
mkdir -p "/etc/netns/$C"
printf 'nameserver 192.168.77.1\n' > "/etc/netns/$C/resolv.conf"
ORIG_RESOLV=$(cat "/etc/netns/$C/resolv.conf")

# --- services ---------------------------------------------------------------
ip netns exec $R python3 -I "$H/lab_dns.py" 192.168.77.1 203.0.113.2 "$W/isp_dns.log" & PIDS+=($!)
ip netns exec $N python3 -I "$H/lab_dns.py" 203.0.113.2 203.0.113.2 "$W/inet_dns.log" & PIDS+=($!)
ip netns exec $N python3 -I "$H/lab_http.py" 203.0.113.2 8080 "$W/http.log" "$W/blob.sha" & PIDS+=($!)
for _ in $(seq 100); do [ -s "$W/blob.sha" ] && ip netns exec $C curl -s -o /dev/null --max-time 1 http://203.0.113.2:8080/ready && break; sleep 0.1; done

get() { ip netns exec $C curl -s --max-time "${2:-5}" "$1"; }
http_lines() { wc -l < "$W/http.log"; }

echo "  -- without the VPN"
check "the web host sees the client's own address" [ "$(get http://direct-1.test:8080/)" = "caller=192.168.77.2" ]
check "lookups go to the ISP's resolver" grep -q "^192.168.77.2 direct-1.test 1$" "$W/isp_dns.log"

# --- server -----------------------------------------------------------------
"$SRV" --identity "$W/srv.id" --print-public > "$W/pins" 2>/dev/null
PQ=$(sed -n 's/^server_ml_dsa_pub *= *"\(.*\)"/\1/p' "$W/pins")
ED=$(sed -n 's/^server_ed_pub *= *"\(.*\)"/\1/p' "$W/pins")
start_server() { # <n>
  ip netns exec $S "$SRV" --identity "$W/srv.id" --listen 198.51.100.2:443 --tun pqs0 --tun-addr 10.77.0.1/24 \
    --nat s0 --dns-upstream 203.0.113.2:53 --metrics 127.0.0.1:9100 --lease-grace-secs 3 > "$W/server.$1.log" 2>&1 &
  SRV_PID=$!; PIDS+=($SRV_PID)
  waitfor "$W/server.$1.log" "shaipd listening" 100
}

cat > "$W/client.toml" <<EOF
[client]
identity   = "$W/cli.id"
tun_device = "pqc0"

[server]
address           = "198.51.100.2:443"
server_ml_dsa_pub = "$PQ"
server_ed_pub     = "$ED"
EOF
start_client() { # <n> [run flags...]
  local n=$1; shift
  SHAIP_STATE_DIR="$W/state" SHAIP_STATUS_FILE="$W/status" \
    ip netns exec $C "$CLI" run --config "$W/client.toml" --keepalive-secs 1 --dead-secs 4 "$@" \
    > "$W/client.$n.log" 2>&1 &
  CLI_PID=$!; PIDS+=($CLI_PID)
  waitfor "$W/client.$n.log" "^connected:" 150
}
status_field() { sed -n "s/^$1=//p" "$W/status" 2>/dev/null; }
metric() { ip netns exec $S curl -s http://127.0.0.1:9100/metrics | sed -n "s/^$1 //p"; }
# NAT (conntrack) entries in the server's kernel for connections from ADDR.
flows_from() { ip netns exec $S conntrack -L --orig-src "$1" 2>/dev/null | grep -c . ; }

# What the ISP sees, from the first handshake through the restarts below.
ip netns exec $R python3 -I "$H/lab_wirecap.py" rc 192.168.77.2 198.51.100.2 443 "$W/wire.json" & CAP_PID=$!; PIDS+=($CAP_PID)
sleep 0.3
wire() { python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])); [v:=v[k] for k in sys.argv[2:]]; print(v)' "$W/wire.json" "$@"; }

check "shaipd starts (TUN + NAT + DNS forwarder)" start_server 1
check "shaip run connects" start_client 1
waitfor "$W/status" "^rtt_ms=[0-9]" 50
TUNIP=$(status_field tunnel_address)

echo "  -- through the VPN"
MARK=$(http_lines)
check "the web host sees only the VPN server's address" [ "$(get http://vpn-1.test:8080/)" = "caller=198.51.100.2" ]
check "lookups leave from the VPN server's forwarder" grep -q "^198.51.100.2 vpn-1.test 1$" "$W/inet_dns.log"
check "the ISP's resolver saw none of them (no DNS leak)" bash -c "! grep -q 'vpn-1.test' '$W/isp_dns.log'"
SPEED=$(ip netns exec $C curl -s --max-time 60 -o "$W/blob" -w '%{speed_download}' http://vpn-2.test:8080/blob)
SHA=$(sha256sum "$W/blob" | cut -d' ' -f1)
check "a 16 MiB download through the tunnel is byte-identical" [ "$SHA" = "$(cat "$W/blob.sha")" ]
echo "    (measured: $(awk -v b="${SPEED:-0}" 'BEGIN { printf "%.0f", b * 8 / 1e6 }') Mbit/s through the tunnel on this machine)"
ROUTES=$(ip -n $C route)
check "routes: 0/1 + 128/1 into the tunnel, the server pinned via the ISP" bash -c \
  "grep -q '^0.0.0.0/1 dev pqc0' <<<'$ROUTES' && grep -q '^128.0.0.0/1 dev pqc0' <<<'$ROUTES' && grep -q '^198.51.100.2 via 192.168.77.1 dev c0' <<<'$ROUTES'"
check "the resolver is the server's forwarder" grep -q '^nameserver 10.77.0.1' "/etc/netns/$C/resolv.conf"
check "IPv6 is blocked while connected (the tunnel is IPv4-only)" bash -c \
  "ip netns exec $C nft list table inet shaip_client | grep -q 'meta nfproto ipv6 reject'"
check "the tunnel interface MTU is 1370 (no outer fragmentation)" bash -c "ip -n $C link show pqc0 | grep -q 'mtu 1370'"
check "status shows a measured RTT" grep -qE '^rtt_ms=[0-9.]+$' "$W/status"
get http://172.16.5.5/ 2 >/dev/null
check "private destinations behind the server are filtered" bash -c \
  "ip netns exec $S curl -s http://127.0.0.1:9100/metrics | grep -qE '^shaip_server_filtered_packets_total [1-9]'"
check "the server reports 1 active session" bash -c \
  "ip netns exec $S curl -s http://127.0.0.1:9100/metrics | grep -q '^shaip_server_sessions_active 1$'"

echo "  -- resilience"
kill -TERM $SRV_PID; wait $SRV_PID 2>/dev/null
check "the client heard the server's Close" waitfor "$W/client.1.log" "tunnel down" 50
check "shaipd restarts" start_server 2
check "the client reconnected after a graceful restart" waitfor "$W/client.1.log" "tunnel up again \(reconnect #1\)" 200
check "traffic flows again" [ "$(get http://vpn-3.test:8080/)" = "caller=198.51.100.2" ]
check "the client kept its tunnel address ($TUNIP)" [ "$(status_field tunnel_address)" = "$TUNIP" ]
kill -9 $SRV_PID; wait $SRV_PID 2>/dev/null
check "shaipd restarts after a crash" start_server 3
check "the client reconnected after a server crash" waitfor "$W/client.1.log" "tunnel up again \(reconnect #2\)" 300
check "traffic flows again" [ "$(get http://vpn-4.test:8080/)" = "caller=198.51.100.2" ]

echo "  -- what the ISP's link carried (three handshakes, 16 MiB and more)"
kill -TERM "$CAP_PID"; for _ in $(seq 50); do [ -s "$W/wire.json" ] && break; sleep 0.1; done
echo "     $(cat "$W/wire.json" 2>/dev/null)"
check "no IP fragments crossed the ISP" [ "$(wire ip_fragments)" = 0 ]
check "every datagram fits a 1500-byte path (at most 1452 bytes)" [ "$(wire max_datagram)" -le 1452 ]
check "three handshakes went in 1200-byte datagrams, both ways" \
  python3 -I -c 'import json,sys; b=json.load(open(sys.argv[1]))["boot_datagrams"]; sys.exit(not (b["c2s"] >= 9 and b["s2c"] >= 6))' "$W/wire.json"
check "no datagram carries the protocol magic" [ "$(wire magic_hits)" = 0 ]
check "no byte position holds a fixed value across the client's packets" \
  python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])); n=v["data_packets"]["c2s"]; s=v["max_position_share"]["c2s"]; sys.exit(not (n >= 1000 and s < 0.03))' "$W/wire.json"
check "no byte position holds a fixed value across the server's packets" \
  python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1])); n=v["data_packets"]["s2c"]; s=v["max_position_share"]["s2c"]; sys.exit(not (n >= 1000 and s < 0.03))' "$W/wire.json"
check "the web host never saw the client's own address while connected" bash -c \
  "! tail -n +$((MARK+1)) '$W/http.log' | grep -q '^192.168.77.2 '"
check "the server's kernel holds NAT state for the client's open connections" [ "$(flows_from "$TUNIP")" -gt 0 ]

echo "  -- disconnect"
kill -TERM $CLI_PID; wait $CLI_PID 2>/dev/null
check "the client disconnected cleanly" grep -q "^disconnected:" "$W/client.1.log"
check "routes restored" bash -c "! ip -n $C route | grep -qE '0.0.0.0/1|128.0.0.0/1|^198.51.100.2'"
check "resolver restored" [ "$(cat "/etc/netns/$C/resolv.conf")" = "$ORIG_RESOLV" ]
check "firewall rules removed" bash -c "! ip netns exec $C nft list table inet shaip_client >/dev/null 2>&1"
sessions_zero() { local i; for i in $(seq 30); do [ "$(metric shaip_server_sessions_active)" = 0 ] && return 0; sleep 0.1; done; return 1; }
check "the server ended the session on the client's Close" sessions_zero
# After the lease grace (3 s here), the address's NAT state is deleted, so a
# client given the address next can never receive this client's late replies.
sleep 5
check "the freed tunnel address's NAT state was deleted" [ "$(flows_from "$TUNIP")" = 0 ]
check "direct traffic works again" [ "$(get http://after-1.test:8080/)" = "caller=192.168.77.2" ]

echo "  -- kill switch"
check "shaip run --kill-switch connects" start_client 2 --kill-switch
check "traffic goes through the tunnel" [ "$(get http://vpn-5.test:8080/)" = "caller=198.51.100.2" ]
kill -9 $CLI_PID; wait $CLI_PID 2>/dev/null
MARK=$(http_lines)
check "after the client crashes, nothing leaks out directly" [ -z "$(get http://203.0.113.2:8080/ 3)" ]
check "the web host saw no request from the client's address" bash -c "! tail -n +$((MARK+1)) '$W/http.log' | grep -q '^192.168.77.2 '"
DOWN=$(SHAIP_STATE_DIR="$W/state" ip netns exec $C "$CLI" down 2>&1)
check "shaip down lifts the kill switch and restores the resolver" bash -c \
  "grep -q 'removed the kill-switch' <<<'$DOWN' && grep -q 'restored /etc/resolv.conf' <<<'$DOWN'"
check "direct traffic works after shaip down" [ "$(get http://after-2.test:8080/)" = "caller=192.168.77.2" ]

echo "  -- the server keeps nothing about its client"
CLI_ID=$("$CLI" keygen --out "$W/cli.id" 2>/dev/null | sed -n 's/^identity_id : //p')
check "the server's logs carry no IP address at all (client, tunnel or otherwise)" bash -c \
  "! grep -hE '([0-9]{1,3}\.){3}[0-9]{1,3}' '$W'/server.*.log"
check "the server's logs never name the client's identity" bash -c \
  "[ -n '$CLI_ID' ] && ! grep -q '${CLI_ID:0:12}' '$W'/server.*.log"
check "the server's logs have no line per session" bash -c \
  "! grep -hiE 'session (established|ended)|handshake (refused|ok)|CLIENT_HELLO' '$W'/server.*.log"

echo "  VPN lab: $ok checks passed, $bad failed"
[ "$bad" -eq 0 ]
