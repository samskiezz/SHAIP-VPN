# Exposure safeguards

Implementation date: 2026-10-17. These changes harden the existing single-hop
VPN. They do not implement the 50 proposed integrations or guarantee anonymity.

## Implemented behaviour

| Surface | Before | Now |
|---|---|---|
| Linux `pqanon run` | Kill switch required an extra flag | Enabled by default; installed before the first handshake, after endpoint resolution |
| Handshake / network setup failure | Protection could be removed during setup cleanup | Once installed, kill switch remains closed; routes and DNS are restored on ordinary error cleanup |
| Full-tunnel readiness | Echo servers or absent pushed DNS could proceed | Rejects missing/unusable client address, invalid prefix, or missing/off-subnet/self/network/broadcast DNS; no implicit system-DNS fallback |
| Reconnect | Changed DNS/prefix or failed address setup could leave stale settings | Stops on incompatible parameters or address/route application errors; kill switch stays closed |
| Desktop Connect | Checking that a binary exists could imply connection | Owns `pqanon run`; requires a fresh private status from that child, an authenticated server identity, full routing, tunnel DNS, IPv6 blocking and kill switch |
| Desktop status | No process-backed protection proof | Expired, malformed, duplicate, foreign-PID and old-format status is unverified; exited engine is never connected |
| Android | Empty VPN interface could be mistaken for protection | Connect disabled, service refuses to manufacture a connected state, explicit “Not protected” message |
| Browser instrument UI | A browser toggle could display “secured”, armed kill switch and zero threat counters without a VPN | Live VPN controls unavailable; preview-only animation carries a persistent simulation notice; absent telemetry is unverified, not zero threats |
| iOS / native FFI | Successful handshake could be mistaken for a routed server | Shared full-tunnel parameter check before applying settings; reconnect rejects lost/changed DNS or prefix |
| Web / desktop / Android account API | Remote cleartext or redirect handling could expose credentials | Remote HTTPS required, automatic redirects disabled; local development exception only |
| Private file writes | Predictable temp name could follow a symlink | Exclusive temp creation with mode 0600 on Unix, fsync, atomic replacement |

Status is local engine evidence, not an independent external leak test. It is
not uploaded as a connection receipt. Older engines intentionally cannot produce
a verified desktop connection with this GUI.

## Linux use

Build the updated CLI and desktop together:

```sh
cargo build --release -p pqanon-client --bin pqanon
cargo build --release --manifest-path clients/desktop/Cargo.toml
```

The operator-issued client TOML must contain pinned server keys, a working
endpoint and identity configuration. The server must provide routed IPv4 and a
resolver in the assigned tunnel subnet; echo mode remains suitable for `probe`
and protocol tests, not full-tunnel operation.

```sh
sudo ./target/release/pqanon run --config /absolute/path/client.toml
sudo ./target/release/pqanon disconnect
# After a failed start/crash, inspect the cause. Explicitly release blocking:
sudo ./target/release/pqanon down
```

`disconnect`/Ctrl-C explicitly restores normal networking. Startup, pump and
monitor failures leave a successfully installed kill switch closed. This blocks
the host's ordinary outbound connections, including remote administration
replies; validate on a test host with console access before using it on a server.
Failure to install nftables protection aborts startup and cannot promise blocking.

Desktop uses `PQANON_ENGINE` (default `pqanon` on PATH), `PQANON_CONFIG` or the
config path field, and `SHAIP_API`. The engine inherits the launching user's
privileges; this change adds no privileged broker or automatic elevation. Linux
requires network administration privileges, `/dev/net/tun` and nftables. Desktop
VPN operation on Windows/macOS is explicitly unavailable.

The CLI retains explicit opt-outs (`--kill-switch=false`, `--keep-dns`,
`--split-tunnel`, `--allow-ipv6-leak`). Their combinations may block traffic or
reduce protection; the desktop will not verify such a session as protected.

Remote account API bases must use HTTPS. Web and desktop allow exact loopback
HTTP for development; Android permits emulator/loopback HTTP only in debug
builds. Redirects fail rather than forwarding account credentials. Serve the web
page itself over HTTPS too: URL checks cannot protect a page delivered over HTTP
against modification in transit.

## Remaining exposure and work

- A single-hop gateway sees the source IP and the destination IPs. Destination
  services see the exit IP and may identify users through logins/fingerprints.
  HTTPS is still required for end-to-end application confidentiality.
- Endpoint hostname resolution occurs before the bootstrap firewall. Use an
  operator-issued numeric endpoint with pinned keys to avoid that bootstrap DNS
  query. This change does not add private discovery or ODoH.
- Padding, mix routing, multi-operator trust separation and relay-only peer
  access from the proposed list are not implemented. Performance features such
  as multipath, batching and FEC would not establish anonymity by themselves.
- Android still needs an actual JNI session/packet pump, routes, DNS, foreground
  lifecycle and network/device tests. A native crypto self-test is not a VPN.
- iOS Network Extension changes require an Xcode/device build and leak testing.
  This Linux environment cannot verify that integration or Apple platform bypass
  behaviour. Include-all-networks/always-on policy is a separate deployment task.
- CLI enrollment/payment HTTP helpers are outside this account-client change;
  use HTTPS endpoints. No claim is made that every repository network request
  has been hardened.
- Firewall configuration is host-wide and assumes one Linux tunnel owner.
  Multiple simultaneous engine instances, pre-existing policy conflicts,
  privileged local attackers and external firewall changes need separate handling.
- No independent security audit or live network isolation test was performed
  for this patch. Unit tests cannot prove real egress behaviour.

## Reproduce checks

```sh
RUST_MIN_STACK=16777216 cargo test --workspace --lib --bins --locked
cargo test --manifest-path clients/desktop/Cargo.toml --locked
cc -std=c11 -Wall -Wextra -Werror -Iffi/include -fsyntax-only ffi/tests/smoke.c
cd web-ui
npm ci
npm run test:transport
npm run typecheck
npm run build
```

Run `scripts/e2e/vpn_lab.sh` on a disposable Linux host with the required network
privileges to verify fail-closed egress, DNS and IPv6 on real TUN interfaces.
Test failed first handshake, missing DNS, setup error, daemon crash and reconnect
parameter changes as well as successful traffic. The existing loopback integration
tests stalled waiting for daemon startup logs in this environment; they were
stopped, not counted as passing. Android Gradle bootstrap was blocked by network
access; no new APK or IPA was produced.
