# Client API: `pqanon::client`, `pqanon::supervisor` and the C ABI (`pqanon-ffi`)

Every front end runs the same connection code. The CLI's VPN (`pqanon run`) and
native apps (through the C ABI's `pqanon_session_*`) use the reconnecting link,
`pqanon::supervisor::ManagedTunnel`. The connectivity check (`pqanon probe`) uses
one bare `pqanon::client::Tunnel`.

## `pqanon::supervisor` (Rust): a link that stays up

```rust
use pqanon::supervisor::{ManagedTunnel, SupervisorConfig};

let link = ManagedTunnel::start(SupervisorConfig::new(client_config)).await?; // first handshake, or its error
link.send(&ip_packet).await;          // dropped (and counted) while reconnecting, never sent elsewhere
let pkt = link.recv().await?;         // across reconnects; Err only once stopped
let st = link.status();               // state, SessionInfo, RTT, totals, reconnects, rekeys, last error
link.reconnect_now("network changed");
link.stop().await;                    // sends Close
```

It pings every 10 s (the RTT comes from the PONG), treats 35 s without an
authenticated packet as a dead session, reconnects with exponential backoff, and
rekeys every 20 minutes (or before either direction nears its nonce limit) with a
fresh handshake on a new socket, switching over once the server confirms it. A
`Close` from the server (it is shutting down) triggers an immediate reconnect.
`server/tests/supervisor.rs` runs it against the real `pqanond` through a
graceful restart, a crash, a silent hang (only the dead-peer timer can catch
that), and a rekey.

## `pqanon::client` (Rust)

```rust
use pqanon::client::{ClientConfig, Tunnel};

let tunnel = Tunnel::connect(ClientConfig {
    server: "vpn.example.com:443".into(),
    server_pub,                 // pinned: `pqanond --identity <f> --print-public`
    identity,                   // pqanon::keystore::load_or_create_identity(..)
    device_cert: Some(cert),    // from `pqanon enroll`, for device-bound servers
    handshake_timeout: Duration::from_secs(10),
}).await?;

tunnel.send(&ip_packet).await?;      // seal + morph + send one IP packet
let pkt = tunnel.recv().await?;      // next IP packet (cover/control skipped)
tunnel.info().assigned_v4;           // the address the server assigned (TUN mode)
tunnel.stats();                      // packets/bytes sent/received, dropped
```

`send` and `recv` take `&self`, so one task can send while another receives.
That is the shape of every TUN or packet-flow loop.

### Session confirmation

Previously the server sent nothing after CLIENT_FINISH. A client could not tell
"admitted" from "silently refused", and its first data packet would just draw a
TLS decoy reply. Now `pqanond`, on establishing a session, sends one **sealed
ACK** (`MsgType::Ack`, morphed like DATA). `Tunnel::connect` returns only after
it arrives, which proves two things:

- the server derived the same keys (key confirmation);
- the server **admitted this client**. A device-bound server drops an unenrolled
  or revoked device, which then fails with a clear error: *"the server did not
  confirm the session … not admitted (e.g. an unenrolled or revoked device)"*.

The ACK carries `SessionInfo`: the tunnel address the server assigned, the
prefix and the gateway, and (ACK v2) the resolver to use inside the tunnel, the
interface MTU (1370), and whether the server answers keepalives. A v1 ACK from an
older server still decodes. In TUN mode the server routes return traffic by the
address it allocated, and a client keeps the same address across reconnects and
rekeys. Handshake messages are retransmitted with backoff until answered; the
server replies to a repeat from its cache, so a retransmit never forks the
handshake.

## C ABI (`ffi/include/pqanon.h`)

The `pqanon-ffi` crate builds `libpqanon_ffi.a` (static, e.g. for an iOS/macOS
Network Extension) and `libpqanon_ffi.so` (Android JNI, Linux; `.dylib`/`.dll`
elsewhere). `ffi/include/module.modulemap` lets Swift `import PQAnonFFI`.

The reconnecting session, which is what an app should use (the iOS Packet
Tunnel extension in `clients/ios/SHAIPTunnel` does exactly this):

```c
char *err = NULL;
PqanonSession *s = pqanon_session_start("vpn.example.com:443", ml_dsa_hex, ed_hex,
                                        identity_path, cert_path_or_NULL, 15000, &err);
if (!s) { show_error(err); pqanon_string_free(err); return; }

PqanonStatus st;
pqanon_session_status(s, &st);       /* assigned_ipv4, prefix_len, dns_ipv4, mtu → OS tunnel settings */

/* the packet loops: one thread sends, another receives */
pqanon_session_send(s, pkt, len);                                   /* dropped while reconnecting */
long n = pqanon_session_recv(s, buf, PQANON_MAX_PACKET, 250, &err); /* >0 packet, 0 timeout, -1 stopped */

pqanon_session_reconnect(s);         /* the device changed networks */
pqanon_session_status(s, &st);       /* state, rtt_us, stats, reconnects, rekeys, server_identity */

pqanon_session_stop(s);              /* Close; the receiver's next call returns -1 */
/* …once no thread is inside a pqanon_session_* call: */
pqanon_session_free(s);
```

Handshakes run on a dedicated 16 MiB-stack thread inside the library (ML-DSA-65
needs more stack than iOS gives secondary threads), so any caller thread is fine.

One bare session (no keepalive or reconnect), for probes and tests:

```c
char *err = NULL;
PqanonTunnel *t = pqanon_tunnel_connect("vpn.example.com:443", ml_dsa_hex, ed_hex,
                                        "/data/pqanon/client.id", "/data/pqanon/client.id.cert",
                                        10000, &err);
if (!t) { show_error(err); pqanon_string_free(err); return; }

/* the packet loop — e.g. NEPacketTunnelFlow or the VpnService fd */
pqanon_tunnel_send(t, pkt, len, &err);
long n = pqanon_tunnel_recv(t, buf, PQANON_MAX_PACKET, 1000, &err); /* >0 packet, 0 timeout, -1 error */

pqanon_tunnel_close(t);
```

Enrollment from a deep-link handler:

```c
char *account = NULL;
if (pqanon_enroll_link_verify(link, PINNED_AUTHORITY_HEX, &account, &err) == 0) {
    /* show "Add this device to <account>?" — then: */
    char *device_id = pqanon_enroll(link, CP_URL, PINNED_AUTHORITY_HEX, PINNED_CA_HEX,
                                    "/data/pqanon/client.id", "Pixel 9", &err);
}
```

Guarantees:
- **NULL-safe and panic-safe.** A Rust panic becomes an error return and never
  unwinds into C.
- **Errors are strings.** On failure, `*err` receives a heap-allocated message.
  It and every returned string are released with `pqanon_string_free`.
- **One sender and one receiver** may use a tunnel concurrently.
- **The header cannot fall behind.** A Rust test fails if any exported function
  is missing from `pqanon.h`.

Link a static build with the libraries `cargo rustc -p pqanon-ffi --lib
--crate-type staticlib -- --print native-static-libs` reports. On Linux that is
`-lgcc_s -lutil -lrt -lpthread -lm -ldl -lc`.

## Tested

- `server/tests/client_loopback.rs` drives the **real `pqanond` binary** over
  loopback: confirmed sessions with byte-identical packets and exact stats; 200
  packets with concurrent send/recv; another server's (valid) keys refused at
  SERVER_HELLO; a device-bound server not confirming a client with no
  certificate.
- Battery stage `tunnel` (the real Go control plane plus a real device-bound
  `pqanond`):
  - `smoke.c` is compiled with `-Wall -Wextra -Werror` against the header and
    linked with the static library; it drives the bare tunnel and the session
    API, including a measured RTT, the server identity, a forced reconnect, and
    stop/free;
  - an enrolled device is admitted via `pqanon probe` **and** via the C program;
  - an unenrolled identity is refused;
  - after revocation, the same device is refused once the daemon refreshes its
    CRL (it is refused, and the server logs nothing about it);
  - in **TUN mode**, `pqanon probe` sends ICMP echo requests through the tunnel,
    and the server's **kernel** answers. Three checksum-valid echo replies come
    back from the gateway, to the address assigned in the ACK.

- Battery stage `ios`: the iOS app's own Swift over this ABI
  (`clients/ios/FFI`) is compiled on Linux against the header and module map,
  linked with the static library, and run against a live `pqanond` in the
  extension's call order (`clients/ios/FFIInterop`).

## Not done here

- **The native shells themselves.** The iOS app is written but needs Xcode to
  build; Android and Windows shells don't exist yet. Their packet loops are the
  ones above.
