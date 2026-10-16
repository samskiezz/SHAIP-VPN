# Client API: `pqanon::client` and the C ABI (`pqanon-ffi`)

Every front end runs the same connection code. The CLI's TUN loop
(`pqanon run`), the connectivity check (`pqanon probe`), and native apps (through
the C ABI) all go through `pqanon::client`.

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
prefix, and the gateway. In TUN mode the server routes return traffic by the
address it allocated. `pqanon run` now configures its TUN device with that
address instead of trusting a static config value that could disagree.

## C ABI (`ffi/include/pqanon.h`)

The `pqanon-ffi` crate builds `libpqanon_ffi.a` (static, e.g. for an iOS/macOS
Network Extension) and `libpqanon_ffi.so` (Android JNI, Linux; `.dylib`/`.dll`
elsewhere).

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
    linked with the static library;
  - an enrolled device is admitted via `pqanon probe` **and** via the C program;
  - an unenrolled identity is refused;
  - after revocation, the same device is refused once the daemon refreshes its
    CRL (its log reads `device has been revoked`);
  - in **TUN mode**, `pqanon probe` sends ICMP echo requests through the tunnel,
    and the server's **kernel** answers. Three checksum-valid echo replies come
    back from the gateway, to the address assigned in the ACK.

## Not done here

- **The native shells themselves** (Swift/Kotlin/C# apps that host this ABI)
  cannot be built, signed or run in this Linux container. The ABI they call is
  built and exercised from C here.
- **Handshake retransmission and fragmentation.** Like `pqanon run` before it,
  `connect` sends each handshake message once. On lossy paths a lost datagram
  means a timeout and a fresh `connect`, which uses a new socket and so a fresh
  server-side handshake. Real-path hardening needs idempotent SERVER_HELLO
  caching and fragmentation of the ~7 KB handshake messages; see the README's
  known limitations.
