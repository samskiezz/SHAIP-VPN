# PQ·ANON — Desktop client (Linux + Windows)

A native desktop client for the SHAIP / PQ·ANON post-quantum VPN, written in
Rust with `egui`/`eframe`. It carries the same glass design language as the web
UI, iOS and Android — deep-graphite gradient, translucent glass panels, cyan
signal accent, mono labels (clients/ios/design/HANDOFF.md) — and talks to the
same `PQANON-CP/1` control plane.

## What is real here

- **Cross-compiles from Linux to both a Linux binary and a Windows `.exe`** — no
  Windows machine or macOS needed:
  ```sh
  cargo build --release                                  # Linux ELF
  cargo build --release --target x86_64-pc-windows-gnu   # Windows PE32+ GUI .exe
  ```
  (The Windows build needs `rustup target add x86_64-pc-windows-gnu` and the
  `gcc-mingw-w64-x86-64` linker; see `.cargo/config.toml`.)
- **Talks to the real control plane** over the same HTTP API as the web/CLI:
  register / sign in, dashboard, the signed node directory (Servers), and the
  identity-free discount/comp-code redemption (Buy access).
- **Anonymous accounts** (16-digit number, no email); the number is never
  written to disk by this client.
- Requests run off the UI thread (native worker thread); the UI repaints when a reply lands.

## The tunnel

On Linux, Connect launches the updated `pqanon run --config FILE --kill-switch`
engine. Set `PQANON_CONFIG` to an absolute operator-issued TOML path (or enter it
on the dashboard) and `PQANON_ENGINE` to the matching CLI binary if it is not on
PATH. It inherits the current user's privileges: no privileged broker or
automatic elevation is implemented. TUN, nftables and network administration
privileges are required.

Connected requires a live owned child and a fresh private status confirming full
IPv4 routing, tunnel DNS, IPv6 blocking and kill switch. Missing/stale/old-format
status is unverified. Disconnect waits for the engine to exit; failure may leave
the kill switch closed until `pqanon down`. This is engine evidence, not an
external leak test. The Windows/macOS VPN backend is unavailable.

See [exposure safeguards](../../docs/exposure-safeguards.md) for remaining risks,
startup blocking behaviour and build/test instructions.

## Offline preview

`PQANON_DEMO=1` seeds sample infrastructure data (demo node names, a placeholder
account number — never customer data) so the signed-in screens render without a
backend; `PQANON_SCREEN=dashboard|servers|buy` picks the tab. Used for
screenshots and offline demos.

## Config

`PQANON_API` sets the control-plane base URL (default `http://127.0.0.1:8080`).
Remote hosts require HTTPS; automatic redirects are refused.

## Layout

```
src/
  main.rs    window + entry point
  theme.rs   the glass look in egui (shared tokens) + gradient painter
  api.rs     control-plane client (ureq + serde), async → UI channel
  app.rs     state, the login/dashboard/servers/buy screens, tunnel control
```
