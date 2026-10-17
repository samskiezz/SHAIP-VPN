# PQ·ANON — Android client

A native Android client for the SHAIP / PQ·ANON post-quantum VPN, built with
Kotlin + Jetpack Compose. It shares one visual language with the iOS app
(`clients/ios`) and the web UI (`web-ui`): the deep-graphite background,
Liquid-Glass cards, mono eyebrows and the cyan **signal** accent, from the same
design tokens (`clients/ios/design/HANDOFF.md`).

## What is real here

- **Builds to a real APK on Linux** — no macOS needed. `./gradlew assembleDebug`
  produces `app/build/outputs/apk/debug/app-debug.apk`.
- **Talks to the real control plane** (`PQANON-CP/1`, the Go service in
  `control-plane/`) over the same HTTP API the web UI and CLI use:
  register / sign in, dashboard, the signed node directory (Servers), device
  enrollment, and the identity-free discount/comp-code redemption (Buy access).
- **Anonymous accounts**: a random 16-digit account number is the only login;
  no email, no name. The number is never persisted to disk.
- **Privacy posture matches the other clients**: app-private storage only, and
  cloud backup / device transfer are disabled for shared-prefs, files and
  databases (`res/xml/data_extraction_rules.xml`). Cleartext is allowed only to
  the dev control plane (emulator loopback), everything else is HTTPS.
- Account requests require HTTPS for remote hosts and refuse redirects. The
  emulator/loopback HTTP exception is restricted to debug builds.

## VPN availability

**Android packet forwarding is not implemented. This app does not protect device
traffic.** The connection button is disabled and the VpnService refuses to
manufacture a connected state. The native crypto self-test only generates keys;
it does not establish a routed tunnel.

JNI session plumbing, a real packet pump, protected sockets, routes, DNS,
foreground lifecycle and device/network tests are still required. See
[exposure safeguards](../../docs/exposure-safeguards.md).

- Payments (buying blind-signed tokens) happen in the app/CLI flow; the web/pay
  screen here shows plans and redeems codes, as on web.

## Build

```sh
# Requires JDK 17+ and the Android SDK (platform 34, build-tools 34).
# Point the build at your SDK (or set ANDROID_HOME):
echo "sdk.dir=/path/to/android-sdk" > local.properties
./gradlew :app:assembleDebug
```

The control-plane base URL defaults to `http://10.0.2.2:8080` (the host
loopback as seen from the Android emulator); change it in `Session` or the
`DEFAULT_API_BASE` build-config field.

## Layout

```
app/src/main/java/net/shaip/pqanon/
  MainActivity.kt         entry point
  ui/theme/               design tokens + Compose theme (shared palette)
  ui/Glass.kt Controls.kt Layout.kt   the glass component kit
  ui/App.kt               signed-in shell + tab nav
  ui/screens/             Login, Dashboard, Servers, Devices, Pay
  net/                    control-plane API client (OkHttp + kotlinx.serialization)
  vpn/PqanonVpnService.kt the unavailable-tunnel service gate
```
