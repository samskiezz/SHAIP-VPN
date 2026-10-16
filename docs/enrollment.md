# Device enrollment and binding (§ infrastructure)

One-click enrollment adds a device to an account and binds its identity key,
using two signed artifacts:

1. An **enrollment token** — issued by an operator, delivered to the device out
   of band (a QR code or a `pqanon://enroll?t=…&v=1` deep link). It authorizes
   one device to join one account, and is verified against a **pinned
   enrollment-authority key** the client ships.
2. A **device certificate** — issued by the control plane after the device
   proves it holds a fresh identity key, binding that key to the account and
   signed by a **device-CA key** the servers pin. A server verifies it before
   admitting the device.

Both are self-contained, offline-verifiable, and carry their own validity
window. Neither requires the verifier to call back to the issuer.

## Wire format

Each artifact is `<label>.<base64url(body)>.<base64url(sig)>` with unpadded,
URL/QR-safe base64url:

| label  | artifact            | signed by               |
|--------|---------------------|-------------------------|
| `PQE1` | enrollment token    | enrollment-authority key |
| `PQC1` | device certificate  | device-CA key           |

`body` is a fully deterministic, length-prefixed binary structure (big-endian
integers). `sig` is an **Ed25519** signature (RFC 8032, pure — the body *is* the
message; Ed25519 hashes it internally, so there is no separate digest step). The
first field of every body is a domain-separation magic
(`PQANON-ENROLL-V1` / `PQANON-DEVCERT-V1`), so a signature over one artifact type
can never be reinterpreted as the other even if the outer label is swapped.

Enrollment-token body:

```
u16 len | "PQANON-ENROLL-V1"
u8      | version (1)
[16]    | token id
u16 len | account (UTF-8)
u64     | issued-at  (Unix seconds)
u64     | expires-at (Unix seconds)
u8      | flags (bit0 = one-time)
```

Device-certificate body:

```
u16 len | "PQANON-DEVCERT-V1"
u8      | version (1)
[16]    | device id
u16 len | account (UTF-8)
[32]    | device Ed25519 public key
u64     | issued-at  (Unix seconds)
u64     | expires-at (Unix seconds)
```

A deterministic binary layout is used rather than CBOR so that the signed bytes
are trivially identical across the two implementations; there is no canonical-form
ambiguity to get wrong.

## Verification

A verifier:

1. Splits `label.body.sig`, checks the label, and base64url-decodes both halves.
2. Verifies the Ed25519 signature over the body bytes with the **pinned** key
   (enrollment-authority key for `PQE1`, device-CA key for `PQC1`). This is
   checked *before* the body is interpreted.
3. Reads the body, requiring the expected magic and version and rejecting any
   trailing bytes.
4. Checks the validity window: `issued-at − skew ≤ now ≤ expires-at`, where the
   skew (120 s) applies only to the not-yet-valid boundary; expiry is strict.

The `one-time` flag is advisory to the control plane (it should accept a given
token id at most once); the token id is the de-duplication key.

## Implementations and cross-language proof

- **Issuer + verifier (Go):** `control-plane/enrollment/enrollment.go` — stdlib
  `crypto/ed25519` + `encoding/binary` + `encoding/base64`, no external deps.
- **Verifier (Rust):** `client/src/enrollment.rs` — `ed25519-dalek` + `base64`,
  no network/time deps (`now` is supplied as Unix seconds by the caller). The
  client verifies the enrollment token; the server verifies the device
  certificate; both go through this one module.

Because the body encoding is byte-exact across both, a token or certificate
signed by the Go issuer verifies in Rust unchanged. This is pinned by a shared
vector: Go's `TestCrossLanguageVector` logs a token and a certificate (with fixed
keys); the Rust `cross_language_enroll_token_verifies` and
`cross_language_device_cert_verifies` tests embed those exact strings and verify
them, including that the certificate binds exactly the device's public key. If the
format ever changes, both sides change together.

## Control-plane API

| Endpoint | Auth | Does |
|---|---|---|
| `POST /api/enroll/issue` | session | Issue a one-time token for the caller's account (default 15 min, max 24 h). Returns `token`, the `pqanon://enroll?t=…&v=1` link, and the expiry. |
| `POST /api/enroll/claim` | none (the token is the authorization) | `{token, device_pub, pop, name}` returns a device certificate (1 year). |
| `GET /api/enroll/keys` | none | `enroll_authority_pub`, `device_ca_pub`, `crl_pub` — the pins. |
| `GET /api/devices` | session | The caller's devices. |
| `DELETE /api/devices/{id}` | session | Revoke a device. It is published in the signed CRL. |

- **Proof of possession.** A claim must carry an Ed25519 signature by the device
  key over `PQANON-ENROLL-CLAIM-V1:<token>`. This proves the claimant holds the
  key being bound, so a claim cannot bind someone else's public key.
- **One-time, atomically.** Issued tokens are recorded (`enroll_tokens`). A claim
  consumes the token and inserts the device (`devices`) in one transaction. In
  Postgres a row lock serializes concurrent claims, so exactly one wins. A failed
  claim — a reused device key, a bad proof — changes nothing and does not burn the
  token. The certificate is signed *before* the claim commits, so a signing
  failure (say, an HSM error) burns nothing either.
- **No personal data in artifacts.** Tokens and certificates name the account by
  its opaque user id, never its email.
- **Keys.** The enrollment authority and the device CA are resolved like every
  other control-plane key (`ENROLL_AUTHORITY_SIGNER`, `DEVICE_CA_SIGNER`, or
  `KEY_DIR`), so both can live in an HSM — see [keys.md](keys.md).
- **Revocation.** `/api/crl` now carries `revoked_devices` inside the signed
  payload, plus `crl_b64`: the exact signed bytes, so any verifier checks what was
  signed without re-serializing JSON.

## Device side

```bash
pqanon enroll 'pqanon://enroll?t=PQE1.…&v=1' --server https://cp.example \
  --authority-key <pinned enroll_authority_pub> --ca-key <pinned device_ca_pub> \
  --identity ~/.pqanon/client.id --name laptop
#  Enrolled device 4b40…0a08 for account 21f6…b2e7
#  certificate: ~/.pqanon/client.id.cert
```

The client verifies the link against the pinned authority key **before**
contacting anyone, so a tampered or forged link is refused locally. It binds the
identity's Ed25519 key — the same key that signs every tunnel handshake. It also
checks that the returned certificate verifies under the pinned CA and binds
exactly that key to the token's account before storing it (0600). Point
`[client].device_cert` at the file and `pqanon run` presents it.
`pqanon crl --url … --pubkey <crl_pub>` fetches and verifies the revocation
list.

## Tunnel admission (device binding)

`pqanond --device-ca <device_ca_pub>` admits **only** clients that present a
valid certificate from that CA:
- the certificate must bind the same Ed25519 key that signs the handshake
  transcript, so a replayed certificate is useless without the device's key;
- it must not be expired;
- its device id must not be revoked.

With `--crl-url … --crl-pub <crl_pub>`, the daemon loads the signed CRL at
startup and refuses to start without it (fail closed). It refreshes every
`--crl-refresh-secs`. A failed refresh keeps the last verified list. A list that
is stale (more than 10 minutes old, as a replay would be) or older than the one
in force is rejected. Without `--device-ca` the daemon stays in open demo mode
and says so in its log.

The certificate travels inside CLIENT_FINISH, which is **AEAD-sealed** under a
key derived from `ss_mix`. Neither the client's long-term keys nor its
certificate (and so its account id) ever appear on the wire. This was previously
documented but not true: CLIENT_FINISH went out in plaintext. A regression test
now fails if the identity key, the certificate, or the account id is ever
visible in the bytes on the wire.

## Tested

- Go: `handlers_enroll_test.go` covers auth, the happy path, one-time use, and
  every rejection (foreign, unissued, or expired token; bad proof; short key; key
  reuse, and that failures don't burn tokens). It also covers per-account
  isolation, and that the signed CRL lists revoked devices with `crl_b64`
  identical to the served bytes.
- The **store contract** (`store_contract_test.go`) runs the same assertions
  against the in-memory store and a **real PostgreSQL** cluster (battery stage
  `postgres`). That includes a 16-way concurrent claim race, 8 rounds per run. A
  negative control with the row lock removed fails 5 runs out of 5.
- Rust: sealed CLIENT_FINISH, a tamper test, device admission, and refusal of a
  missing, foreign-key, foreign-CA, revoked, or expired certificate. CRL
  verification is tested against tampering, the wrong key, staleness and
  future-dated lists. A test-only issuer reproduces the Go certificate
  byte-for-byte.
- Battery stage `enroll` runs the real Rust CLI against the real Go control
  plane: pins, an auth gate, the deep link, a tampered link and a wrong pin
  (both refused locally), enrollment with a 0600 certificate, one-time use, the
  device list, revocation, revocation visible in the Rust-verified CRL, and the
  CRL refused under the wrong pin.

## Not done here

- **Network end-to-end of tunnel admission.** Device admission is tested
  in-process, through the real handshake state machines. `pqanond`'s CRL startup
  has been checked by hand: it refuses to start when the CRL is unreachable and
  loads it when healthy. A battery stage that connects a real client to a live
  `pqanond` (admitted, then revoked and refused) needs a userspace client, and
  lands with the `pqanon::client` facade.
- **Native deep-link handlers** (iOS/macOS/Windows/Android/Linux registration of
  the `pqanon://` scheme) and **QR scanning** are per-OS and cannot be compiled,
  signed, or tested in this Linux container. Link parsing and verification are
  done (`parse_enroll_url`, `pqanon enroll`); only OS registration is missing.
- **Web device-management UI**: a view over `/api/devices`.
