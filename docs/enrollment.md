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

## Not wired here / out of scope in this container

The security-critical core — the signed token and certificate, their encoding,
and verification — is complete and tested. The surrounding delivery is ordinary
plumbing, and some of it cannot be built or tested in this Linux CI container:

- **Control-plane issuance endpoints** (`/enroll/issue`, `/enroll/claim`) and the
  `devices` table: issuing a token for an authenticated account, accepting a
  device public key, recording the binding, and enforcing one-time use. This is
  DB + HTTP plumbing on top of the issuer already implemented in Go.
- **Native deep-link handlers** (iOS/macOS/Windows/Android/Linux registration of
  the `pqanon://` scheme) and **QR scanning**: these are per-OS, and cannot be
  compiled, signed, or tested here. The URL *formatting and parsing* are done and
  tested (`enroll_url` / `parse_enroll_url`); only the OS registration is absent.
- **Web device-management UI**: listing and revoking a device's certificate is a
  view over the control-plane endpoints above.
