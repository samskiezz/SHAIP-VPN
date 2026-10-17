# Key custody and HSM support

Every long-term key in SHAIP VPN is either **persistent** (a key file or an HSM)
or explicitly **ephemeral** with a warning in the log. A key that silently
changes on restart breaks whoever pinned it, so the defaults below exist to make
that failure loud.

## Control-plane signing keys (Go)

| Key | Signs | Pinned by | Resolve with |
|---|---|---|---|
| `token` | API bearer tokens | the control plane itself (and its replicas) | `TOKEN_SIGNER`, or legacy `TOKEN_SIGNING_KEY` |
| `crl` | the signed CRL (`/api/crl`) | tunnel servers | `CRL_SIGNER` |

Each is an Ed25519 key resolved by `control-plane/keys.go`, in this order:

1. `<NAME>_SIGNER` — an explicit key spec (below);
2. the legacy base64-seed variable, where one exists (`TOKEN_SIGNING_KEY`);
3. `$KEY_DIR/<name>.key` — created 0600 on first boot when `KEY_DIR` is set;
4. otherwise an **ephemeral** key and a `WARNING` line.

A malformed spec fails startup; it never falls back to an ephemeral key.

### Key specs (`control-plane/keystore`)

```
file:/var/lib/pqanon/keys/crl.key     Ed25519 seed file (base64 or 32 raw bytes);
                                      created 0600; refused if group/world-accessible
env:TOKEN_SIGNING_KEY                 base64 32-byte seed in an environment variable
pkcs11:token=<label>;object=<label>?module-path=<.so>&pin-env=<VAR>[&create=1]
                                      key inside a PKCS#11 token (HSM)
ephemeral                             in-memory key (dev/tests only)
```

Every backend is a standard Go `crypto.Signer`, and every signature is checked
against the signer's public key before use (`keystore.Sign`). A misconfigured
backend — the wrong curve, or a prehash mode — therefore fails loudly instead of
producing artifacts nobody can verify. The enrollment issuer and the directory
authority take a `crypto.Signer` too, so their keys can live in an HSM the same
way.

### HSM (PKCS#11)

The PKCS#11 backend uses the PKCS#11 3.0 Edwards mechanisms
(`CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA`). With `create=1` it generates the
keypair **on the token**, with the private half marked sensitive and
non-extractable. The control plane can then ask the token to sign, and nothing
can read the key out. On open it signs a self-test message and verifies it.

```bash
# Example with SoftHSM2 (a software token that speaks real PKCS#11):
softhsm2-util --init-token --free --label pqanon --pin "$PIN" --so-pin "$SO_PIN"
export PQANON_HSM_PIN="$PIN"
export CRL_SIGNER='pkcs11:token=pqanon;object=crl?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-env=PQANON_HSM_PIN&create=1'
./control-plane      # logs: signing keys: token=... crl=pkcs11:token=pqanon;object=crl?...
```

For a hardware HSM, use the vendor's module path. The PKCS#11 backend needs a
**cgo** build (`CGO_ENABLED=1`) on an image that ships the module. The default
container image is a static `CGO_ENABLED=0` build. It rejects `pkcs11:` specs
with a clear error and supports every other backend.

**Tested:** the master battery's `hsm` stage provisions a throwaway SoftHSM2
token. It runs the keystore's PKCS#11 test, failing if that test was skipped
rather than run. The test covers a wrong PIN, generate-on-token, a pure-Ed25519
signature check, persistence, non-extractability, and issuing a real enrollment
token. The stage then boots the live control plane with its token and CRL keys
inside the HSM, logs in, and restarts. The old login token still verifies and
the CRL key is unchanged.

### Not in the HSM

- **E-cash denomination keys** are RSA blind-signing keys (RFC 9474, via CIRCL),
  which need the raw private key. They live in `PAY_KEY_DIR`, which defaults to
  `$KEY_DIR/mint` when only `KEY_DIR` is set.

## Daemon and client identities (Rust)

| Binary | Flag | Key |
|---|---|---|
| `pqanond` | `--identity <file>` | hybrid ML-DSA-65 + Ed25519 server identity |
| `pqanond` | `--print-public` | prints `identity_id`, `server_ml_dsa_pub`, `server_ed_pub` — the client's `[server]` pins — and exits |
| `pqanon-mixd` | `--key <file>` | X25519 onion key (published in the directory) |
| `pqanon` | `keygen --out <file>` / `[client].identity` | client identity (what a server allow-lists) |

The files are created 0600 on first run. They are refused if group- or
world-accessible, and every load is validated: an identity load re-signs and
verifies a probe, so a corrupt or spliced file is rejected at startup.

These keys use files, not PKCS#11, because the identity's post-quantum half is
**ML-DSA-65**. PKCS#11 only gained ML-DSA mechanisms in v3.2, and no token
available here (SoftHSM2 2.6) implements them.
