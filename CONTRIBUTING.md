# Contributing

## Build & test

```
make test     # cargo test --workspace  +  go vet/test
make build    # release binaries + control plane + web build
cargo clippy --workspace --all-targets   # must be warning-free
cargo fmt --all
```

The bar for merge: `cargo test --workspace` green, `cargo clippy` warning-free,
`go vet ./...` clean, and `npx tsc --noEmit` clean in `web-ui/`.

## Commit style

Conventional Commits: `type(scope): subject`, e.g.
`feat(transport): add tail-loss probe`, `fix(obf): correct length reconstruction`.

## Pull requests

- One logical change per PR, with tests.
- Update `README.md` / docs if behavior changes.
- Run the full suite before pushing.

## Where to start

`README.md` lists the known limitations (TUN loop, cover-traffic driver, mix
delay queue + Bloom filter, rekey driver, anti-probing cookie path). Those are
the next integration slots; several build directly on the tested primitives in
`client/src/` (e.g. `dns_cache`, `stream`, `reconnect`, `mix_delay`,
`mix_reputation`).
