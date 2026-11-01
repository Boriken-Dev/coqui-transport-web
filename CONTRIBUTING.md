# Contributing to coqui-web

## Licence

This project is distributed under the **Mozilla Public License 2.0** (`LICENSE`). Its copyleft is per file: using
the crate imposes nothing on your code, and a modified file must be published under the MPL 2.0.

## Contributor licence agreement

A first pull request needs a one-time signature. The bot will comment with the exact sentence to reply with; read
[`CLA.md`](CLA.md) first. You keep the copyright in everything you write.

## Before you open a pull request

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --no-default-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
(cd bindings/dart/coqui_web && dart analyze && dart test)
```

A change to the wire format changes `vectors/frames.json`, which both suites run. [`AGENTS.md`](AGENTS.md) is the
crate's API header and ships in the package; keep it current in the same commit. Files are LF, on every platform.
