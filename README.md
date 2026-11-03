# coqui-web

[![Version](https://img.shields.io/crates/v/coqui-web.svg)](https://crates.io/crates/coqui-web)
[![Rust version](https://img.shields.io/crates/msrv/coqui-web.svg)](https://crates.io/crates/coqui-web)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-web/blob/main/LICENSE)
[![Docs](https://img.shields.io/docsrs/coqui-web)](https://docs.rs/coqui-web)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-web/test.yml)](https://github.com/Boriken-Dev/coqui-web/actions/workflows/test.yml)

**Reliable message channels a browser can open natively, and their native peers.** WebTransport first, WebSocket as an explicit
fallback, and a policy that never downgrades after a security failure. It knows nothing of the application above it, and it
proves nothing about who the peer is: identity is a separate step, on the channel it hands you. Documentation:
<https://boriken-dev.github.io/coqui-web/>.

## Features

- A `Channel` of whole, ordered messages, readable and writable from different threads.
- `connect`: WebTransport first, WebSocket when the path fails or the server does not offer it. A certificate, proof or permission failure never falls back, and a
  pinned endpoint never downgrades.
- Validated `Endpoints`: explicit URLs, one host, no credentials or query, plain WebSocket only on loopback by opt-in.
- Blocking drivers for WebTransport and WebSocket, with a bound on every size and handshake.
- Raw datagrams beside the messages, on a ladder: WebTransport's own, a WebRTC data channel on the same UDP port (`webrtc` feature), then
  inside the WebSocket. A blocked UDP path costs only the attempt.
- The same wire in Rust and Dart, held together by shared vectors.

What belongs here: a channel a browser can open natively. An HTTP client, a web framework or an application protocol does not.

## Installation

```sh
cargo add coqui-web --features websocket
```

| Feature | Adds | Default |
| --- | --- | --- |
| `websocket` | `websocket::{Dialer, Listener}`, on `tungstenite`, `rustls` and `mio` | off |
| `webtransport` | `webtransport::{Dialer, Listener}`, on `wtransport`, with a small runtime inside the driver | off |
| `webrtc` | `webrtc::Port`, and a WebSocket channel that climbs onto a data channel on it, on `str0m`. Implies the other two | off |

The Dart package is in `bindings/dart/coqui_web`.

## Quick start

```rust
use coqui_web::{Endpoints, Failure, Kind, Phase, Recovery};

// One address: WebTransport on its UDP port and WebSocket on its TCP port, the same number.
let endpoints = Endpoints::builder()
    .address("https://peer.example/channel")
    .build()?;
assert!(endpoints.webtransport().is_some());

// A path failure may fall back, once the same peer is proven again. A rejected certificate never does.
assert_eq!(Failure::Timeout.recovery(Kind::WebTransport, Phase::Opening, true), Recovery::VerifyFallback);
assert_eq!(Failure::Certificate.recovery(Kind::WebTransport, Phase::Opening, true), Recovery::Deny);
# Ok::<(), coqui_web::EndpointError>(())
```

## API overview

| Module | Purpose |
| --- | --- |
| root | `Channel`, `Dialer`, `connect`, `Unverified`, `Endpoints`, `Failure`, `Recovery`, `Limits` |
| `frame` | the stream wire format, with no I/O |
| `websocket` | the WebSocket driver |
| `webtransport` | the WebTransport driver |
| `webrtc` | one UDP port for WebTransport and data channels |

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
(cd bindings/dart/coqui_web && dart analyze && dart test)
```

### Releasing

A `v*` tag runs the tests and the strict docs build, then creates the release from `CHANGELOG.md`. Nothing is published to a
registry yet: `publish = false` until a release is chosen.

## License

MPL-2.0; see [LICENSE](https://github.com/Boriken-Dev/coqui-web/blob/main/LICENSE).
