# coqui-transport-web

[![Version](https://img.shields.io/crates/v/coqui-transport-web.svg)](https://crates.io/crates/coqui-transport-web)
[![Rust version](https://img.shields.io/crates/msrv/coqui-transport-web.svg)](https://crates.io/crates/coqui-transport-web)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-transport-web/blob/main/LICENSE)
[![Docs](https://img.shields.io/docsrs/coqui-transport-web)](https://docs.rs/coqui-transport-web)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-transport-web/test.yml)](https://github.com/Boriken-Dev/coqui-transport-web/actions/workflows/test.yml)

**Reliable message channels a browser can open natively, and their native peers.** WebTransport first, WebSocket as an explicit
fallback, and a policy that never downgrades after a security failure. It knows nothing of the application above it, and it
proves nothing about who the peer is: identity is a separate step, on the channel it hands you. Documentation:
<https://boriken-dev.github.io/coqui-transport-web/>.

## Features

- A `Channel` of whole, ordered messages, readable and writable from different threads, with its own bound on each direction. A
  change to the read bound can be staged by position: the next message under a small bound, everything after it under the full one,
  however far the driver reads ahead. How far it reads ahead is set per channel, so a peer not yet proved can be held to one message.
- A send that waits for room as long as its caller says, rather than being refused when the queue is full.
- `connect`: WebTransport first, WebSocket when the path fails or the server does not offer it. A certificate, proof or permission failure never falls back, and a
  pinned endpoint never downgrades.
- Validated `Endpoints`: explicit URLs, one host, no credentials or query, plain WebSocket only on loopback by opt-in.
- Blocking drivers for WebTransport and WebSocket, with a bound on every size and handshake, and a server handshake another thread can
  cancel.
- The certificate chain TLS accepted from the peer, on either end of a channel, for a peer proof or a pin to decide on.
- Plain WebSocket beyond loopback only by a deliberate choice, which the listener or dialer reports.
- A dialer bound to a chosen local address, so a listener's per-source rules can be tested from more than one source.
- Raw datagrams beside the messages, on a ladder: WebTransport's own, a WebRTC data channel on the same UDP port (`webrtc` feature), then
  inside the WebSocket. A blocked UDP path costs only the attempt.
- The same wire in Rust and Dart, held together by shared vectors.

What belongs here: a channel a browser can open natively. An HTTP client, a web framework or an application protocol does not.

## Installation

```sh
cargo add coqui-transport-web --features websocket
```

| Feature | Adds | Default |
| --- | --- | --- |
| `websocket` | `websocket::{Dialer, Listener}`, on `tungstenite`, `rustls`, `mio` and `socket2` | off |
| `webtransport` | `webtransport::{Dialer, Listener}`, on `wtransport`, with a small runtime inside the driver | off |
| `webrtc` | `webrtc::Port`, and a WebSocket channel that climbs onto a data channel on it, on `str0m`. Implies the other two | off |

The Dart package is in `bindings/dart/coqui_transport_web`.

## Quick start

```rust
use coqui_transport_web::{Endpoints, Failure, FailureExt, Kind, Phase, Recovery};

// One address: WebTransport on its UDP port and WebSocket on its TCP port, the same number.
let endpoints = Endpoints::builder()
    .address("https://peer.example/channel")
    .build()?;
assert!(endpoints.webtransport().is_some());

// A path failure may fall back, once the same peer is proven again. A rejected certificate never does.
assert_eq!(Failure::Timeout.recovery(Kind::WebTransport, Phase::Opening, true), Recovery::VerifyFallback);
assert_eq!(Failure::Certificate.recovery(Kind::WebTransport, Phase::Opening, true), Recovery::Deny);
# Ok::<(), coqui_transport_web::EndpointError>(())
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
(cd bindings/dart/coqui_transport_web && dart analyze && dart test)
```

### Releasing

A `v*` tag runs the tests and the strict docs build, then creates the release from `CHANGELOG.md`. Nothing is published to a
registry yet: `publish = false` until a release is chosen.

## License

MPL-2.0; see [LICENSE](https://github.com/Boriken-Dev/coqui-transport-web/blob/main/LICENSE).
