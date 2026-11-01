# coqui-web

A reliable message channel a browser can open natively, and the native peer for it. WebTransport first, WebSocket as an explicit
fallback. The library knows nothing of the application above it and proves nothing about who the peer is.

!!! note "Alpha"
    Not published yet: the API may change in any release before 1.0.

## The wire

- **WebTransport**: one reliable bidirectional stream the client opens. Each message is a little-endian `u32` body length, then
  the body. Non-empty, at most 1 MiB unless the application chooses otherwise. No datagrams.
- **WebSocket**: one application message per WebSocket message, with no prefix. Text by default.

`vectors/frames.json` holds the wire as data; the Rust and Dart suites both run it.

## A channel is open, not trusted

`connect` returns `Unverified`. Run the peer's identity proof on it before any application message. A URL, a host name or TLS alone
proves no peer. In Dart, `StagedChannel` holds early messages for that step.

[Choosing a transport](fallback.md) explains when another transport may be tried.
