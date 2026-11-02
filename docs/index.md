# coqui-web

A reliable message channel a browser can open natively, and the native peer for it. WebTransport first, WebSocket as an explicit
fallback. The library knows nothing of the application above it and proves nothing about who the peer is.

!!! note "Alpha"
    Not published yet: the API may change in any release before 1.0.

## The wire

- **WebTransport**: one reliable bidirectional stream the client opens. Each message is a little-endian `u32` body length, then
  the body. Non-empty, at most 1 MiB unless the application chooses otherwise. Raw datagrams may go beside it.
- **WebSocket**: one application message per WebSocket message, with no prefix. Text by default.

`vectors/frames.json` holds the wire as data; the Rust and Dart suites both run it.

## A channel is open, not trusted

`connect` returns `Unverified`. Run the peer's identity proof on it before any application message. A URL, a host name or TLS alone
proves no peer. In Dart, `StagedChannel` holds early messages for that step.

## Raw datagrams

A WebTransport channel also carries the session's own datagrams, with no framing of this library's: `channel.datagrams()` in Rust and `datagramsOf(channel)` in Dart. They can be lost, reordered or repeated. A WebSocket has none, so on a fallback those calls answer nothing rather than quietly using a stream, and a caller decides there what to do without them.

- **Size:** `max_size` says what fits now, and it can change with the path. Larger is refused, and leaves the channel usable.
- **Loss:** nothing reports what the network lost, so a caller that needs to know numbers its own. A reader that falls behind loses them too: Rust counts those in `dropped`, and a browser keeps its own small queue and does not say.
- **Identity:** a peer proof covers messages. Datagrams are outside it, so TLS is all that protects them, and a channel that seals its messages has no datagrams unless it says how it seals them.

[Choosing a transport](fallback.md) explains when another transport may be tried.
