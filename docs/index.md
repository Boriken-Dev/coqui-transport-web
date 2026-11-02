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

A channel can carry raw datagrams beside its messages: `channel.datagrams()` in Rust and `datagramsOf(channel)` in Dart. They answer nothing on a channel that has none, and `delivery` says what the ones it has really are, since a caller that wants a lost packet to hold up nothing cannot get that over TCP.

| | WebTransport | WebSocket |
| --- | --- | --- |
| Has them | Always: they are the session's own | When the client asked and the server agreed |
| `delivery` | `unreliable`: lost, reordered or repeated without notice | `overStream`: in order and late rather than lost on the way, held up by anything before them |
| `max_size` | What fits a packet now, which can change with the path | A setting, 64 KiB by default, with no floor |
| Lost | On the network, unseen, or by a reader behind | Only where a queue at either end is full |

**On a WebSocket** a client asks with the subprotocol `coqui-web-datagrams.1`, and a server that agrees echoes it. Every binary message on that connection then starts with a tag: `0` and a non-empty message, or `1` and a datagram, which may be empty. Any other tag ends the channel. Text messages are unchanged. Nobody is sent a tag they did not ask for. A Rust dialer that asks a server that does not agree fails with `Failure::Unsupported`; a browser connects anyway, and `datagramsOf` then answers nothing.

- **Size:** one larger than `max_size` is refused, and leaves the channel usable. On a WebSocket one arriving larger than this side's setting is discarded and counted.
- **Loss:** nothing reports what the network lost, so a caller that needs to know numbers its own. Rust counts what it discards in `dropped`. A browser keeps its own small queue for WebTransport and does not say, and it offers no bound on what a WebSocket has waiting to send, so there only Rust discards on sending.
- **Memory:** over a WebSocket none are held until `datagrams()` is first asked for, so a peer that has proved nothing cannot fill memory that way.
- **Identity:** a peer proof covers messages. Datagrams are outside it, so TLS is all that protects them, and a channel that seals its messages has no datagrams unless it says how it seals them.

[Choosing a transport](fallback.md) explains when another transport may be tried.
