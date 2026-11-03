# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- A server's WebSocket handshake waits on the socket's readiness rather than in blocking reads, and starts no watchdog thread. Its
  limit still bounds it in total.
- A WebTransport dialer refused by the server, as a listener's admission refuses a source, fails with `Failure::Permission` rather
  than `Failure::PathLost`. `connect` therefore no longer falls back to WebSocket after such a refusal. The refusal is QUIC's
  CONNECTION_REFUSED, which any QUIC server may send and anyone who saw the client's first packet can forge.
- Breaking for a Dart class that implements these: `WebDatagrams.changes` and `DatagramWebChannel.carriedSignals` are new abstract members.

### Fixed

- A busy WebSocket on Windows no longer dies with `Failure::PathLost` or loses bytes. A worker polled its socket with a read timeout, which Windows says leaves a connection in an indeterminate state, and a read could fail with OS error 997. It now waits on the socket's readiness, with `mio` under the `websocket` feature: an idle channel takes no CPU and a message no longer waits for a poll to be sent.
- `close` no longer hangs when a channel's failure cannot reach a reader who is behind.
- A WebSocket dialer refuses `ws://` beyond loopback before connecting, so the refusal is always `Failure::Permission` and the server
  sees no connection. It used to connect first, and an unreachable address gave `Failure::Timeout` instead.
- A WebTransport dialer given a host name that resolves to both address families reaches a listener on either. It dialled only the
  first address, so `localhost` resolving to `::1` first timed out against a listener on `127.0.0.1`. It now tries each address, the
  families taking turns, a new attempt every 250 ms beside those still opening, and takes the first to open; a failure that is not
  about the path ends the dial at once.
- A WebSocket `send` after its worker ended answers `Failure::PathLost`. It answered `Failure::NoProgress` when what the worker left
  queued still filled `Limits::queued_bytes`, which read the same as a full queue.
- A WebSocket peer sending a message over the reader's bound no longer kills the worker in a debug build (tungstenite's
  `assertion failed: self.in_buffer.capacity() > len`), and in a release build no longer reads its own full buffer as the peer
  resetting. Either way the socket closed with bytes unread, and the reset made the peer's sends `Failure::PathLost`. The worker
  read through tungstenite again after a read had failed, while closing. It now never does: it closes with code 1009 (1002, 1003
  or 1007 for a broken wire), discards what the peer still sends until the peer closes, and the peer reports `Failure::Protocol`
  to its reader and to its senders.
- A WebSocket whose reader stops for longer than twice `Limits::idle` is no longer taken for gone by either end. The end not
  reading counted the silence it could not hear and ended with `Failure::NoProgress`; it now pings the peer every `idle` instead.
  Its worker sleeps until the reader takes a message rather than waking every 10 ms.
- A busy WebSocket sender reads between every 256 KiB it writes, rather than after as many as 256 queued messages, so a peer's
  close or ping is heard while large messages keep coming.

### Added

- `Channel::peer_certificates`: the DER chain the peer presented and this side's rustls configuration accepted, on a TLS WebSocket and on
  WebTransport, the server's on a client and the client's on a server that asked for one. `None` by default, on a plain WebSocket, and
  when the peer presented none.
- `websocket::Pending::peer_addr` and `webtransport::Pending::peer_addr`: the source address `Listener::next` admitted, which on a
  `webrtc::Port` is the client's rather than its relay's.
- `Channel::set_max_receive` and `Channel::set_max_send` bound what a channel reads and what it sends apart, so a side reading under
  a small limit can still answer up to its peer's. `set_max_message` still sets both. The defaults ignore them, as it does.
- `Channel::send_timeout` waits up to a caller's timeout for room rather than refusing, and answers `Failure::Timeout`, with nothing
  sent and the channel usable, when there was none. On a WebSocket it waits behind `Limits::queued_bytes` with no polling: the worker
  wakes a waiting sender as it takes a message or ends. On WebTransport it replaces `Limits::send` for that call, and a wait that
  ends after part of the message went ends the stream with `Failure::NoProgress`. The default sends at once.
- `Cancel`, from `websocket::Pending::canceller` and `webtransport::Pending::canceller`: abandons a server's handshake from another
  thread, before or while `Pending::handshake` runs, which then returns `Failure::Cancelled` and closes the connection. A cancel after
  the handshake finished does nothing.
- Plain WebSocket beyond loopback by a deliberate choice: `websocket::Listener::bind_plain`, which binds any address with no TLS, and
  `websocket::Dialer::with_plain_beyond_loopback`. Each reports the choice in `plain_beyond_loopback()` and in its `Debug`.
  `Listener::bind` with no TLS, a dialer without the choice and `Endpoints` still refuse it.
- Dart: `StagedChannel.nextSetupBytes` gives a setup message as its bytes, so a peer proof with a binary handshake, such as Noise's, runs on a staged channel. `nextSetupMessage` still decodes text, and the wire is unchanged.
- A ladder of datagrams: WebTransport's own, a WebRTC data channel on the same UDP port, then inside the WebSocket, behind the new `webrtc` feature in Rust and `DataChannelSettings` in Dart, both off by default. `webrtc::Port` shares one UDP port between an unmodified `wtransport` listener and data channels, by the first byte of each packet. A WebSocket with `Dialer::with_webrtc` and `Listener::with_webrtc` starts with its datagrams in the stream, offers over the channel it already has, and switches when the data channel opens. `Datagrams::delivery` and `max_size` follow the path, `path_changes` (Dart: `changes`) reports each switch, one over the limit is refused rather than moved, and if UDP is blocked only the attempt is lost. `Signaling::ByCaller` (Dart: `carriedSignals`) leaves the offer and answer to a caller, to carry inside a proven link, and then nothing tagged inside the WebSocket is taken while the data channel is open. A data channel answers checks only from its WebSocket peer's address and holds to the source its peer nominated; one IP address holds a share of relays and data channels; a relay is kept by a finished WebTransport handshake and ends with its connection.
- Raw datagrams beside a channel's messages: `Channel::datagrams` and `Datagrams` in Rust, `datagramsOf` and `WebDatagrams` in Dart. WebTransport's are the session's own. A WebSocket carries them as tagged binary messages when the client asks with `with_datagrams` and the server agrees, and `delivery` says which a caller has. Nobody is sent a tag they did not ask for.

### Added

- Reliable message channels over WebTransport and WebSocket, in Rust and Dart, with explicit endpoints,
  a fallback policy that never downgrades after a security failure, and shared wire vectors.
