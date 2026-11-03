# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Breaking for a Dart class that implements these: `WebDatagrams.changes` and `DatagramWebChannel.carriedSignals` are new abstract members.

### Fixed

- A busy WebSocket on Windows no longer dies with `Failure::PathLost` or loses bytes. A worker polled its socket with a read timeout, which Windows says leaves a connection in an indeterminate state, and a read could fail with OS error 997. It now waits on the socket's readiness, with `mio` under the `websocket` feature: an idle channel takes no CPU and a message no longer waits for a poll to be sent.
- `close` no longer hangs when a channel's failure cannot reach a reader who is behind.

### Added

- Dart: `StagedChannel.nextSetupBytes` gives a setup message as its bytes, so a peer proof with a binary handshake, such as Noise's, runs on a staged channel. `nextSetupMessage` still decodes text, and the wire is unchanged.
- A ladder of datagrams: WebTransport's own, a WebRTC data channel on the same UDP port, then inside the WebSocket, behind the new `webrtc` feature in Rust and `DataChannelSettings` in Dart, both off by default. `webrtc::Port` shares one UDP port between an unmodified `wtransport` listener and data channels, by the first byte of each packet. A WebSocket with `Dialer::with_webrtc` and `Listener::with_webrtc` starts with its datagrams in the stream, offers over the channel it already has, and switches when the data channel opens. `Datagrams::delivery` and `max_size` follow the path, `path_changes` (Dart: `changes`) reports each switch, one over the limit is refused rather than moved, and if UDP is blocked only the attempt is lost. `Signaling::ByCaller` (Dart: `carriedSignals`) leaves the offer and answer to a caller, to carry inside a proven link, and then nothing tagged inside the WebSocket is taken while the data channel is open. A data channel answers checks only from its WebSocket peer's address and holds to the source its peer nominated; one IP address holds a share of relays and data channels; a relay is kept by a finished WebTransport handshake and ends with its connection.
- Raw datagrams beside a channel's messages: `Channel::datagrams` and `Datagrams` in Rust, `datagramsOf` and `WebDatagrams` in Dart. WebTransport's are the session's own. A WebSocket carries them as tagged binary messages when the client asks with `with_datagrams` and the server agrees, and `delivery` says which a caller has. Nobody is sent a tag they did not ask for.

### Added

- Reliable message channels over WebTransport and WebSocket, in Rust and Dart, with explicit endpoints,
  a fallback policy that never downgrades after a security failure, and shared wire vectors.
