# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Raw datagrams beside a channel's messages: `Channel::datagrams` and `Datagrams` in Rust, `datagramsOf` and `WebDatagrams` in Dart. WebTransport's are the session's own. A WebSocket carries them as tagged binary messages when the client asks with `with_datagrams` and the server agrees, and `delivery` says which a caller has. Nobody is sent a tag they did not ask for.

### Added

- Reliable message channels over WebTransport and WebSocket, in Rust and Dart, with explicit endpoints,
  a fallback policy that never downgrades after a security failure, and shared wire vectors.
