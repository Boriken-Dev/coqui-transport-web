# `coqui-web` — API header

Header-file-style reference for the `coqui-web` crate: every public item with its signature, contract and gotchas, so the crate can be used without reading its source. It ships inside the package and is self-contained. Development documentation lives with the source at <https://github.com/Boriken-Dev/coqui-web>.

| Feature | Adds | Default |
| --- | --- | --- |
| `websocket` | `websocket::{Channel, Dialer, Frames, Listener}`, on `tungstenite` and `rustls` | off |
| `webtransport` | `webtransport::{Channel, Dialer, Listener}`, on `wtransport`, with a small runtime inside | off |

MSRV Rust 1.89. A default build depends on `url` alone. Version `0.0.0-alpha.0`, not published; the API may change in any
release before 1.0.

Imports: the crate root holds the channel contract, `connect`, `Endpoints`, `Failure` and, with a driver feature, `Limits`.
Public modules: `frame`, `websocket`, `webtransport`.

No `unsafe` code (`#![forbid(unsafe_code)]`). No process-wide state. A dialer holds no trust roots: TLS is the caller's.

## Channels (crate root)

```rust
pub enum Kind {
    WebTransport,
    WebSocket,
}
```

A transport a channel runs over.

```rust
pub trait Channel: Send + Sync {
    fn send(&self, message: &[u8]) -> Result<(), Failure>;
    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>;
    fn close(&self);
    fn set_max_message(&self, _bytes: usize) {}   // both ways, from the next read; a peer's answer to anything sent after this call meets it; default ignores it
    fn datagrams(&self) -> Option<&dyn Datagrams> { None }   // Some on WebTransport; a WebSocket, or a channel wrapping another, has none
}
```

A reliable, ordered channel of whole messages.

```rust
pub trait Datagrams: Send + Sync {
    fn max_size(&self) -> Option<usize>;                                          // what fits now; it can change; None: the peer takes none
    fn send(&self, payload: &[u8]) -> Result<(), Failure>;                        // Protocol if too large, and the channel goes on; Unsupported; PathLost
    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>;   // None once the connection ended; Timeout
    fn dropped(&self) -> u64;                                                     // discarded here for a reader behind; network loss cannot be seen
}
```

Raw datagrams beside the messages: lost, reordered or repeated without notice, whole or not at all, and with no framing of this library's. **Outside any identity proof run on the messages**, so TLS is all that protects them. Read only once `datagrams()` is first called; the transport's bounded buffer holds them until then.

```rust
pub trait Dialer {
    type Connection: Channel;
    fn dial(&mut self, kind: Kind, endpoint: &Url, timeout: Duration) -> Result<Self::Connection, Failure>;
}
```

Opens a channel of one kind. A driver, or a test.

```rust
pub trait Preflight<C: Channel> {
    fn check(&mut self, kind: Kind, channel: &C) -> Result<(), Failure>;
}
```

An optional liveness probe on a channel that just opened, before any authentication or application message.

```rust
pub struct NoPreflight;
```

No probe.

```rust
pub struct Unverified<C: Channel> { /* private */ }
```

A channel that is open and **not yet trusted**. Run the peer's identity proof on it before delivering any application message.

```rust
pub fn connect<D, P>(
    endpoints: &Endpoints,
    dialer: &mut D,
    probe: &mut P,
    timeout: Duration,
) -> Result<Unverified<D::Connection>, Failure>
where
    D: Dialer,
    P: Preflight<D::Connection>,
```

Opens WebTransport first, and WebSocket when that fails on the path before anything crossed.

## Endpoints (crate root)

```rust
pub struct CertificatePin([u8; 32]);
```

The SHA-256 of a certificate a WebTransport client pins, written `sha256:<64 hex digits>`.

```rust
pub enum EndpointError {
    Empty,
    Url,
    WebTransport,
    WebSocket,
    NotPlain,
    HostMismatch,
    Pin,
}
```

Why a set of endpoints was refused.

```rust
pub struct Endpoints { /* private */ }
```

Explicit endpoints for one expected peer.

```rust
pub struct EndpointsBuilder { /* private */ }
```

Builds [`Endpoints`]; all validation happens in [`build`](Self::build).

## Failures (crate root)

```rust
pub enum Failure {
    Unsupported,
    Timeout,
    PathLost,
    NoProgress,
    SuspectedMtu,
    Certificate,
    PeerProof,
    Protocol,
    Permission,
    Cancelled,
}
```

A failure a driver can distinguish.

```rust
pub enum Phase {
    Opening,
    Active,
}
```

Whether application traffic has already crossed the channel.

```rust
pub enum Recovery {
    Deny,
    VerifyFallback,
    VerifyAndReconcile,
}
```

What a failed channel allows next.

## Framing (coqui_web::frame)

```rust
pub const DEFAULT_MAX_MESSAGE: usize = 1024 * 1024;
```

The largest body a peer may send unless the application chooses otherwise: 1 MiB.

```rust
pub enum FrameError {
    Size,
}
```

A frame outside the bounds this side accepts.

```rust
pub fn encode(body: &[u8], maximum: usize) -> Result<Vec<u8>, FrameError> {
    // ...
}
```

Prefixes a non-empty body of at most `maximum` bytes with its length.

```rust
pub struct Decoder { /* private */ }
```

An incremental decoder for fragmented or coalesced stream bytes.

```rust
impl Decoder {
    pub const fn new(maximum: usize) -> Self {
        // ...
    }
    pub fn push(&mut self, part: &[u8]) {
        // ...
    }
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        // ...
    }
}
```

Methods for the `Decoder` struct.

## Limits (crate root, with a driver feature)

```rust
pub struct Limits { pub max_message: usize, pub pending: usize, pub handshake: Duration, pub queued_bytes: usize, pub send: Duration, pub idle: Duration, pub pending_datagrams: usize }
pub const fn with_max_message(self, bytes: usize) -> Self
pub const fn with_pending(self, messages: usize) -> Self
pub const fn with_handshake(self, limit: Duration) -> Self
pub const fn with_queued_bytes(self, bytes: usize) -> Self
pub const fn with_send(self, limit: Duration) -> Self
pub const fn with_idle(self, limit: Duration) -> Self
```

`#[non_exhaustive]`. Defaults: 1 MiB, 64 messages, 10 s in total for a handshake, 64 MiB queued to send, 30 s for one send, a ping after 60 s of silence and `Failure::NoProgress` after 120 s. A message over `max_message` ends the channel with `Failure::Protocol`. When `pending`
messages wait for a slow reader, the driver stops reading from the peer.

## WebSocket (`coqui_web::websocket`, feature `websocket`)

```rust
pub enum Frames { Text, Binary }            // default Text; a binary message on a Text channel is Failure::Protocol
pub struct Channel                          // implements coqui_web::Channel
pub fn Dialer::new() -> Self                // no TLS: reaches only ws://; wss:// fails with Failure::Certificate
pub fn Dialer::with_tls(self, tls: Arc<rustls::ClientConfig>) -> Self
pub const fn Dialer::with_limits(self, limits: Limits) -> Self
pub const fn Dialer::with_frames(self, frames: Frames) -> Self
pub fn Dialer::with_header(self, name: impl Into<String>, value: impl Into<String>) -> Self // a value never prints
pub fn Listener::bind(address: SocketAddr, tls: Option<Arc<rustls::ServerConfig>>) -> Result<Self, Failure>
pub const fn Listener::with_limits(self, limits: Limits) -> Self
pub const fn Listener::with_frames(self, frames: Frames) -> Self
pub fn Listener::with_origins(self, origins: impl IntoIterator<Item = String>) -> Self
pub fn Listener::with_admission(self, admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self
pub fn Listener::local_addr(&self) -> Result<SocketAddr, Failure>
pub fn Listener::next(&self, timeout: Option<Duration>) -> Result<Pending, Failure>
pub fn Pending::handshake(self) -> Result<Channel, Failure>
pub fn Listener::accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure>
```

`bind` with no TLS on a non-loopback address is `Failure::Permission`. `accept` runs one handshake, bounded in total by `Limits::handshake`. `Listener::next` returns a `Pending` before its handshake, for a server that runs `Pending::handshake` on threads of its own so one slow peer cannot hold up others. A dialer refuses `ws://` beyond loopback with `Failure::Permission`. `close` returns once what was queued has gone. `Failure::Certificate` means a certificate was rejected, by this side or the peer's; any other TLS error is `Failure::Protocol`, since one forged record can cause it.

## WebTransport (`coqui_web::webtransport`, feature `webtransport`)

```rust
pub struct Channel                          // implements coqui_web::Channel
pub fn Dialer::pinned(pins: &[CertificatePin]) -> Result<Self, Failure>
pub fn Dialer::with_tls(tls: Arc<rustls::ClientConfig>) -> Result<Self, Failure>
pub const fn Dialer::with_limits(self, limits: Limits) -> Self
pub fn Listener::bind(address: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<Self, Failure>
pub const fn Listener::with_limits(self, limits: Limits) -> Self
pub fn Listener::with_origins(self, origins: impl IntoIterator<Item = String>) -> Self
pub fn Listener::with_admission(self, admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self
pub const fn Listener::local_addr(&self) -> SocketAddr
pub fn Listener::next(&self, timeout: Option<Duration>) -> Result<Pending, Failure>
pub fn Pending::handshake(self) -> Result<Channel, Failure>
pub fn Listener::accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure>
```

`Listener::next` sends a source to retry first, since UDP sources are forgeable, then judges it by admission, and `Pending::handshake` completes it. Each dialer and listener runs its own runtime, and its calls block. Inside an async runtime, call them from its blocking pool.

## Gotchas

- `Unverified` proves nothing about the peer. Run the identity proof before `into_verified`.
- `connect` never retries after returning, and an endpoint with pins never falls back, even on a path failure.
- A pin needs a certificate valid for at most 14 days, ECDSA P-256, in browsers and in `Dialer::pinned` alike. Otherwise it is refused as `Failure::Certificate`.
- QUIC does not fall back between address families: a host resolving to IPv6 first can time out against an IPv4 listener. Dial by address when in doubt.
- WebSocket `Text` frames: `Channel::send` refuses bytes that are not UTF-8 before they reach the wire.
