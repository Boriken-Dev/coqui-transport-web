# `coqui-web` — API header

Header-file-style reference for the `coqui-web` crate: every public item with its signature, contract and gotchas, so the crate can be used without reading its source. It ships inside the package and is self-contained. Development documentation lives with the source at <https://github.com/Boriken-Dev/coqui-web>.

| Feature | Adds | Default |
| --- | --- | --- |
| `websocket` | `websocket::{Channel, Dialer, Frames, Listener}`, on `tungstenite`, `rustls` and `mio` | off |
| `webtransport` | `webtransport::{Channel, Dialer, Listener}`, on `wtransport`, with a small runtime inside | off |
| `webrtc` | `webrtc::{Port, Settings, Signaling}`, and a WebSocket channel that climbs onto a data channel, on `str0m`; implies both others | off |

MSRV Rust 1.89. A default build depends on `url` alone. Version `0.0.0-alpha.0`, not published; the API may change in any
release before 1.0.

Imports: the crate root holds the channel contract, `connect`, `Endpoints`, `Failure` and, with a driver feature, `Limits`.
Public modules: `frame`, `webrtc`, `websocket`, `webtransport`.

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
    fn peer_certificates(&self) -> Option<&[Vec<u8>]> { None }   // DER, the peer's own first; Some on a TLS WebSocket and on WebTransport
}
```

A reliable, ordered channel of whole messages. `peer_certificates` is the chain the peer presented and this side's rustls configuration accepted: the server's on a client, the client's on a server whose configuration asked for one. `None` without TLS, or when the peer presented none, as a client does when not asked. It proves what that configuration's verifier checked, and nothing about a channel wrapping this one.

```rust
pub trait Datagrams: Send + Sync {
    fn max_size(&self) -> Option<usize>;                                          // what fits now; it can change; None: the peer takes none
    fn send(&self, payload: &[u8]) -> Result<(), Failure>;                        // Protocol if too large, and the channel goes on; Unsupported; PathLost
    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>;   // None once the connection ended; Timeout
    fn dropped(&self) -> u64;                                                     // discarded here: a reader behind, or on a WebSocket a link behind; network loss cannot be seen
    fn delivery(&self) -> Delivery;                                               // how they travel now
    fn path_changes(&self) -> Option<Receiver<Delivery>> { None }                 // each change from this call on, as the Delivery now in force; None: this path never changes
}
pub enum Delivery { Unreliable, OverStream }   // non_exhaustive
```

Raw datagrams beside the messages, whole or not at all. `Unreliable` (WebTransport): lost, reordered or repeated without notice. `OverStream` (a WebSocket whose client asked with `websocket::Dialer::with_datagrams` and whose server agreed, which a `Listener` always does): in order and late rather than lost on the way, as tagged binary messages. **Outside any identity proof run on the messages**, so TLS is all that protects them. Read only once `datagrams()` is first called. Until then WebTransport's transport holds them in its bounded buffer, and a WebSocket discards and counts them. A WebSocket with the `webrtc` feature can change from `OverStream` to `Unreliable` and back during a connection: `max_size` follows the path, and one over it is refused with `Failure::Protocol` rather than moved.

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
pub struct Limits { pub max_message: usize, pub pending: usize, pub handshake: Duration, pub queued_bytes: usize, pub send: Duration, pub idle: Duration, pub pending_datagrams: usize, pub websocket_datagram: usize }
pub const fn with_max_message(self, bytes: usize) -> Self
pub const fn with_pending(self, messages: usize) -> Self
pub const fn with_handshake(self, limit: Duration) -> Self
pub const fn with_queued_bytes(self, bytes: usize) -> Self
pub const fn with_send(self, limit: Duration) -> Self
pub const fn with_idle(self, limit: Duration) -> Self
```

`#[non_exhaustive]`. Defaults: 1 MiB, 64 messages, 10 s in total for a handshake, 64 MiB queued to send, 30 s for a WebSocket peer to take nothing while there is something to send, which ends the channel with `Failure::NoProgress`, a ping after 60 s of silence and `Failure::NoProgress` after 120 s. A message over `max_message` ends the channel with `Failure::Protocol`. When `pending`
messages wait for a slow reader, the driver stops reading from the peer.

## WebSocket (`coqui_web::websocket`, feature `websocket`)

```rust
pub enum Frames { Text, Binary }            // default Text; a binary message on a Text channel is Failure::Protocol
pub struct Channel                          // implements coqui_web::Channel
pub fn Dialer::new() -> Self                // no TLS: reaches only ws://; wss:// fails with Failure::Certificate
pub fn Dialer::with_tls(self, tls: Arc<rustls::ClientConfig>) -> Self
pub const fn Dialer::with_limits(self, limits: Limits) -> Self
pub const fn Dialer::with_frames(self, frames: Frames) -> Self
pub const fn Dialer::with_datagrams(self) -> Self                       // asks the server to agree; one that does not makes the dial Failure::Unsupported
pub const fn Dialer::with_webrtc(self, settings: webrtc::Settings) -> Self  // feature webrtc; datagrams too, and a climb where the listener can
pub fn Dialer::with_header(self, name: impl Into<String>, value: impl Into<String>) -> Self // a value never prints
pub const fn Dialer::with_plain_beyond_loopback(self) -> Self               // ws:// beyond loopback too: a weakening
pub const fn Dialer::plain_beyond_loopback(&self) -> bool
pub fn Listener::bind(address: SocketAddr, tls: Option<Arc<rustls::ServerConfig>>) -> Result<Self, Failure>
pub fn Listener::bind_plain(address: SocketAddr) -> Result<Self, Failure>   // no TLS, loopback or not, such as 0.0.0.0: a weakening beyond loopback
pub fn Listener::plain_beyond_loopback(&self) -> bool
pub const fn Listener::with_limits(self, limits: Limits) -> Self
pub const fn Listener::with_frames(self, frames: Frames) -> Self
pub fn Listener::with_origins(self, origins: impl IntoIterator<Item = String>) -> Self
pub fn Listener::with_admission(self, admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self
pub fn Listener::with_webrtc(self, port: &webrtc::Port) -> Self             // feature webrtc
pub fn Listener::local_addr(&self) -> Result<SocketAddr, Failure>
pub fn Listener::next(&self, timeout: Option<Duration>) -> Result<Pending, Failure>
pub const fn Pending::peer_addr(&self) -> SocketAddr                         // the source Listener::next admitted
pub fn Pending::handshake(self) -> Result<Channel, Failure>
pub fn Listener::accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure>
pub fn Channel::next_signal(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>  // feature webrtc, Signaling::ByCaller
pub fn Channel::deliver_signal(&self, signal: &[u8]) -> Result<(), Failure>                        // feature webrtc, Signaling::ByCaller
```

`bind` with no TLS on a non-loopback address is `Failure::Permission`; `bind_plain` is the deliberate choice of one. A dialer refuses `ws://` beyond loopback with `Failure::Permission` before connecting, unless `with_plain_beyond_loopback`. A listener or dialer that allows it says so in `plain_beyond_loopback()` and in its `Debug`, for the host to show; neither prints. `Endpoints` still takes `ws://` only on loopback. `accept` runs one handshake, bounded in total by `Limits::handshake`. `Listener::next` returns a `Pending` before its handshake, for a server that runs `Pending::handshake` on threads of its own so one slow peer cannot hold up others. `close` returns once what was queued has gone, or the peer has taken nothing for `Limits::send`. Each channel has a worker thread that sleeps on its socket and on its callers, so an idle channel takes no CPU and a message goes as soon as it is sent; the wait holds up to two file handles beside the socket. `Failure::Certificate` means a certificate was rejected, by this side or the peer's; any other TLS error is `Failure::Protocol`, since one forged record can cause it.

## WebTransport (`coqui_web::webtransport`, feature `webtransport`)

```rust
pub struct Channel                          // implements coqui_web::Channel
pub fn Dialer::pinned(pins: &[CertificatePin]) -> Result<Self, Failure>
pub fn Dialer::with_tls(tls: Arc<rustls::ClientConfig>) -> Result<Self, Failure>
pub const fn Dialer::with_limits(self, limits: Limits) -> Self
pub fn Listener::bind(address: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<Self, Failure>
pub fn Listener::on_port(port: &webrtc::Port, tls: Arc<rustls::ServerConfig>) -> Result<Self, Failure>  // feature webrtc; one per port, a second is Failure::Permission
pub const fn Listener::with_limits(self, limits: Limits) -> Self
pub fn Listener::with_origins(self, origins: impl IntoIterator<Item = String>) -> Self
pub fn Listener::with_admission(self, admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self
pub const fn Listener::local_addr(&self) -> SocketAddr
pub fn Listener::next(&self, timeout: Option<Duration>) -> Result<Pending, Failure>
pub const fn Pending::peer_addr(&self) -> SocketAddr                         // the source admission judged; on a Port the client's, not its relay's
pub fn Pending::handshake(self) -> Result<Channel, Failure>
pub fn Listener::accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure>
```

`Listener::next` sends a source to retry first, since UDP sources are forgeable, then judges it by admission, and `Pending::handshake` completes it. Each dialer and listener runs its own runtime, and its calls block. Inside an async runtime, call them from its blocking pool.

## The ladder (`coqui_web::webrtc`, feature `webrtc`)

```rust
pub struct Settings { pub enabled: bool, pub attempt: Duration, pub path_mtu: usize, pub public_address: Option<SocketAddr>, pub any_candidate: bool, pub signaling: Signaling, pub max_sessions: usize, pub max_relays: usize, pub max_per_address: usize, pub relay_idle: Duration }
pub const fn with_enabled(self, enabled: bool) -> Self
pub const fn with_attempt(self, limit: Duration) -> Self
pub const fn with_path_mtu(self, bytes: usize) -> Self
pub const fn with_public_address(self, address: SocketAddr) -> Self
pub const fn with_any_candidate(self) -> Self
pub const fn with_signaling(self, signaling: Signaling) -> Self
pub const fn with_max_sessions(self, sessions: usize) -> Self
pub const fn with_max_relays(self, relays: usize) -> Self
pub const fn with_max_per_address(self, held: usize) -> Self
pub const fn with_relay_idle(self, limit: Duration) -> Self
pub enum Signaling { OnChannel, ByCaller }            // non_exhaustive; default OnChannel
pub struct Port                                       // Clone; Debug
pub fn Port::bind(address: SocketAddr, settings: Settings) -> Result<Self, Failure>   // Permission when taken or not allowed; Unsupported for settings that leave no room
pub fn Port::local_addr(&self) -> SocketAddr
pub fn Port::relays(&self) -> usize                   // QUIC sources relayed now
pub fn Port::data_channels(&self) -> usize            // data channels held now, opening or open
```

`#[non_exhaustive]`. Defaults: on, 5 s for an attempt, a path of 1280 bytes, no public address, a candidate only where the peer is, `OnChannel`, 256 data channels, 512 relays, 64 of either for one IP address, 120 s for a relay's silence on the listener's side. Settings with a `path_mtu` of 116 or less, or a zero time or count, are `Failure::Unsupported` from `Port::bind` and from a `with_webrtc` dialer's `dial`.

A `Port` reads the first byte of each packet (RFC 9443): QUIC to a loopback relay in front of `webtransport::Listener::on_port`, STUN and DTLS to a data channel, anything else dropped. One worker thread serves it and sleeps while nothing is due; at rest it wakes when `str0m` asks, every few seconds per data channel. It ends with its last clone, listener or channel: the socket and relays close and the thread is joined.

A WebSocket with `Dialer::with_webrtc` asks for `coqui-web-ladder.1` and `coqui-web-datagrams.1`, and a listener with `with_webrtc` prefers the first, which adds tag 2, a signal: one byte, 1 offer, 2 answer or 3 refused, then the session description. A listener with no port never agrees to it, and a dialer without `with_webrtc` never asks. The attempt starts at each end when `datagrams()` is first called there, once per channel. The channel is unordered with no retransmits, created by the dialer. Until it opens, and after it dies, datagrams stay in the WebSocket; each switch is reported by `path_changes`. An attempt that fails changes nothing and reports nothing.

## Gotchas

- `Unverified` proves nothing about the peer. Run the identity proof before `into_verified`.
- `connect` never retries after returning, and an endpoint with pins never falls back, even on a path failure.
- A pin needs a certificate valid for at most 14 days, ECDSA P-256, in browsers and in `Dialer::pinned` alike. Otherwise it is refused as `Failure::Certificate`.
- QUIC does not fall back between address families: a host resolving to IPv6 first can time out against an IPv4 listener. Dial by address when in doubt.
- WebSocket `Text` frames: `Channel::send` refuses bytes that are not UTF-8 before they reach the wire.
- A data channel's `max_size` is at most 1100 bytes, and less for a smaller `path_mtu`: a fragmented unreliable message is lost when any fragment is. The peer's own limit is not read.
- An empty datagram sent from Rust on a data channel is refused with `Failure::Protocol`: `str0m` writes nothing for one. One arriving from a browser is delivered.
- A datagram sent from a data channel's end before the other end has switched still arrives: each end listens on both paths.
- `Port`'s candidate names the address the WebSocket connection arrived at, with the UDP port's number. Behind a proxy or NAT set `Settings::public_address`: the default is wrong there, and tells the peer an address it had no other way to learn. A peer always learns the address it is given. On a host with several addresses, bind one: a reply leaves by whichever the system picks, on a wildcard socket.
- A peer can name any candidate in an answer. `with_webrtc` refuses one not at the WebSocket's peer unless `Settings::any_candidate`; candidates in an offer are discarded. A browser has no such check for a server named by host name.
- A listening data channel answers checks only from its WebSocket peer's IP address, and once its peer nominates a source it hears from that one alone, so a client holding the credentials cannot point the port's traffic elsewhere or take another session's path. A check is routed by the fragment it names, anything else by its source. Behind a proxy the WebSocket peer is the proxy: set `any_candidate` on the `Port`, and each session is then held to the first source its peer nominated, which that peer could have forged.
- One IP address holds at most `max_per_address` relays and as many data channels. Behind a proxy every client has the proxy's address.
- Through a reverse proxy a UDP path needs a stream block for the port, or the host's own port with `public_address`. Without one the attempt fails and the ladder ends at the WebSocket.
- A relay is a socket per QUIC source, so a flood of forged sources is a real cost, which the caps bound. Past either cap a new source replaces the oldest of the same kind with no finished handshake and at least half a second old, or is dropped, and takes at least a 1200-byte first packet. A relay whose WebTransport handshake finished is never replaced and ends when its connection does, after which only a first packet of 1200 bytes from that source starts another for 10 s; one is kept alive only by what the listener sends, never by the source. A flood of more than the cap per half second still holds back new WebTransport sessions, which fall back like any failed WebTransport. It shares the port's one thread with the data channels, so it can slow them too.
- A relay's address is a loopback port the system hands out, so it can come back for another source. A Retry token names that address and lasts seconds, and went only to the source it was minted for. No address-validation token is handed out on a port: one is bound to an IP address, and every relay is 127.0.0.1.
- `webtransport::Listener::on_port` sees the relay's address, not the client's, inside `wtransport`; admission and `Debug` read through to the real one. A local process reaching its loopback socket directly is refused when admission is set. QUIC's ECN does not cross the relay.
- `Datagrams::path_changes` before `datagrams()` is not possible, and an event between the two calls is missed: read `delivery()` after subscribing. A climbing channel tells only its 16 most recent subscriptions.
- Signals on the channel have what TLS gives them. For datagrams bound to a peer proof use `Signaling::ByCaller` and carry them inside the proven link. Then, while the data channel is open, a datagram tagged inside the WebSocket is discarded and counted, so everything received is inside the proof; before it opens, and after it dies, they are what TLS gives them.
