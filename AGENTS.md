# `coqui-transport-web` — API header

Header-file-style reference for the `coqui-transport-web` crate: every public item with its signature, contract and gotchas, so the crate can be used without reading its source. It ships inside the package and is self-contained. Development documentation lives with the source at <https://github.com/Boriken-Dev/coqui-transport-web>.

| Feature | Adds | Default |
| --- | --- | --- |
| `websocket` | `websocket::{Channel, Dialer, Frames, Listener}`, on `tungstenite`, `rustls`, `mio` and `socket2` | off |
| `webtransport` | `webtransport::{Channel, Dialer, Listener}`, on `wtransport`, with a small runtime inside | off |
| `webrtc` | `webrtc::{Port, Settings, Signaling}`, and a WebSocket channel that climbs onto a data channel, on `str0m`; implies both others | off |

MSRV Rust 1.89. A default build depends on `url` and `coqui-transport` (by git revision: the family has no releases yet). Version
`0.0.0-alpha.0`, not published; the API may change in any release before 1.0.

Imports: the crate root holds the channel contract (`Channel`, `Datagrams`, `Delivery`, `Failure`, `Capabilities`, `Carrier`,
re-exported from `coqui-transport`, which defines them), `connect`, `Dialer`, `FailureExt`, `Endpoints`, `NonDefault` and, with a
driver feature, `Limits` and `Cancel`. Public modules: `frame`, `webrtc`, `websocket`, `webtransport`.

It was `coqui-web-channel`, now a deprecated crate that re-exports this one and `coqui-transport`. A name that crate had is
here, except that `Failure::recovery` is a method of the `FailureExt` trait: import it.

No `unsafe` code (`#![forbid(unsafe_code)]`). No process-wide state. A dialer holds no trust roots: TLS is the caller's.

## Channels (crate root)

```rust
pub enum Kind {
    WebTransport,
    WebSocket,
}
```

A transport a channel runs over.

The contract below is `coqui_transport::Channel`, `Datagrams`, `Delivery` and `Failure`, re-exported unchanged. Both drivers
implement it, and `capabilities()` and `is_closed()` too.

```rust
pub trait Channel: Send + Sync {
    fn send(&self, message: &[u8]) -> Result<(), Failure>;
    fn receive(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>;
    fn close(&self);
    fn set_max_message(&self, _bytes: usize) {}   // both ways, from the next read; a peer's answer to anything sent after this call meets it; default ignores it
    fn set_max_receive(&self, _bytes: usize) {}   // what it reads only, as above
    fn set_max_receive_after(&self, messages: usize, bytes: usize) -> Result<(), Failure> { /* 0: set_max_receive; else Err(Unsupported) */ }
    fn set_pending(&self, _messages: usize) -> Result<(), Failure> { Err(Failure::Unsupported) }   // how many unread messages the driver holds; 0 is 1
    fn set_max_send(&self, _bytes: usize) {}      // what it sends only: a side reading under a small bound can still answer up to the peer's
    fn send_timeout(&self, message: &[u8], _timeout: Option<Duration>) -> Result<(), Failure> { self.send(message) }   // waits for room
    fn datagrams(&self) -> Option<&dyn Datagrams> { None }   // Some on WebTransport; a WebSocket, or a channel wrapping another, has none
    fn peer_certificates(&self) -> Option<&[Vec<u8>]> { None }   // DER, the peer's own first; Some on a TLS WebSocket and on WebTransport
    fn capabilities(&self) -> Capabilities { /* only what datagrams() says */ }   // both drivers override it
    fn is_closed(&self) -> bool { false }                                          // both drivers track it
}
```

`capabilities()` on a WebSocket reports `Carrier::Messages`, the send and read bounds in force, and datagrams only where both ends
agreed (`Delivery::OverStream`, or `Unreliable` while a data channel is open); on WebTransport `Carrier::Stream`, the bounds, and
`Delivery::Unreliable` with the connection's current datagram size. It starts nothing: unlike `datagrams()`, it neither makes a
WebSocket hold datagrams nor begins a data-channel attempt. `is_closed()` is true once this side closed the channel or knows the
peer or a failure ended it; false promises nothing.

A reliable, ordered channel of whole messages. `peer_certificates` is the chain the peer presented and this side's rustls configuration accepted: the server's on a client, the client's on a server whose configuration asked for one. `None` without TLS, or when the peer presented none, as a client does when not asked. It proves what that configuration's verifier checked, and nothing about a channel wrapping this one.

`set_max_receive_after(n, bytes)` stages the read bound by position: the next `n` messages `receive` has not yet returned are held to the bound in force now, and every one after them to `bytes`. Both drivers judge each message by its position as they read it, however far they have read ahead of the reader, so the bound for message k does not depend on timing: a large message right behind the small one is taken, and one in its place is refused as any message over its bound is (on a WebSocket, a close with 1009 and `Failure::Protocol` at both ends). Positions count from what `receive` has returned at the call, so stage before the peer can send what the stage is for. A message already read when the call is made keeps its judgement. A later `set_max_receive_after`, `set_max_receive` or `set_max_message` replaces a stage not yet reached. Both drivers return `Ok`; the default, for a channel that cannot stage, changes nothing and returns `Failure::Unsupported`, except `n` = 0, which is `set_max_receive`. `Box<dyn Channel>` forwards it.

`set_pending(n)` sets how far one channel reads ahead of its reader: the driver holds at most `n` messages `receive` has not yet returned, and reads nothing more from the peer until the reader takes one, which holds the peer's sends back exactly as a slow reader does (on a WebSocket it still pings every `idle`, and neither end is taken for gone). A channel starts at its driver's `Limits::pending`; 0 is 1. A new limit governs only reading not yet done: a message already read stays, a lower limit drops nothing and holds the driver until the reader is below it, and a higher one wakes the driver at once. The bound for each message is still fixed by its position, staged or not, so the two combine in any order. Both drivers return `Ok`; the default, for a channel that cannot bound its read-ahead, changes nothing and returns `Failure::Unsupported`. `Box<dyn Channel>` forwards it.

`send_timeout` queues as `send` does but waits up to `timeout` for room rather than refusing; `None` waits as long as the channel lives. `Failure::Timeout` means no room in time: nothing was sent and the channel goes on. Each driver's own terms are in its section.

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

```rust
pub trait FailureExt { fn recovery(self, failed: Kind, phase: Phase, has_websocket: bool) -> Recovery; }   // implemented for Failure
```

What a failure allows next. Only a path failure on `WebTransport`, with a WebSocket endpoint the peer advertised, allows a
fallback (`VerifyFallback` while opening, `VerifyAndReconcile` once active); a protocol failure only while opening; a certificate,
peer-proof, permission or cancel failure never. An operation of uncertain outcome is never replayed.

```rust
pub struct NonDefault { pub setting: &'static str, pub default: String, pub value: String }   // non_exhaustive
pub fn NonDefault::new(setting: &'static str, default: impl ToString, value: impl ToString) -> Self
```

A setting that differs from its default, as data. `websocket::Dialer::non_defaults()` and `websocket::Listener::non_defaults()` return
them (today `plain_beyond_loopback` only). The crate never logs or warns about one: the application decides what it means.

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

## Framing (coqui_transport_web::frame)

```rust
pub const WEBTRANSPORT: coqui_transport::frame::LengthPrefix;   // LengthPrefix::u32_le().refuse_empty()
```

The framing of a WebTransport stream, as `coqui-transport`'s length-prefix codec, held to the old bytes by `tests/vectors/webtransport_frame.json`.
`encode` and `Decoder` delegate to it; `FrameError` and `DEFAULT_MAX_MESSAGE` are `coqui_transport::frame`'s.

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
messages wait for a slow reader, the driver stops reading from the peer, which holds the peer's sends back; `pending` is where each
channel starts, `Channel::set_pending` changes it for one, and 0 is 1. A WebSocket that has
stopped reading does not count the peer's silence, which it cannot hear, and pings the peer every `idle`, so neither end takes a
stalled reader for gone. The sending end still ends the channel with `Failure::NoProgress` once the peer has taken nothing for `send`.

## Cancelling a handshake (crate root, with a driver feature)

```rust
pub struct Cancel                     // Clone; Debug; from websocket::Pending::canceller or webtransport::Pending::canceller
pub fn cancel(&self) -> bool          // whether this call stopped a handshake that had not finished
```

A cancel before or during `Pending::handshake`, from any thread, makes it return `Failure::Cancelled` at once and closes the connection: a WebSocket's socket, or a WebTransport session (one not yet accepted is refused, which its dialer reads as `Failure::Permission`). Once the handshake has finished, a cancel does nothing and returns `false`. A server WebSocket handshake waits on the socket's readiness, its deadline and a cancel together, on the caller's thread and no other.

## WebSocket (`coqui_transport_web::websocket`, feature `websocket`)

```rust
pub enum Frames { Text, Binary }            // default Text; a binary message on a Text channel is Failure::Protocol
pub struct Channel                          // implements coqui_transport_web::Channel
pub fn Dialer::new() -> Self                // no TLS: reaches only ws://; wss:// fails with Failure::Certificate
pub fn Dialer::with_tls(self, tls: Arc<rustls::ClientConfig>) -> Self
pub const fn Dialer::with_limits(self, limits: Limits) -> Self
pub const fn Dialer::with_local_addr(self, address: SocketAddr) -> Self    // binds each connection's socket there first
pub const fn Dialer::with_frames(self, frames: Frames) -> Self
pub const fn Dialer::with_datagrams(self) -> Self                       // asks the server to agree; one that does not makes the dial Failure::Unsupported
pub const fn Dialer::with_webrtc(self, settings: webrtc::Settings) -> Self  // feature webrtc; datagrams too, and a climb where the listener can
pub fn Dialer::with_header(self, name: impl Into<String>, value: impl Into<String>) -> Self // a value never prints
pub const fn Dialer::with_plain_beyond_loopback(self) -> Self               // ws:// beyond loopback too: not the default, reported
pub const fn Dialer::plain_beyond_loopback(&self) -> bool
pub fn Dialer::non_defaults(&self) -> Vec<NonDefault>
pub struct Connector                                                        // Clone, Debug; a coqui_transport::Connector
pub const fn Connector::new(dialer: Dialer, endpoint: Url) -> Self          // connect(timeout) dials that endpoint, each call with a clone of the dialer
pub fn Listener::bind(address: SocketAddr, tls: Option<Arc<rustls::ServerConfig>>) -> Result<Self, Failure>
pub fn Listener::bind_plain(address: SocketAddr) -> Result<Self, Failure>   // no TLS, loopback or not, such as 0.0.0.0: reported beyond loopback
pub fn Listener::plain_beyond_loopback(&self) -> bool
pub fn Listener::non_defaults(&self) -> Vec<NonDefault>
pub const fn Listener::with_limits(self, limits: Limits) -> Self
pub const fn Listener::with_frames(self, frames: Frames) -> Self
pub fn Listener::with_origins(self, origins: impl IntoIterator<Item = String>) -> Self
pub fn Listener::with_admission(self, admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self
pub fn Listener::with_webrtc(self, port: &webrtc::Port) -> Self             // feature webrtc
pub fn Listener::local_addr(&self) -> Result<SocketAddr, Failure>
pub fn Listener::next(&self, timeout: Option<Duration>) -> Result<Pending, Failure>
pub const fn Pending::peer_addr(&self) -> SocketAddr                         // the source Listener::next admitted
pub fn Pending::canceller(&self) -> Cancel                                   // abandons the handshake from another thread
pub fn Pending::handshake(self) -> Result<Channel, Failure>
pub fn Listener::accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure>
pub fn Channel::next_signal(&self, timeout: Option<Duration>) -> Result<Option<Vec<u8>>, Failure>  // feature webrtc, Signaling::ByCaller
pub fn Channel::deliver_signal(&self, signal: &[u8]) -> Result<(), Failure>                        // feature webrtc, Signaling::ByCaller
```

`bind` with no TLS on a non-loopback address is `Failure::Permission`; `bind_plain` is the deliberate choice of one. A dialer refuses `ws://` beyond loopback with `Failure::Permission` before connecting, unless `with_plain_beyond_loopback`. A listener or dialer that allows it says so in `plain_beyond_loopback()` and in its `Debug`, for the host to show; neither prints. `Endpoints` still takes `ws://` only on loopback. `accept` runs one handshake, bounded in total by `Limits::handshake`. `Listener::next` returns a `Pending` before its handshake, for a server that runs `Pending::handshake` on threads of its own so one slow peer cannot hold up others. `send` answers `Failure::NoProgress` at once while `Limits::queued_bytes`, or 256 messages, wait to be sent; `send_timeout` waits for room instead, woken by the worker only while a sender waits, and answers why the worker ended once it has: `Failure::Protocol` when either end refused what the other sent, otherwise `Failure::PathLost`. A message over the bound a reader set, or one that breaks the wire, ends the channel with a close code saying so (1009, 1002, 1003 or 1007): the reading end reports `Failure::Protocol`, and so does the sending end once the close arrives, to its reader and its senders. The reading end then reads and discards what the peer still sends until the peer closes, for up to 500 ms, so the close is not lost to a reset. `close` returns once what was queued has gone, or the peer has taken nothing for `Limits::send`. Each channel has a worker thread that sleeps on its socket and on its callers, so an idle channel takes no CPU and a message goes as soon as it is sent; the wait holds up to two file handles beside the socket. `Failure::Certificate` means a certificate was rejected, by this side or the peer's; any other TLS error is `Failure::Protocol`, since one forged record can cause it.

Both listeners are `coqui_transport::Listener`s: `accept()` with no timeout waits for the next connection, and a failed handshake
fails that call only. Their own `accept(timeout)` is the inherent method; call the trait's as `coqui_transport::Listener::accept(&l)`.

## WebTransport (`coqui_transport_web::webtransport`, feature `webtransport`)

```rust
pub struct Channel                          // implements coqui_transport_web::Channel
pub fn Dialer::pinned(pins: &[CertificatePin]) -> Result<Self, Failure>
pub struct Connector                                                        // Clone, Debug; a coqui_transport::Connector
pub const fn Connector::new(dialer: Dialer, endpoint: Url) -> Self
pub fn Dialer::with_tls(tls: Arc<rustls::ClientConfig>) -> Result<Self, Failure>
pub const fn Dialer::with_limits(self, limits: Limits) -> Self
pub const fn Dialer::with_local_addr(self, address: SocketAddr) -> Self    // binds the UDP socket there, one per address tried
pub fn Listener::bind(address: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<Self, Failure>
pub fn Listener::on_port(port: &webrtc::Port, tls: Arc<rustls::ServerConfig>) -> Result<Self, Failure>  // feature webrtc; one per port, a second is Failure::Permission
pub const fn Listener::with_limits(self, limits: Limits) -> Self
pub fn Listener::with_origins(self, origins: impl IntoIterator<Item = String>) -> Self
pub fn Listener::with_admission(self, admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static) -> Self
pub fn Listener::with_tls_per_connection(self, tls: impl Fn(SocketAddr, SocketAddr) -> Arc<rustls::ServerConfig> + Send + Sync + 'static) -> Self  // (source, local) -> this connection's TLS
pub const fn Listener::local_addr(&self) -> SocketAddr
pub fn Listener::next(&self, timeout: Option<Duration>) -> Result<Pending, Failure>
pub const fn Pending::peer_addr(&self) -> SocketAddr                         // the source admission judged; on a Port the client's, not its relay's
pub const fn Pending::local_addr(&self) -> SocketAddr                        // the address the client reached; on a wildcard bind the one it sent to, on a Port the port's
pub fn Pending::canceller(&self) -> Cancel                                   // abandons the handshake from another thread
pub fn Pending::handshake(self) -> Result<Channel, Failure>
pub fn Listener::accept(&self, timeout: Option<Duration>) -> Result<Channel, Failure>
```

`with_tls_per_connection` builds each connection's TLS configuration in `Pending::handshake`, before its QUIC handshake, from the source and the local address `Pending` reports, so a client certificate verifier can judge a client by both, or keep strangers from different sources apart. The handshake itself runs on the listener's runtime threads, where nothing set up around `Pending::handshake` (a thread-local scope) is in force. Its ALPN is set to WebTransport's; without it every connection gets the configuration the listener was bound with. A dialer whose certificate the server refuses, or which presented none to a server requiring one, fails with `Failure::Certificate`, as a TLS WebSocket reads the same alerts (bad, unsupported, revoked, expired or unknown certificate, unknown CA, access denied, certificate required); another TLS alert is `Failure::Unsupported`.

`Listener::next` sends a source to retry first, since UDP sources are forgeable, then judges it by admission, and `Pending::handshake` completes it. A source admission refuses, or a `Pending` dropped before its handshake, is closed with QUIC's CONNECTION_REFUSED, which its dialer reports as `Failure::Permission` and never falls back from. The client cannot tell that from any QUIC server refusing a connection (quinn also does when it runs out of connection IDs), and anyone who saw its first packet can forge one, as with a TCP reset. Each dialer and listener runs its own runtime, and its calls block. Inside an async runtime, call them from its blocking pool.

`send` waits up to `Limits::send` for the peer's flow control, then ends the stream with `Failure::NoProgress`. `send_timeout(Some(t))` waits `t` instead: `Failure::Timeout` if nothing of the message went, and the channel goes on; `Failure::NoProgress` if part of it went, and the stream ends, since nothing can follow half a frame. Flow control often takes part of a message before it stops, so expect either. `send_timeout(None)` is `send`.

## The ladder (`coqui_transport_web::webrtc`, feature `webrtc`)

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

- A dialled channel, from `connect` or a `Connector`, is open and unauthenticated. `connect` returns it as `Unverified`.

- `Unverified` proves nothing about the peer. Run the identity proof before `into_verified`.
- `connect` never retries after returning, and an endpoint with pins never falls back, even on a path failure.
- A pin needs a certificate valid for at most 14 days, ECDSA P-256, in browsers and in `Dialer::pinned` alike. Otherwise it is refused as `Failure::Certificate`.
- A WebTransport dialer given a host name tries every address it resolves to, the families taking turns from the resolver's first, a new attempt every 250 ms beside those still opening (RFC 8305); the first to open wins. A failure that is not about the path, such as a rejected certificate, ends the dial at once, whichever address gave it. The name is resolved by the system before the dial's timeout starts, as a WebSocket dialer's is. An address literal is dialled as it is.
- WebSocket `Text` frames: `Channel::send` refuses bytes that are not UTF-8 before they reach the wire.
- `Dialer::with_local_addr` (both drivers) binds before connecting, so a listener's admission and `Pending::peer_addr` see that
  address. Give port 0. Only endpoint addresses of its family are tried. An address this host cannot bind, or an endpoint with
  none of its family, fails the dial with `Failure::Unsupported` before anything is sent (`Failure::Permission` when the address
  is taken or not allowed). A second loopback address such as `127.0.0.2` works only where the system binds it and routes it to
  loopback; where it cannot be bound, the dial is that `Failure::Unsupported`.
- A WebSocket or WebTransport channel reads ahead of its reader, up to `pending` messages or what `set_pending` set, and judges
  each by the receive bound in force when it reads it. A bound raised just before `receive` does not
  reach a message already being read: raise it before the peer can send larger, or that message ends the channel with
  `Failure::Protocol` at both ends. To read the next message under a small bound and the rest under a larger one, as with a peer
  that still owes a proof, stage it with `set_max_receive_after(1, larger)` before the peer can send either.
- `set_pending` after a handshake reaches only what the driver has not read yet, and a driver starts reading as soon as the channel
  opens: up to `Limits::pending` messages (64 by default) may already be held by then. To hold a peer that still owes a proof to one
  message from its first, give the listener `Limits::with_pending(1)` and call `set_pending` with a larger value on each channel once
  its peer is proved. Besides those messages, a channel holds only bytes below them, none of which `max_message` multiplies: what
  its last read brought in beyond the message (under tungstenite's 128 KiB read buffer on a WebSocket, under 16 KiB on WebTransport),
  what TLS has decrypted, and the transport's own window: the system's TCP receive buffer, or QUIC's stream window (quinn's default,
  1,250,000 bytes).
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
