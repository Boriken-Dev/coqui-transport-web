# coqui-transport-web

A reliable message channel a browser can open natively, and the native peer for it. WebTransport first, WebSocket as an explicit
fallback. The library knows nothing of the application above it and proves nothing about who the peer is. It implements
[`coqui-transport`](https://github.com/Boriken-Dev/coqui-transport)'s `Channel`, `Datagrams`, `Connector` and `Listener`, and it was
`coqui-web-channel`, which now re-exports it.

!!! note "Alpha"
    Not published yet: the API may change in any release before 1.0.

## The wire

- **WebTransport**: one reliable bidirectional stream the client opens. Each message is a little-endian `u32` body length, then
  the body (`coqui-transport`'s `LengthPrefix::u32_le().refuse_empty()`). Non-empty, at most 1 MiB unless the application chooses otherwise. Raw datagrams may go beside it.
- **WebSocket**: one application message per WebSocket message, with no prefix. Text by default.

`tests/vectors/frames.json` holds the wire as data; the Rust and Dart suites both run it. `tests/vectors/webtransport_frame.json` holds the
bytes the stream framing produced before it moved onto `coqui-transport`'s codec, and the Rust suite checks the codec against them.

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

## A ladder of datagrams

A browser with no WebTransport, or a path where QUIC is blocked, can still have real unreliable delivery, with the `webrtc` feature and
`DataChannelSettings` in Dart, both off by default:

1. WebTransport's own datagrams, when WebTransport opened.
2. A WebRTC data channel on the same UDP port number.
3. Inside the WebSocket.

```rust
let port = webrtc::Port::bind(address, webrtc::Settings::default())?;
let quic = webtransport::Listener::builder(port.clone(), tls.clone()).build()?;
let websocket = websocket::Listener::builder(port.local_addr(), websocket::ServerTls::Config(tls)).webrtc(&port).build()?;
```

**One port.** A `Port` owns the socket and reads the first byte of each packet, as [RFC 9443](https://www.rfc-editor.org/rfc/rfc9443) lays out: QUIC goes through a relay to an unmodified
`wtransport`, STUN and DTLS to a data channel, and anything else is dropped. STUN or DTLS without a session's credentials gets no reply;
QUIC is answered as any QUIC server answers, with a Retry first. The relay map has a cap, a share for each IP address and an idle expiry
that only the listener's side resets. A relay whose handshake finished is never replaced, and ends with its connection. A flood of forged
sources can still hold back new WebTransport sessions, which then fall back like any other that fails, and it shares the port's thread
with the data channels. QUIC must not grease its fixed bit on a shared port, so this listener does not offer to.

**Who may use a data channel's path.** A server answers checks only from its WebSocket peer's IP address, routes each check by the
username fragment it names, and once the peer nominates a source hears from that source alone. So a client holding the credentials can
neither point the server's traffic at someone else nor take another client's path. Behind a proxy, where the WebSocket peer is the proxy,
`any_candidate` lifts the address check and only the hold to the nominated source remains.

**Climbing.** A client that asks offers `coqui-web-ladder.1` before `coqui-web-datagrams.1`, and a server with a port chooses it, which adds
tag 2 to the binary messages: a signal, one byte (1 offer, 2 answer, 3 refused) and a session description. Datagrams start in the WebSocket.
When a caller first asks for them, the client creates the data channel, unordered with no retransmits, and offers over the channel it has.
The server, ICE-lite with one host candidate, answers once its own caller has asked too. When the channel opens both ends switch.
`delivery` and `max_size` follow the path, an event says so, and a datagram over the limit is refused, never moved. A data channel's limit
is what fits one packet of `path_mtu`, because a fragment lost is the whole datagram lost. If the path later dies they go back to the WebSocket,
with an event, and nothing tries again. If UDP is blocked only the attempt is lost: 5 s by default, a setting, as is turning it off.

**Identity.** Signals on the WebSocket have what TLS gives them. A caller with a proven, sealed link can carry them itself (`Signaling::ByCaller`,
`carriedSignals` in Dart). The DTLS fingerprints are then inside the proof, and so are that data channel's datagrams, which WebTransport's and
the WebSocket's are not. While that data channel is open, a datagram tagged inside the WebSocket is discarded and counted rather than
delivered beside them.

**Addresses.** An offer goes with no candidates, so it names nothing about the client; the server learns it from the first check. A server
names one candidate: the address the WebSocket arrived at, or `public_address`. Set that behind a proxy or NAT, or the candidate is wrong
and reveals the address behind it. A candidate naming anywhere else is refused by the Rust client, and by a browser's where it dialled an
address rather than a name.

**A reverse proxy.** nginx in front of the WebSocket does nothing for UDP. Give the port a `stream` block, or let clients reach the host's own
port and set `public_address`. Without one the attempt fails and the ladder ends at the WebSocket.

[Choosing a transport](fallback.md) explains when another transport may be tried.
