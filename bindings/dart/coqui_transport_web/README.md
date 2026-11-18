# coqui_transport_web

Reliable message channels a browser can open natively: WebTransport first, WebSocket as an explicit
fallback, and a policy that never downgrades after a security failure. The Dart side of
[coqui-transport-web](https://github.com/Boriken-Dev/coqui-transport-web).

A channel is open, not trusted: run the peer's identity proof with `StagedChannel.nextSetupMessage`, then
call `allowApplicationMessages`. A method whose handshake is binary, such as Noise, reads each message with `nextSetupBytes`
and sends with `sendBytes`, both before the handoff. No keys, trust decisions or application protocol live here.

The Dart VM has no WebTransport, so it reports `TransportUnavailable` and uses the WebSocket endpoint.

On the Dart VM a WebSocket reaches its server the way `dart:io` does. A caller whose route is its own (a proxy the platform's library cannot log in to) passes `webSocketDialer: (uri, timeout, pins) => openWebSocketChannel(uri, timeout, pins, connector: (uri, protocols) => IOWebSocketChannel.connect(uri, protocols: protocols, customClient: client))`, and everything after the socket opens is the same.

## Datagrams

`datagramsOf(channel)` gives raw datagrams beside the messages: WebTransport's own, or inside a WebSocket that asked with
`webSocketDatagrams: true`. With `dataChannel: const DataChannelSettings()` a WebSocket also tries to climb onto a WebRTC data channel on
the same address, so a browser with no WebTransport, or a blocked QUIC path, still gets unreliable delivery. It starts on the WebSocket
when `datagramsOf` is first called, offers over the channel it already has, and switches when the data channel opens. `delivery` and
`maxSize` follow the path, `changes` reports each switch, and one over `maxSize` is refused rather than moved. If UDP is blocked only the
attempt is lost. The Dart VM has no WebRTC, and stays on the WebSocket.

With `carriedSignals: true` the offer and answer are left to the caller, through `signalsOf(channel)`. Carried inside a sealed, proven link,
the DTLS fingerprints are bound to that proof, so the data channel's datagrams are too. While it is open, a datagram tagged inside the
WebSocket is discarded and counted in `dropped`.
