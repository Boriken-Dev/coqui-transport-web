# Choosing a transport

1. Dial the explicitly advertised `https://` WebTransport endpoint.
2. On unsupported WebTransport, a timeout or a lost path, use the *explicitly advertised* `wss://` endpoint. A fallback host is never
   synthesized, and peer identity is never inferred from DNS.
3. While opening, whatever says WebTransport is not working there tries that endpoint too: a server that does not offer it, or an
   opening that breaks the wire format. The other transport must still prove the same peer, so nothing is given up.
4. A certificate, identity or permission failure never falls back, since each may be someone in the way. A QUIC server refusing the
   connection is a permission failure. Once a channel is open, a
   protocol failure never falls back either: a proven peer, or someone on the path, broke the format. An endpoint with pinned
   certificates never falls back at all, since a browser cannot always tell its failures apart.
4. If an established channel stops making progress, an application may open WebSocket, but must prove the **same** peer before
   delivering any message, and reconcile its own session. An operation of unknown outcome is never replayed automatically.

## Loss and MTU

QUIC requires a path carrying at least 1200 bytes of UDP payload ([RFC 9000 section 14](https://www.rfc-editor.org/rfc/rfc9000#section-14)).
Below that, WebTransport fails or stalls while TCP may still work. Browser JavaScript cannot generally tell a QUIC blackhole from any
other connection failure, so a dial timeout is the signal. A `Preflight` probe can catch a path that opens and then stalls, if both ends support one.

An idle channel is not stalled merely because nobody has typed: detecting failure needs a negotiated ping or an outstanding-operation deadline.
