# Choosing a transport

1. Dial the explicitly advertised `https://` WebTransport endpoint.
2. On unsupported WebTransport, a timeout or a lost path, use the *explicitly advertised* `wss://` endpoint. A fallback host is never
   synthesized, and peer identity is never inferred from DNS.
3. A certificate, identity, protocol or permission failure is not a path problem and never falls back. An endpoint with pinned
   certificates never falls back at all, since a browser cannot always tell its failures apart.
4. If an established channel stops making progress, an application may open WebSocket, but must prove the **same** peer before
   delivering any message, and reconcile its own session. An operation of unknown outcome is never replayed automatically.

## Loss and MTU

QUIC requires a path carrying at least 1200 bytes of UDP payload ([RFC 9000 section 14](https://www.rfc-editor.org/rfc/rfc9000#section-14)).
Below that, WebTransport fails or stalls while TCP may still work. Browser JavaScript cannot generally tell a QUIC blackhole from any
other connection failure, so a dial timeout is the signal. A `Preflight` probe can catch a path that opens and then stalls, if both ends support one.

An idle channel is not stalled merely because nobody has typed: detecting failure needs a negotiated ping or an outstanding-operation deadline.
