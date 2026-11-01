# coqui_web

Reliable message channels a browser can open natively: WebTransport first, WebSocket as an explicit
fallback, and a policy that never downgrades after a security failure. The Dart side of
[coqui-web](https://github.com/Boriken-Dev/coqui-web).

A channel is open, not trusted: run the peer's identity proof with `StagedChannel.nextSetupMessage`, then
call `allowApplicationMessages`. No keys, trust decisions or application protocol live here.

The Dart VM has no WebTransport, so it reports `TransportUnavailable` and uses the WebSocket endpoint.
