import 'contracts.dart';
import 'websocket.dart';
import 'webtransport.dart';

export 'contracts.dart';

typedef WebDialer =
    Future<WebChannel> Function(
      Uri uri,
      Duration timeout,
      List<String> certificatePins,
    );

/// Opens a reliable, ordered message channel. This does not authenticate a peer,
/// start an application protocol, or authorize anything.
///
/// Prefer browser WebTransport, falling back to an EXPLICIT WSS endpoint when the
/// transport is unavailable or an opening breaks the wire format, since the same
/// peer must still prove itself there. Never fall back after an authentication or
/// a pinned-certificate failure. The caller must bind both
/// endpoints to one verified peer before processing application messages.
///
/// [webSocketDatagrams] asks a WebSocket's server to agree to datagrams, up to [maxWebSocketDatagram]. WebTransport has its own either way.
Future<WebChannel> connectWebChannel(
  WebEndpoints endpoints, {
  Duration timeout = const Duration(seconds: 10),
  WebDialer? webTransportDialer,
  WebDialer? webSocketDialer,
  bool webSocketDatagrams = false,
  int maxWebSocketDatagram = defaultWebSocketDatagram,
}) async {
  final wt = endpoints.webTransport;
  final ws = endpoints.webSocket;
  if (wt != null) {
    try {
      return await (webTransportDialer ?? openWebTransportChannel)(
        wt,
        timeout,
        endpoints.certificatePins,
      );
    } on TransportUnavailable {
      if (ws == null) rethrow;
    } on TransportProtocolFailure {
      if (ws == null) rethrow;
    }
  }
  if (ws != null) {
    final dial = webSocketDialer;
    if (dial != null) return dial(ws, timeout, const []);
    return openWebSocketChannel(
      ws,
      timeout,
      const [],
      datagrams: webSocketDatagrams,
      maxDatagram: maxWebSocketDatagram,
    );
  }
  throw const TransportUnavailable('No usable endpoint');
}
