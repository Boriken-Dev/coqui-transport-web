import 'contracts.dart';
import 'websocket.dart';
import 'webtransport.dart';

export 'contracts.dart';

typedef WebDialer = Future<WebChannel> Function(
  Uri uri,
  Duration timeout,
  List<String> certificatePins,
);

/// Opens a reliable, ordered message channel. This does not authenticate a peer,
/// start an application protocol, or authorize anything.
///
/// Prefer browser WebTransport, falling back to an EXPLICIT WSS endpoint
/// only on unavailable transport. Never fall back after authentication,
/// protocol, or a pinned-certificate failure. The caller must bind both
/// endpoints to one verified peer before processing application messages.
Future<WebChannel> connectWebChannel(
  WebEndpoints endpoints, {
  Duration timeout = const Duration(seconds: 10),
  WebDialer? webTransportDialer,
  WebDialer? webSocketDialer,
}) async {
  final wt = endpoints.webTransport;
  final ws = endpoints.webSocket;
  if (wt != null) {
    try {
      return await (webTransportDialer ?? openWebTransportChannel)(
        wt, timeout, endpoints.certificatePins,
      );
    } on TransportUnavailable {
      if (ws == null) rethrow;
    }
  }
  if (ws != null) {
    return (webSocketDialer ?? openWebSocketChannel)(ws, timeout, const []);
  }
  throw const TransportUnavailable('No usable endpoint');
}
