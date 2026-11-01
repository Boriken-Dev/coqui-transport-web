import 'dart:async';
import 'dart:convert';

import 'package:web_socket_channel/web_socket_channel.dart';

import 'contracts.dart';

Future<WebChannel> openWebSocketChannel(
  Uri uri,
  Duration timeout,
  List<String> certificatePins,
) async {
  final channel = WebSocketChannel.connect(uri);
  try {
    await channel.ready.timeout(timeout);
  } catch (e) {
    unawaited(channel.sink.close());
    throw TransportUnavailable('WebSocket could not connect: $e');
  }
  return _WebSocketConnection(channel);
}

final class _WebSocketConnection implements WebChannel {
  _WebSocketConnection(this._channel) {
    _subscription = _channel.stream.listen(
      (dynamic message) {
        if (_ended) return;
        if (message is! String || utf8.encode(message).length > defaultMaxMessage) {
          _end(const TransportProtocolFailure('WebSocket messages must be bounded UTF-8 text'));
          unawaited(close());
        } else {
          _incoming.add(message);
        }
      },
      onError: (Object error) {
        _end(error);
        unawaited(close());
      },
      onDone: () {
        _end();
        unawaited(close());
      },
      cancelOnError: true,
    );
  }
  final WebSocketChannel _channel;
  final StreamController<String> _incoming = StreamController<String>();
  late final StreamSubscription<dynamic> _subscription;
  bool _ended = false;
  bool _released = false;

  @override
  WebChannelKind get kind => WebChannelKind.webSocket;
  @override
  Stream<String> get messages => _incoming.stream;

  void _end([Object? error]) {
    if (_ended) return;
    _ended = true;
    if (error != null) _incoming.addError(error);
    unawaited(_incoming.close());
  }

  @override
  Future<void> send(String message) async {
    if (_ended) throw const TransportUnavailable('WebSocket connection closed');
    if (message.isEmpty || utf8.encode(message).length > defaultMaxMessage) {
      throw const TransportProtocolFailure('WebSocket message exceeds limits or is empty');
    }
    _channel.sink.add(message);
  }

  @override
  Future<void> close() async {
    // A stream that already ended still holds its socket.
    if (_released) return;
    _released = true;
    _end();
    await _subscription.cancel();
    // A peer that never answers the close handshake must not hold the caller.
    try {
      await _channel.sink.close().timeout(const Duration(seconds: 2));
    } catch (_) {}
  }
}
