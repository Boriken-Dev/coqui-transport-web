import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:web_socket_channel/web_socket_channel.dart';

import 'contracts.dart';

/// [datagrams] asks the server to agree to them. One that does not still connects, and has none: see [datagramsOf].
Future<WebChannel> openWebSocketChannel(
  Uri uri,
  Duration timeout,
  List<String> certificatePins, {
  bool datagrams = false,
  int maxDatagram = defaultWebSocketDatagram,
}) async {
  final channel = WebSocketChannel.connect(
    uri,
    protocols: datagrams ? const [webSocketDatagramsProtocol] : null,
  );
  try {
    await channel.ready.timeout(timeout);
  } catch (e) {
    unawaited(channel.sink.close());
    throw TransportUnavailable('WebSocket could not connect: $e');
  }
  return _WebSocketConnection(
    channel,
    tagged: datagrams && channel.protocol == webSocketDatagramsProtocol,
    maxDatagram: maxDatagram,
  );
}

const _messageTag = 0;
const _datagramTag = 1;

final class _WebSocketDatagrams implements WebDatagrams {
  _WebSocketDatagrams(this._connection, this.maxSize);
  final _WebSocketConnection _connection;
  final StreamController<Uint8List> _arrived =
      StreamController<Uint8List>.broadcast();

  @override
  final int maxSize;

  @override
  WebDatagramDelivery get delivery => WebDatagramDelivery.overStream;

  @override
  Stream<Uint8List> get incoming => _arrived.stream;

  @override
  int dropped = 0;

  void arrive(Uint8List body) {
    if (body.length > maxSize || !_arrived.hasListener) {
      dropped += 1;
    } else {
      _arrived.add(body);
    }
  }

  @override
  Future<void> send(Uint8List datagram) async {
    if (datagram.length > maxSize) {
      throw const TransportProtocolFailure(
        'A datagram larger than this channel takes',
      );
    }
    _connection._sendTagged(_datagramTag, datagram);
  }

  void end() => unawaited(_arrived.close());
}

final class _WebSocketConnection implements DatagramWebChannel {
  _WebSocketConnection(
    this._channel, {
    bool tagged = false,
    int maxDatagram = defaultWebSocketDatagram,
  }) {
    if (tagged) _datagrams = _WebSocketDatagrams(this, maxDatagram);
    _subscription = _channel.stream.listen(
      (dynamic message) {
        if (_ended) return;
        final Uint8List? bytes = switch (message) {
          final String text => utf8.encode(text),
          final Uint8List binary => _opened(binary),
          final List<int> binary => _opened(Uint8List.fromList(binary)),
          _ => null,
        };
        if (identical(bytes, _taken)) return;
        if (bytes == null || bytes.length > defaultMaxMessage) {
          _end(
            const TransportProtocolFailure(
              'WebSocket message is unknown or over its limit',
            ),
          );
          unawaited(close());
        } else {
          _incoming.add(bytes);
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

  /// A binary message that was a datagram, and so is no message at all.
  static final Uint8List _taken = Uint8List(0);

  _WebSocketDatagrams? _datagrams;

  @override
  WebDatagrams? get datagrams => _datagrams;

  /// A binary message's body, or null for what no peer may send. An unknown tag is not guessed at.
  Uint8List? _opened(Uint8List binary) {
    final datagrams = _datagrams;
    if (datagrams == null) return binary;
    if (binary.isEmpty) return null;
    final body = Uint8List.sublistView(binary, 1);
    if (binary[0] == _datagramTag) {
      datagrams.arrive(body);
      return _taken;
    }
    return binary[0] == _messageTag && body.isNotEmpty ? body : null;
  }

  void _sendTagged(int tag, Uint8List body) {
    if (_ended) throw const TransportUnavailable('WebSocket connection closed');
    final tagged = Uint8List(body.length + 1);
    tagged[0] = tag;
    tagged.setRange(1, tagged.length, body);
    _channel.sink.add(tagged);
  }

  final WebSocketChannel _channel;
  final StreamController<Uint8List> _incoming = StreamController<Uint8List>();
  late final StreamSubscription<dynamic> _subscription;
  bool _ended = false;
  bool _released = false;

  @override
  WebChannelKind get kind => WebChannelKind.webSocket;
  @override
  Stream<String> get messages => _incoming.stream.map(decodeText);
  @override
  Stream<Uint8List> get bytes => _incoming.stream;

  void _end([Object? error]) {
    if (_ended) return;
    _ended = true;
    if (error != null) _incoming.addError(error);
    unawaited(_incoming.close());
    _datagrams?.end();
  }

  @override
  Future<void> send(String message) async {
    if (_ended) throw const TransportUnavailable('WebSocket connection closed');
    if (message.isEmpty || utf8.encode(message).length > defaultMaxMessage) {
      throw const TransportProtocolFailure(
        'WebSocket message exceeds limits or is empty',
      );
    }
    _channel.sink.add(message);
  }

  @override
  Future<void> sendBytes(Uint8List message) async {
    if (_ended) throw const TransportUnavailable('WebSocket connection closed');
    if (message.isEmpty || message.length > defaultMaxMessage) {
      throw const TransportProtocolFailure(
        'WebSocket message exceeds limits or is empty',
      );
    }
    if (_datagrams != null) {
      _sendTagged(_messageTag, message);
    } else {
      _channel.sink.add(message);
    }
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
