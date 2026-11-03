import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:web_socket_channel/web_socket_channel.dart';

import 'contracts.dart';
import 'datachannel.dart';
import 'datachannel_path.dart';

/// [datagrams] asks the server to agree to them. One that does not still connects, and has none: see [datagramsOf].
/// [dataChannel] also asks to climb onto a data channel, which starts when the datagrams are first asked for.
Future<WebChannel> openWebSocketChannel(
  Uri uri,
  Duration timeout,
  List<String> certificatePins, {
  bool datagrams = false,
  int maxDatagram = defaultWebSocketDatagram,
  DataChannelSettings? dataChannel,
}) async {
  final climbing = datagrams && (dataChannel?.enabled ?? false);
  final channel = WebSocketChannel.connect(
    uri,
    protocols: climbing
        ? const [webSocketLadderProtocol, webSocketDatagramsProtocol]
        : datagrams
        ? const [webSocketDatagramsProtocol]
        : null,
  );
  try {
    await channel.ready.timeout(timeout);
  } catch (e) {
    unawaited(channel.sink.close());
    throw TransportUnavailable('WebSocket could not connect: $e');
  }
  return _WebSocketConnection(
    channel,
    tagged:
        datagrams &&
        (channel.protocol == webSocketDatagramsProtocol ||
            channel.protocol == webSocketLadderProtocol),
    maxDatagram: maxDatagram,
    endpoint: uri,
    climb: climbing && channel.protocol == webSocketLadderProtocol
        ? dataChannel
        : null,
  );
}

const _messageTag = 0;
const _datagramTag = 1;
const _signalTag = 2;

final class _WebSocketDatagrams implements WebDatagrams, DataChannelEvents {
  _WebSocketDatagrams(this._connection, this._maxOverStream);
  final _WebSocketConnection _connection;
  final int _maxOverStream;
  final StreamController<Uint8List> _arrived =
      StreamController<Uint8List>.broadcast();
  final StreamController<WebDatagramDelivery> _changes =
      StreamController<WebDatagramDelivery>.broadcast();
  DataChannelPath? _path;

  bool get _climbed => _path?.isOpen ?? false;

  @override
  int get maxSize => _climbed ? _path!.maxSize : _maxOverStream;

  @override
  WebDatagramDelivery get delivery => _climbed
      ? WebDatagramDelivery.unreliable
      : WebDatagramDelivery.overStream;

  @override
  Stream<WebDatagramDelivery> get changes => _changes.stream;

  @override
  Stream<Uint8List> get incoming => _arrived.stream;

  @override
  void signal(Uint8List signal) => _connection._sendSignal(signal);

  @override
  void opened() => _changes.add(WebDatagramDelivery.unreliable);

  @override
  void ended() => _changes.add(WebDatagramDelivery.overStream);

  @override
  void arrived(Uint8List datagram) {
    // The setting is for the WebSocket: the data channel has its own limit, already applied.
    if (_arrived.hasListener) {
      _arrived.add(datagram);
    } else {
      dropped += 1;
    }
  }

  @override
  void discarded() => dropped += 1;

  @override
  int dropped = 0;

  /// One that came inside the WebSocket. Once a data channel whose signals the caller carried is open, only TLS protects such a one
  /// and everything arriving is meant to be inside the peer proof, so it is discarded and counted.
  void arrive(Uint8List body) {
    if (_climbed && _connection._carriedSignals != null) {
      dropped += 1;
      return;
    }
    if (body.length > _maxOverStream || !_arrived.hasListener) {
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
    if (_climbed) {
      _path!.send(datagram);
    } else {
      _connection._sendTagged(_datagramTag, datagram);
    }
  }

  void end() {
    _path?.close();
    unawaited(_arrived.close());
    unawaited(_changes.close());
  }
}

/// The signals of a channel that leaves them to its caller.
final class _CarriedSignals implements CarriedSignals {
  _CarriedSignals(this._connection);
  final _WebSocketConnection _connection;
  final StreamController<Uint8List> _outgoing = StreamController<Uint8List>();

  @override
  Stream<Uint8List> get outgoing => _outgoing.stream;

  @override
  void deliver(Uint8List signal) => _connection._deliverSignal(signal);

  void end() => unawaited(_outgoing.close());
}

final class _WebSocketConnection implements DatagramWebChannel {
  _WebSocketConnection(
    this._channel, {
    bool tagged = false,
    int maxDatagram = defaultWebSocketDatagram,
    Uri? endpoint,
    DataChannelSettings? climb,
  }) : _endpoint = endpoint,
       _climb = climb {
    if (tagged) _datagrams = _WebSocketDatagrams(this, maxDatagram);
    if (climb?.carriedSignals ?? false) {
      _carriedSignals = _CarriedSignals(this);
    }
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
  final Uri? _endpoint;
  final DataChannelSettings? _climb;
  _CarriedSignals? _carriedSignals;
  bool _started = false;

  /// The first asking for these starts the climb, as at the other end: nothing goes out for a caller with no use for them.
  @override
  WebDatagrams? get datagrams {
    final datagrams = _datagrams;
    final climb = _climb;
    if (datagrams != null && climb != null && !_started && !_ended) {
      _started = true;
      datagrams._path = startDataChannel(_endpoint!, climb, datagrams);
    }
    return datagrams;
  }

  @override
  CarriedSignals? get carriedSignals => _carriedSignals;

  void _deliverSignal(Uint8List signal) => _datagrams?._path?.deliver(signal);

  void _sendSignal(Uint8List signal) {
    final carried = _carriedSignals;
    if (carried != null) {
      carried._outgoing.add(signal);
    } else if (!_ended) {
      _sendTagged(_signalTag, signal);
    }
  }

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
    if (binary[0] == _signalTag && _climb != null) {
      // A caller carrying signals trusts none that came any other way.
      if (_carriedSignals == null) _deliverSignal(body);
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
    _carriedSignals?.end();
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
