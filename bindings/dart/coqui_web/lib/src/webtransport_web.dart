import 'dart:async';
import 'dart:js_interop';
import 'dart:typed_data';

import 'contracts.dart';

@JS('globalThis.WebTransport')
external JSAny? get _webTransportConstructor;

@JS('WebTransport')
extension type _WebTransport._(JSObject _) implements JSObject {
  external factory _WebTransport(String url, JSObject options);
  external JSPromise<JSAny?> get ready;
  external JSPromise<JSAny?> get closed;
  external JSPromise<_Duplex> createBidirectionalStream();
  external _DatagramDuplex get datagrams;
  external void close();
}

extension type _DatagramDuplex._(JSObject _) implements JSObject {
  external _Readable get readable;
  external _Writable get writable;
  external int? get maxDatagramSize;
}

extension type _Duplex._(JSObject _) implements JSObject {
  external _Readable get readable;
  external _Writable get writable;
}
extension type _Readable._(JSObject _) implements JSObject {
  external _Reader getReader();
}
extension type _Reader._(JSObject _) implements JSObject {
  external JSPromise<_ReadResult> read();
  external JSPromise<JSAny?> cancel();
}
extension type _ReadResult._(JSObject _) implements JSObject {
  external bool get done;
  external JSUint8Array? get value;
}
extension type _Writable._(JSObject _) implements JSObject {
  external _Writer getWriter();
}
extension type _Writer._(JSObject _) implements JSObject {
  external JSPromise<JSAny?> write(JSUint8Array chunk);
  external JSPromise<JSAny?> close();
}
extension type _Hash._(JSObject _) implements JSObject {
  external factory _Hash({String algorithm, JSUint8Array value});
}
extension type _Options._(JSObject _) implements JSObject {
  external factory _Options({JSArray<_Hash> serverCertificateHashes});
}

Uint8List _unhex(String pin) {
  final text = pin.substring('sha256:'.length);
  return Uint8List.fromList([
    for (var i = 0; i < text.length; i += 2)
      int.parse(text.substring(i, i + 2), radix: 16),
  ]);
}

Future<WebChannel> openWebTransportChannel(
  Uri uri,
  Duration timeout,
  List<String> certificatePins,
) async {
  if (_webTransportConstructor == null) {
    throw const TransportUnavailable(
      'This browser does not implement WebTransport',
    );
  }
  final _WebTransport transport;
  try {
    final pins = [
      for (final pin in certificatePins)
        _Hash(algorithm: 'sha-256', value: _unhex(pin).toJS),
    ];
    transport = _WebTransport(
      uri.toString(),
      pins.isEmpty ? JSObject() : _Options(serverCertificateHashes: pins.toJS),
    );
  } catch (e) {
    // Browsers may deliberately obscure TLS diagnostics. A failed pinned
    // endpoint MUST NOT downgrade to an unpinned WebSocket.
    if (certificatePins.isNotEmpty) {
      throw const TransportSecurityFailure(
        'Pinned WebTransport connection rejected',
      );
    }
    throw TransportUnavailable('WebTransport construction failed: $e');
  }
  try {
    final duplex = await transport.ready.toDart
        .then((_) => transport.createBidirectionalStream().toDart)
        .timeout(timeout);
    final link = _WebTransportConnection(
      transport,
      duplex.readable.getReader(),
      duplex.writable.getWriter(),
    );
    link.start();
    return link;
  } catch (e) {
    try {
      transport.close();
    } catch (_) {}
    if (certificatePins.isNotEmpty) {
      throw const TransportSecurityFailure(
        'Pinned WebTransport connection rejected',
      );
    }
    throw TransportUnavailable('WebTransport could not establish a stream: $e');
  }
}

final class _Datagrams implements WebDatagrams {
  _Datagrams(this._duplex);
  final _DatagramDuplex _duplex;
  _Writer? _writer;
  _Reader? _reader;
  late final StreamController<Uint8List> _incoming =
      StreamController<Uint8List>.broadcast(onListen: () => unawaited(_read()));

  @override
  int? get maxSize => _duplex.maxDatagramSize;

  @override
  WebDatagramDelivery get delivery => WebDatagramDelivery.unreliable;

  @override
  Stream<WebDatagramDelivery> get changes => const Stream.empty();

  // A browser says nothing of what it discards.
  @override
  int get dropped => 0;

  @override
  Stream<Uint8List> get incoming => _incoming.stream;

  Future<void> _read() async {
    if (_reader != null) return;
    final reader = _reader = _duplex.readable.getReader();
    try {
      for (;;) {
        final read = await reader.read().toDart;
        if (read.done) break;
        final bytes = read.value?.toDart;
        if (bytes != null) _incoming.add(bytes);
      }
    } catch (_) {
      // The session ended, which the channel itself reports.
    }
    unawaited(_incoming.close());
  }

  @override
  Future<void> send(Uint8List datagram) async {
    final limit = maxSize;
    if (limit != null && datagram.length > limit) {
      throw const TransportProtocolFailure(
        'A datagram larger than the path takes',
      );
    }
    final writer = _writer ??= _duplex.writable.getWriter();
    try {
      await writer.write(datagram.toJS).toDart;
    } catch (e) {
      throw TransportUnavailable('WebTransport datagram failed: $e');
    }
  }

  void end() {
    final reader = _reader;
    if (reader != null) {
      unawaited(reader.cancel().toDart.catchError((_) => null));
    }
    if (_reader == null && !_incoming.isClosed) {
      unawaited(_incoming.close());
    }
  }
}

final class _WebTransportConnection implements DatagramWebChannel {
  _WebTransportConnection(this._transport, this._reader, this._writer);
  final _WebTransport _transport;
  final _Reader _reader;
  final _Writer _writer;
  final StreamController<Uint8List> _messages = StreamController<Uint8List>();
  final FrameDecoder _decoder = FrameDecoder();
  late final _Datagrams _datagrams = _Datagrams(_transport.datagrams);
  bool _ended = false;
  bool _released = false;

  @override
  WebDatagrams get datagrams => _datagrams;

  @override
  CarriedSignals? get carriedSignals => null;

  @override
  WebChannelKind get kind => WebChannelKind.webTransport;
  @override
  Stream<String> get messages => _messages.stream.map(decodeText);
  @override
  Stream<Uint8List> get bytes => _messages.stream;

  void start() {
    unawaited(_read());
    _transport.closed.toDart.then(
      (_) {
        _end();
        unawaited(close());
      },
      onError: (Object error) {
        _end(TransportUnavailable('WebTransport closed: $error'));
        unawaited(close());
      },
    );
  }

  Future<void> _read() async {
    try {
      while (!_ended) {
        final read = await _reader.read().toDart;
        if (read.done) break;
        final bytes = read.value?.toDart;
        if (bytes == null) {
          throw const TransportProtocolFailure(
            'Null WebTransport stream chunk',
          );
        }
        _decoder.push(bytes);
        for (
          var body = _decoder.nextBytes();
          body != null;
          body = _decoder.nextBytes()
        ) {
          if (_ended) return;
          _messages.add(body);
        }
      }
      _end();
    } catch (e) {
      _end(e);
    }
    unawaited(close());
  }

  void _end([Object? error]) {
    if (_ended) return;
    _ended = true;
    if (error != null) _messages.addError(error);
    unawaited(_messages.close());
  }

  @override
  Future<void> send(String message) => _write(encodeFrame(message));

  @override
  Future<void> sendBytes(Uint8List message) =>
      _write(encodeBytesFrame(message));

  Future<void> _write(Uint8List frame) async {
    if (_ended) {
      throw const TransportUnavailable('WebTransport connection closed');
    }
    try {
      await _writer.write(frame.toJS).toDart;
    } catch (e) {
      _end(e);
      unawaited(close());
      throw TransportUnavailable('WebTransport send failed: $e');
    }
  }

  @override
  Future<void> close() async {
    // A stream that already ended still holds its session.
    if (_released) return;
    _released = true;
    _end();
    _datagrams.end();
    try {
      await _writer.close().toDart.timeout(const Duration(seconds: 2));
    } catch (_) {}
    try {
      await _reader.cancel().toDart;
    } catch (_) {}
    try {
      _transport.close();
    } catch (_) {}
  }
}
