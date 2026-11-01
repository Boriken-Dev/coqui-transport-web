import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

enum WebChannelKind { webTransport, webSocket }

/// A channel is not an authenticated session. A caller must run the verified
/// peer handshake before emitting or accepting application messages.
abstract interface class WebChannel {
  WebChannelKind get kind;
  Stream<String> get messages;
  Future<void> send(String message);
  Future<void> close();
}

/// A channel that also carries binary messages. [bytes] holds every message, a text one as its UTF-8, and is an alternative to
/// `messages`: listen to one of them.
abstract interface class ByteWebChannel implements WebChannel {
  Stream<Uint8List> get bytes;
  Future<void> sendBytes(Uint8List message);
}

class TransportUnavailable implements Exception {
  const TransportUnavailable(this.reason);
  final String reason;
  @override
  String toString() => 'Transport unavailable: $reason';
}

class TransportSecurityFailure implements Exception {
  const TransportSecurityFailure(this.reason);
  final String reason;
  @override
  String toString() => 'Transport security failure: $reason';
}

class TransportProtocolFailure implements Exception {
  const TransportProtocolFailure(this.reason);
  final String reason;
  @override
  String toString() => 'Transport protocol failure: $reason';
}

/// Explicit endpoints for one authenticated peer. Never derive a different
/// WebSocket host or port from an HTTPS WebTransport URL.
final class WebEndpoints {
  WebEndpoints({
    this.webTransport,
    this.webSocket,
    this.certificatePins = const [],
    this.allowLocalPlainWebSocket = false,
    bool impliedPort = false,
  }) {
    if (webTransport == null && webSocket == null) {
      throw ArgumentError('At least one endpoint is required');
    }
    if (webTransport case final url?) {
      if (url.scheme != 'https' ||
          !(url.hasPort || impliedPort) ||
          !_plainUrl(url)) {
        throw ArgumentError.value(
          url,
          'webTransport',
          'Use HTTPS with an explicit port and no URL credentials, query or fragment',
        );
      }
    }
    if (webSocket case final url?) {
      final loopback = _isLoopback(url.host);
      if ((url.scheme != 'wss' &&
              !(url.scheme == 'ws' && loopback && allowLocalPlainWebSocket)) ||
          !_plainUrl(url)) {
        throw ArgumentError.value(
          url,
          'webSocket',
          'Use WSS, or explicitly allow WS on localhost',
        );
      }
    }
    if (webTransport != null &&
        webSocket != null &&
        webTransport!.host.toLowerCase() != webSocket!.host.toLowerCase()) {
      throw ArgumentError(
        'WebTransport and fallback WebSocket must share a host',
      );
    }
    if (certificatePins.isNotEmpty && webTransport == null) {
      throw ArgumentError(
        'WebTransport certificate pins require a WebTransport endpoint',
      );
    }
    for (final pin in certificatePins) {
      if (!RegExp(r'^sha256:[0-9a-fA-F]{64}$').hasMatch(pin)) {
        throw ArgumentError.value(
          pin,
          'certificatePins',
          'Expected sha256:<64 hex digits>',
        );
      }
    }
  }

  /// One `https://host/path`, or with a port, for both: WebTransport on that UDP port and WebSocket on that TCP port, which
  /// can be the same number on the same name. Without a port that is 443.
  factory WebEndpoints.address(
    Uri url, {
    List<String> certificatePins = const [],
  }) {
    if (url.scheme != 'https') {
      throw ArgumentError.value(url, 'url', 'An address uses HTTPS');
    }
    return WebEndpoints(
      webTransport: url,
      webSocket: url.replace(scheme: 'wss'),
      certificatePins: certificatePins,
      impliedPort: true,
    );
  }

  final Uri? webTransport;
  final Uri? webSocket;
  final List<String> certificatePins;
  final bool allowLocalPlainWebSocket;

  static bool _plainUrl(Uri url) =>
      url.hasAuthority &&
      url.host.isNotEmpty &&
      url.userInfo.isEmpty &&
      !url.hasQuery &&
      !url.hasFragment;
  static bool _isLoopback(String host) =>
      host == 'localhost' || host == '127.0.0.1' || host == '::1';
}

/// One message as text; what is not UTF-8 is a protocol failure.
String decodeText(Uint8List bytes) {
  try {
    return utf8.decode(bytes);
  } on FormatException {
    throw const TransportProtocolFailure('A text message is not UTF-8');
  }
}

/// A message is length-prefixed only *inside a WebTransport stream*. A WebSocket
/// message is already whole and carries one application message.
const defaultMaxMessage = 1024 * 1024;

Uint8List encodeFrame(String text, {int maxBytes = defaultMaxMessage}) =>
    encodeBytesFrame(utf8.encode(text), maxBytes: maxBytes);

Uint8List encodeBytesFrame(
  Uint8List bytes, {
  int maxBytes = defaultMaxMessage,
}) {
  if (bytes.isEmpty || bytes.length > maxBytes) {
    throw const TransportProtocolFailure(
      'Message exceeds frame limits or is empty',
    );
  }
  final frame = Uint8List(4 + bytes.length);
  ByteData.sublistView(frame, 0, 4).setUint32(0, bytes.length, Endian.little);
  frame.setRange(4, frame.length, bytes);
  return frame;
}

/// An incremental decoder for fragmented or coalesced stream bytes: [push] what
/// arrived, then call [nextText] until it answers null. Frames complete before a
/// bad header come before the failure, and a failed decoder stays failed.
final class FrameDecoder {
  FrameDecoder({this.maxBytes = defaultMaxMessage});
  final int maxBytes;
  final List<int> _buffer = [];
  bool _failed = false;

  void push(Uint8List chunk) {
    if (!_failed) _buffer.addAll(chunk);
  }

  /// The next complete frame's bytes, or null until more arrive.
  Uint8List? nextBytes() {
    if (_failed) {
      throw const TransportProtocolFailure(
        'WebTransport frame is empty or exceeds the limit',
      );
    }
    if (_buffer.length < 4) return null;
    // Multiplied rather than shifted: dart2js shifts are signed 32-bit.
    final size =
        _buffer[0] +
        (_buffer[1] << 8) +
        (_buffer[2] << 16) +
        _buffer[3] * 0x1000000;
    if (size < 1 || size > maxBytes) {
      _failed = true;
      _buffer.clear();
      throw const TransportProtocolFailure(
        'WebTransport frame is empty or exceeds the limit',
      );
    }
    if (_buffer.length - 4 < size) return null;
    final body = Uint8List.fromList(_buffer.sublist(4, 4 + size));
    _buffer.removeRange(0, 4 + size);
    return body;
  }

  /// The next complete frame as UTF-8 text, or null until more arrive.
  String? nextText() {
    final body = nextBytes();
    if (body == null) return null;
    try {
      return utf8.decode(body);
    } on FormatException {
      _failed = true;
      _buffer.clear();
      throw const TransportProtocolFailure(
        'Invalid UTF-8 in WebTransport frame',
      );
    }
  }
}
