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

/// How a channel's datagrams actually travel, which decides what a caller can do with them.
enum WebDatagramDelivery {
  /// On the network as datagrams: lost, reordered or repeated without notice, and never held up by anything lost before them.
  unreliable,

  /// Inside the channel's own ordered stream: in order and late rather than lost on the way, so one lost packet holds up everything
  /// behind it.
  overStream,
}

/// Raw datagrams beside a channel's messages, whole or not at all. They are outside any identity proof run on the messages, so TLS is
/// all that protects them.
abstract interface class WebDatagrams {
  /// The largest one now. On WebTransport it can change as the path does. On a WebSocket it is a setting, and on a data channel what
  /// fits one packet.
  int? get maxSize;

  /// How these travel now. On a WebSocket that climbs it changes during the connection, which [changes] reports.
  WebDatagramDelivery get delivery;

  /// Each change of path from now on, as the delivery now in force. [maxSize] follows the path, and one over it is refused rather than
  /// moved to another. Nothing ever arrives here on a channel whose path cannot change.
  Stream<WebDatagramDelivery> get changes;

  /// Each one that arrives. On WebTransport a browser keeps a small queue of its own, and what it discards there it does not report.
  Stream<Uint8List> get incoming;

  /// How many this side discarded: on a WebSocket, those too large, and those arriving with nobody listening.
  int get dropped;

  /// Hands one to the transport, which does not report whether it arrived. Throws [TransportProtocolFailure] for one over [maxSize],
  /// which a browser would otherwise drop without a word, and the channel goes on.
  Future<void> send(Uint8List datagram);
}

/// A channel that may have datagrams. Use [datagramsOf].
abstract interface class DatagramWebChannel implements ByteWebChannel {
  WebDatagrams? get datagrams;

  /// The signals a caller carries for it, or null when it carries its own or has none.
  CarriedSignals? get carriedSignals;
}

/// The signals [channel] leaves to the caller, or null if it leaves none. Asking for its datagrams starts the attempt.
CarriedSignals? signalsOf(WebChannel channel) =>
    channel is DatagramWebChannel ? channel.carriedSignals : null;

/// How a WebSocket channel climbs onto a WebRTC data channel on the same address, when its server agrees.
final class DataChannelSettings {
  const DataChannelSettings({
    this.enabled = true,
    this.attempt = const Duration(seconds: 5),
    this.pathMtu = 1280,
    this.anyCandidate = false,
    this.carriedSignals = false,
  });

  /// Whether to try. Off, a channel asks for nothing more than plain datagrams and sends no signal.
  final bool enabled;

  /// How long a data channel may take to open before the channel stays on the WebSocket for good. Only the attempt is lost.
  final Duration attempt;

  /// The largest IP packet the path is known to carry. It caps a data channel's datagrams, since a fragmented one is lost whenever any
  /// fragment is.
  final int pathMtu;

  /// Lets a candidate name another address than the one dialled, where that was an address at all.
  final bool anyCandidate;

  /// Leaves the offer and answer to the caller, through [signalsOf]. Carried inside a sealed, proven link, the DTLS fingerprints are
  /// bound to that proof, so the data channel's datagrams are too. A signal arriving any other way is ignored.
  final bool carriedSignals;
}

/// The offer and answer of a channel whose [DataChannelSettings.carriedSignals] leaves them to the caller.
abstract interface class CarriedSignals {
  /// What to carry to the peer.
  Stream<Uint8List> get outgoing;

  /// What the peer sent through the caller.
  void deliver(Uint8List signal);
}

/// [channel]'s datagrams, or null if it has none: a WebSocket that was not asked for them, or whose server did not agree, so a caller
/// finds out here rather than quietly getting a stream. A channel wrapping another, such as one sealing its messages, has none unless
/// it says so. [WebDatagrams.delivery] says what they are.
WebDatagrams? datagramsOf(WebChannel channel) =>
    channel is DatagramWebChannel ? channel.datagrams : null;

/// The WebSocket subprotocol that says both ends tag binary messages: 0 and a message, or 1 and a datagram.
const webSocketDatagramsProtocol = 'coqui-web-datagrams.1';

/// [webSocketDatagramsProtocol] and one tag more, 2 and a signal, for what opens a data channel on the same address.
const webSocketLadderProtocol = 'coqui-web-ladder.1';

/// The largest datagram over a WebSocket unless a caller chooses otherwise. There is no packet to fit there.
const defaultWebSocketDatagram = 64 * 1024;

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
