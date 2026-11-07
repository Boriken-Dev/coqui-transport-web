import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'contracts.dart';
import 'datachannel_path.dart';

@JS('globalThis.RTCPeerConnection')
external JSAny? get _peerConnectionConstructor;

@JS('RTCPeerConnection')
extension type _PeerConnection._(JSObject _) implements JSObject {
  external factory _PeerConnection(_Configuration configuration);
  external _Channel createDataChannel(String label, _ChannelInit init);
  external JSPromise<_Description> createOffer();
  external JSPromise<JSAny?> setLocalDescription(_Description description);
  external JSPromise<JSAny?> setRemoteDescription(_Description description);
  external _Description? get localDescription;
  external String get connectionState;
  external _Sctp? get sctp;
  external set onconnectionstatechange(JSFunction? handler);
  external void close();
}

extension type _Sctp._(JSObject _) implements JSObject {
  external num get maxMessageSize;
}

extension type _Configuration._(JSObject _) implements JSObject {
  external factory _Configuration({JSArray<JSObject> iceServers});
}

extension type _ChannelInit._(JSObject _) implements JSObject {
  external factory _ChannelInit({bool ordered, int maxRetransmits});
}

extension type _Description._(JSObject _) implements JSObject {
  external factory _Description({String type, String sdp});
  external String get sdp;
}

extension type _Channel._(JSObject _) implements JSObject {
  external set binaryType(String value);
  external String get readyState;
  external num get bufferedAmount;
  external set onopen(JSFunction? handler);
  external set onclose(JSFunction? handler);
  external set onmessage(JSFunction? handler);
  external void send(JSUint8Array data);
  external void close();
}

extension type _MessageEvent._(JSObject _) implements JSObject {
  external JSAny? get data;
}

const _offer = 1;
const _answer = 2;
const _refused = 3;

/// A session description is a few kilobytes. A peer gets no further than this.
const _maxSignal = 16 * 1024;

/// SCTP, DTLS and padding on a data channel's message, and UDP and IPv6 under them.
const _overhead = 116;

/// What fits one SCTP chunk whichever implementation is at the other end.
const _largest = 1100;

/// Past this much waiting to be sent a datagram is discarded and counted. A browser closes a channel asked to hold too much.
const _maxBuffered = 256 * 1024;

const _label = 'coqui-web-datagrams';

/// [endpoint]'s host as an address, or null for a name, which a page has no way to resolve to compare.
Object? _addressOf(String host) {
  if (host.contains(':')) {
    try {
      return Uri.parseIPv6Address(host).join('.');
    } on FormatException {
      return null;
    }
  }
  return RegExp(r'^\d+\.\d+\.\d+\.\d+$').hasMatch(host) ? host : null;
}

/// [sdp] with nothing about candidates, which an ICE-lite peer has no use for and a page should not tell it.
String _withoutCandidates(String sdp) {
  final out = StringBuffer();
  for (final line in const LineSplitter().convert(sdp)) {
    if (!line.startsWith('a=candidate:') && line != 'a=end-of-candidates') {
      out.write('$line\r\n');
    }
  }
  return out.toString();
}

/// An answer, if it has exactly one candidate, of the host kind over UDP, and at the address [endpoint] dialled unless that is a name
/// or [any] allows another. A peer gets to name one place for this page's checks to go, and only where it already is.
String? _checkedAnswer(String sdp, Uri endpoint, bool any) {
  final candidates = [
    for (final line in const LineSplitter().convert(sdp))
      if (line.startsWith('a=candidate:')) line,
  ];
  if (candidates.length != 1) return null;
  final fields = candidates.single.substring('a=candidate:'.length).split(' ');
  if (fields.length < 8 ||
      fields[2].toLowerCase() != 'udp' ||
      fields[6] != 'typ' ||
      fields[7] != 'host') {
    return null;
  }
  final named = _addressOf(fields[4]);
  if (named == null) return null;
  final dialled = _addressOf(endpoint.host);
  if (!any && dialled != null && dialled != named) return null;
  return sdp;
}

final class _Attempt implements DataChannelPath {
  _Attempt(this._endpoint, this._settings, this._events);

  final Uri _endpoint;
  final DataChannelSettings _settings;
  final DataChannelEvents _events;
  // Null until made, and for good if the browser refuses to make them.
  _PeerConnection? _connection;
  _Channel? _channel;
  Timer? _attempt;
  bool _open = false;
  bool _answered = false;
  bool _closed = false;

  @override
  bool get isOpen => _open;

  @override
  int get maxSize {
    final path = _settings.pathMtu - _overhead;
    final limit = path < _largest ? path : _largest;
    final peer = _connection?.sctp?.maxMessageSize;
    return peer != null && peer > 0 && peer < limit ? peer.toInt() : limit;
  }

  Future<void> start() async {
    final _PeerConnection connection;
    final _Channel channel;
    try {
      connection = _connection = _PeerConnection(
        _Configuration(iceServers: <JSObject>[].toJS),
      );
      channel = _channel = connection.createDataChannel(
        _label,
        _ChannelInit(ordered: false, maxRetransmits: 0),
      );
    } catch (_) {
      _end();
      return;
    }
    channel.binaryType = 'arraybuffer';
    _attempt = Timer(_settings.attempt, _end);
    channel.onopen = (() {
      if (_closed) return;
      _attempt?.cancel();
      _open = true;
      _events.opened();
    }).toJS;
    channel.onclose = (() => _end()).toJS;
    channel.onmessage = ((JSObject event) {
      final data = _MessageEvent._(event).data;
      if (data.isA<JSArrayBuffer>()) {
        final bytes = (data as JSArrayBuffer).toDart.asUint8List();
        if (bytes.length > _largest) {
          _events.discarded();
        } else {
          _events.arrived(bytes);
        }
      }
    }).toJS;
    connection.onconnectionstatechange = (() {
      final state = connection.connectionState;
      if (state == 'failed' || state == 'disconnected' || state == 'closed') {
        _end();
      }
    }).toJS;
    try {
      final offer = await connection.createOffer().toDart;
      await connection.setLocalDescription(offer).toDart;
      if (_closed) return;
      // Sent at once, with no wait for gathering: an ICE-lite peer learns where this page is from its first check.
      final sdp = _withoutCandidates(connection.localDescription!.sdp);
      _events.signal(Uint8List.fromList([_offer, ...utf8.encode(sdp)]));
    } catch (_) {
      _end();
    }
  }

  @override
  void deliver(Uint8List signal) {
    final connection = _connection;
    if (connection == null ||
        _closed ||
        _answered ||
        signal.isEmpty ||
        signal.length > _maxSignal) {
      return;
    }
    if (signal[0] == _refused) {
      _end();
      return;
    }
    if (signal[0] != _answer) return;
    _answered = true;
    final String sdp;
    try {
      sdp = utf8.decode(Uint8List.sublistView(signal, 1));
    } on FormatException {
      _end();
      return;
    }
    final checked = _checkedAnswer(sdp, _endpoint, _settings.anyCandidate);
    if (checked == null) {
      _end();
      return;
    }
    unawaited(
      connection
          .setRemoteDescription(_Description(type: 'answer', sdp: checked))
          .toDart
          .then<void>((_) {}, onError: (Object _) => _end()),
    );
  }

  /// Hands one to the data channel. One that finds too much waiting is discarded and counted.
  @override
  void send(Uint8List datagram) {
    final channel = _channel;
    if (channel == null ||
        channel.readyState != 'open' ||
        channel.bufferedAmount > _maxBuffered) {
      _events.discarded();
      return;
    }
    try {
      channel.send(datagram.toJS);
    } catch (_) {
      _events.discarded();
    }
  }

  void _end() {
    if (_closed) return;
    final wasOpen = _open;
    close();
    if (wasOpen) _events.ended();
  }

  @override
  void close() {
    if (_closed) return;
    _closed = true;
    _open = false;
    _attempt?.cancel();
    final channel = _channel;
    final connection = _connection;
    try {
      if (channel != null) {
        channel.onopen = null;
        channel.onclose = null;
        channel.onmessage = null;
        channel.close();
      }
      if (connection != null) {
        connection.onconnectionstatechange = null;
        connection.close();
      }
    } catch (_) {}
  }
}

/// Starts one attempt, or answers null where this browser has no data channels. Off the attempt limit or on a refusal it ends and the
/// channel stays where it is.
DataChannelPath? startDataChannel(
  Uri endpoint,
  DataChannelSettings settings,
  DataChannelEvents events,
) {
  if (_peerConnectionConstructor == null) return null;
  final attempt = _Attempt(endpoint, settings, events);
  unawaited(attempt.start());
  return attempt;
}
