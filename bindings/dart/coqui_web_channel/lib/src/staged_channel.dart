import 'dart:convert';
import 'dart:typed_data';

import 'message_handoff.dart';

import 'connect.dart';

/// A [WebChannel] with a setup phase, over the protocol-neutral [MessageHandoff] queue.
/// The queue does not authenticate. A coqui-peer method drives setup and
/// the authenticated caller calls allowApplicationMessages().
final class StagedChannel implements ByteWebChannel {
  StagedChannel(this._source) {
    final source = _source;
    _handoff = MessageHandoff<Uint8List>(
      incoming: source is ByteWebChannel
          ? source.bytes
          : source.messages.map(utf8.encode),
      send: (message) => source is ByteWebChannel
          ? source.sendBytes(message)
          : Future.error(
              const TransportUnavailable('This channel carries only text'),
            ),
      closeSource: source.close,
    );
  }

  final WebChannel _source;
  late final MessageHandoff<Uint8List> _handoff;

  @override
  WebChannelKind get kind => _source.kind;
  @override
  Stream<String> get messages => _handoff.applicationMessages.map(decodeText);
  @override
  Stream<Uint8List> get bytes => _handoff.applicationMessages;

  /// The next setup message as text. A peer may send it in a text or a binary frame.
  Future<String> nextSetupMessage() =>
      _handoff.nextSetupMessage().then(decodeText);

  /// The next setup message as its bytes, for a method whose handshake is binary: a text frame gives its UTF-8.
  /// Reads the same queue as [nextSetupMessage], one message per call.
  Future<Uint8List> nextSetupBytes() => _handoff.nextSetupMessage();

  void allowApplicationMessages() => _handoff.handoff();

  @override
  Future<void> send(String message) {
    _handoff.checkOpen();
    return _source.send(message);
  }

  @override
  Future<void> sendBytes(Uint8List message) => _handoff.send(message);
  @override
  Future<void> close() => _handoff.close();
}
