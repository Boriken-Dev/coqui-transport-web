import 'message_handoff.dart';

import 'connect.dart';

/// A [WebChannel] with a setup phase, over the protocol-neutral [MessageHandoff] queue.
/// The queue does not authenticate. A coqui-peer method drives setup and
/// the authenticated caller calls allowApplicationMessages().
final class StagedChannel implements WebChannel {
  StagedChannel(this._source) {
    _handoff = MessageHandoff(
      incoming: _source.messages,
      send: _source.send,
      closeSource: _source.close,
    );
  }

  final WebChannel _source;
  late final MessageHandoff _handoff;

  @override
  WebChannelKind get kind => _source.kind;
  @override
  Stream<String> get messages => _handoff.applicationMessages;

  Future<String> nextSetupMessage() => _handoff.nextSetupMessage();

  void allowApplicationMessages() => _handoff.handoff();

  @override
  Future<void> send(String message) => _handoff.send(message);
  @override
  Future<void> close() => _handoff.close();
}
