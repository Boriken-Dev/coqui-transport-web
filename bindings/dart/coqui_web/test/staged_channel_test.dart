import 'dart:async';
import 'package:coqui_web/coqui_web.dart';
import 'package:test/test.dart';

final class Source implements WebChannel {
  final events = StreamController<String>.broadcast(sync: true);
  bool closed = false;
  @override
  WebChannelKind get kind => WebChannelKind.webSocket;
  @override
  Stream<String> get messages => events.stream;
  @override
  Future<void> send(String frame) async => events.add(frame);
  @override
  Future<void> close() async {
    closed = true;
    if (!events.isClosed) await events.close();
  }
}

void main() {
  test('no authentication or application frames are dropped at handoff', () async {
    final source = Source();
    final channel = StagedChannel(source);
    source.events.add('hello');
    source.events.add('challenge');
    expect(await channel.nextSetupMessage(), 'hello');
    expect(await channel.nextSetupMessage(), 'challenge');
    source.events.add('first application frame');
    channel.allowApplicationMessages();
    final received = <String>[];
    final sub = channel.messages.listen(received.add);
    await Future<void>.delayed(Duration.zero);
    source.events.add('second application frame');
    await Future<void>.delayed(Duration.zero);
    expect(received, ['first application frame', 'second application frame']);
    await sub.cancel();
    await channel.close();
    expect(source.closed, isTrue);
  });

  test('no duplicate handshake read or double promotion', () async {
    final source = Source();
    final channel = StagedChannel(source);
    final waiting = channel.nextSetupMessage();
    expect(() => channel.nextSetupMessage(), throwsStateError);
    expect(() => channel.allowApplicationMessages(), throwsStateError);
    source.events.add('hello');
    expect(await waiting, 'hello');
    channel.allowApplicationMessages();
    expect(() => channel.allowApplicationMessages(), throwsStateError);
    expect(() => channel.nextSetupMessage(), throwsStateError);
    await channel.close();
  });

  test('disconnect prevents authentication success', () async {
    final source = Source();
    final channel = StagedChannel(source);
    final waiting = channel.nextSetupMessage();
    final assertion = expectLater(waiting, throwsStateError);
    await source.events.close();
    await assertion;
    expect(() => channel.allowApplicationMessages(), throwsStateError);
    await channel.close();
  });
}
