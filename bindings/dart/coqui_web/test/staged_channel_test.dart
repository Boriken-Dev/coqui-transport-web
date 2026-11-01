import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

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

final class ByteSource implements ByteWebChannel {
  final events = StreamController<Uint8List>.broadcast(sync: true);
  final sent = <Uint8List>[];
  @override
  WebChannelKind get kind => WebChannelKind.webSocket;
  @override
  Stream<String> get messages => events.stream.map(decodeText);
  @override
  Stream<Uint8List> get bytes => events.stream;
  @override
  Future<void> send(String frame) async {}
  @override
  Future<void> sendBytes(Uint8List message) async => sent.add(message);
  @override
  Future<void> close() async {
    if (!events.isClosed) await events.close();
  }
}

void main() {
  test(
    'no authentication or application frames are dropped at handoff',
    () async {
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
    },
  );

  test(
    'a binary channel gives a setup message as text and later messages as bytes',
    () async {
      final source = ByteSource();
      final channel = StagedChannel(source);
      source.events.add(utf8.encode('challenge'));
      expect(await channel.nextSetupMessage(), 'challenge');
      channel.allowApplicationMessages();
      final received = channel.bytes.first;
      source.events.add(Uint8List.fromList([0xff, 0xfe]));
      expect(await received, [0xff, 0xfe]);
      await channel.sendBytes(Uint8List.fromList([1, 2]));
      expect(source.sent.single, [1, 2]);
      await channel.close();
    },
  );

  test('a text channel cannot send bytes, and says so', () async {
    final channel = StagedChannel(Source());
    await expectLater(
      channel.sendBytes(Uint8List(1)),
      throwsA(isA<TransportUnavailable>()),
    );
    await channel.close();
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
