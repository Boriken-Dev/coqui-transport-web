@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:coqui_transport_web/coqui_transport_web.dart';
import 'package:test/test.dart';

/// A local WebSocket server that answers each message with its length, and sends [push] once a client is connected.
Future<HttpServer> _server({int? push}) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((request) async {
    final socket = await WebSocketTransformer.upgrade(request);
    if (push != null) socket.add(Uint8List(push)..fillRange(0, push, 120));
    socket.listen((message) {
      final size = message is String
          ? message.length
          : (message as List<int>).length;
      socket.add('got $size');
    });
  });
  return server;
}

Future<LimitedWebChannel> _dial(HttpServer server) async {
  final channel = await openWebSocketChannel(
    Uri.parse('ws://127.0.0.1:${server.port}/'),
    const Duration(seconds: 5),
    const [],
  );
  return channel as LimitedWebChannel;
}

void main() {
  const big = defaultMaxMessage * 4;

  test(
    'a WebSocket channel starts at the default limit and refuses a longer message to send',
    () async {
      final server = await _server();
      final channel = await _dial(server);
      expect(channel.maxMessage, defaultMaxMessage);
      await expectLater(
        channel.sendBytes(Uint8List(defaultMaxMessage + 1)),
        throwsA(isA<TransportProtocolFailure>()),
      );
      await channel.close();
      await server.close(force: true);
    },
  );

  test(
    'a raised limit lets a WebSocket channel send and take messages over the default',
    () async {
      final server = await _server(push: big);
      final channel = await _dial(server);
      channel.maxMessage = big;
      final answers = StreamIterator(channel.bytes);
      expect(await answers.moveNext(), isTrue);
      expect(answers.current.length, big);
      await channel.sendBytes(Uint8List(big)..fillRange(0, big, 1));
      expect(await answers.moveNext(), isTrue);
      expect(String.fromCharCodes(answers.current), 'got $big');
      await answers.cancel();
      await channel.close();
      await server.close(force: true);
    },
  );

  test(
    'a WebSocket channel at the default ends on a message over it, which a raised one takes',
    () async {
      final server = await _server(push: defaultMaxMessage + 1);
      final channel = await _dial(server);
      final errors = <Object>[];
      final done = Completer<void>();
      channel.bytes.listen((_) {}, onError: errors.add, onDone: done.complete);
      await done.future.timeout(const Duration(seconds: 5));
      expect(errors.single, isA<TransportProtocolFailure>());
      await server.close(force: true);
    },
  );

  test('a limit under one is refused', () async {
    final server = await _server();
    final channel = await _dial(server);
    expect(() => channel.maxMessage = 0, throwsArgumentError);
    expect(channel.maxMessage, defaultMaxMessage);
    await channel.close();
    await server.close(force: true);
  });

  test('a staged channel passes the limit to its source', () async {
    final server = await _server();
    final staged = StagedChannel(await _dial(server));
    expect(staged.maxMessage, defaultMaxMessage);
    staged.maxMessage = big;
    expect(staged.maxMessage, big);
    await staged.close();
    await server.close(force: true);
  });

  test(
    'a staged channel over a source with a fixed limit refuses to change it',
    () async {
      final staged = StagedChannel(_Fixed());
      expect(staged.maxMessage, defaultMaxMessage);
      expect(() => staged.maxMessage = big, throwsUnsupportedError);
    },
  );

  test(
    'a stream frame decoder takes the limit it is given from the next frame',
    () {
      final decoder = FrameDecoder();
      final frame = encodeBytesFrame(Uint8List(8), maxBytes: 8);
      decoder.maxBytes = 4;
      decoder.push(frame);
      expect(decoder.nextBytes, throwsA(isA<TransportProtocolFailure>()));

      final raised = FrameDecoder(maxBytes: 4)..maxBytes = 8;
      raised.push(frame);
      expect(raised.nextBytes()?.length, 8);
      expect(
        () => encodeBytesFrame(Uint8List(defaultMaxMessage + 1)),
        throwsA(isA<TransportProtocolFailure>()),
      );
      expect(
        encodeBytesFrame(
          Uint8List(defaultMaxMessage + 1),
          maxBytes: big,
        ).length,
        defaultMaxMessage + 5,
      );
    },
  );
}

final class _Fixed implements WebChannel {
  @override
  WebChannelKind get kind => WebChannelKind.webSocket;
  @override
  Stream<String> get messages => const Stream.empty();
  @override
  Future<void> send(String message) async {}
  @override
  Future<void> close() async {}
}
