@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';

import 'package:coqui_web/coqui_web.dart';
import 'package:test/test.dart';

/// A local peer. The socket counts as released when the server sees it end, which is the
/// only evidence of a real close: the client's own state says nothing about the socket.
final class _Peer {
  _Peer._(this._server);

  final HttpServer _server;
  final Completer<void> released = Completer<void>();

  static Future<_Peer> start(void Function(WebSocket socket) onConnect) async {
    final peer = _Peer._(
      await HttpServer.bind(InternetAddress.loopbackIPv4, 0),
    );
    peer._server.listen((request) async {
      final socket = await WebSocketTransformer.upgrade(request);
      socket.listen((_) {}, onDone: peer.released.complete);
      onConnect(socket);
    });
    return peer;
  }

  Future<WebChannel> dial() => openWebSocketChannel(
    Uri.parse('ws://127.0.0.1:${_server.port}/'),
    const Duration(seconds: 5),
    const [],
  );

  Future<void> expectReleased() async {
    await released.future.timeout(const Duration(seconds: 5));
    await _server.close(force: true);
  }
}

void main() {
  test('close on a healthy connection releases the socket', () async {
    final peer = await _Peer.start((_) {});
    final connection = await peer.dial();
    connection.messages.listen((_) {});
    await connection.close();
    await peer.expectReleased();
  });

  test(
    'a frame over the limit fails the stream and releases the socket unprompted',
    () async {
      final peer = await _Peer.start(
        (socket) => socket.add('x' * (defaultMaxMessage + 1)),
      );
      final connection = await peer.dial();
      final errors = <Object>[];
      final done = Completer<void>();
      connection.messages.listen(
        (_) {},
        onError: errors.add,
        onDone: done.complete,
      );
      await done.future.timeout(const Duration(seconds: 5));
      expect(errors.single, isA<TransportProtocolFailure>());
      await peer.expectReleased();
    },
  );

  test('close after a failed stream completes and is safe to repeat', () async {
    final peer = await _Peer.start(
      (socket) => socket.add('x' * (defaultMaxMessage + 1)),
    );
    final connection = await peer.dial();
    final done = Completer<void>();
    connection.messages.listen(
      (_) {},
      onError: (Object _) {},
      onDone: done.complete,
    );
    await done.future.timeout(const Duration(seconds: 5));
    await connection.close();
    await connection.close();
    await peer.expectReleased();
  });

  test('a peer that closes ends the stream, and sending then fails', () async {
    final peer = await _Peer.start((socket) => socket.close());
    final connection = await peer.dial();
    final done = Completer<void>();
    connection.messages.listen((_) {}, onDone: done.complete);
    await done.future.timeout(const Duration(seconds: 5));
    await expectLater(
      connection.send('late'),
      throwsA(isA<TransportUnavailable>()),
    );
    await connection.close();
    await peer.expectReleased();
  });
}
