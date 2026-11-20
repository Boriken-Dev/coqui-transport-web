@TestOn('vm')
library;

import 'dart:async';
import 'dart:io';

import 'package:coqui_transport_web/coqui_transport_web.dart';
import 'package:test/test.dart';
import 'package:web_socket_channel/io.dart';

/// A local peer that sends one message to whoever connects.
Future<HttpServer> _peer() async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((request) async {
    final socket = await WebSocketTransformer.upgrade(request);
    socket.add('hello');
    socket.listen((_) {});
  });
  return server;
}

void main() {
  test(
    'a connector opens the socket, and the channel is the one the default would make',
    () async {
      final server = await _peer();
      addTearDown(() => server.close(force: true));
      // The name the caller dials is not one that resolves: only its own route reaches the server.
      final opened = <(Uri, Iterable<String>?)>[];
      final client = HttpClient()
        ..findProxy = ((_) => 'DIRECT')
        ..connectionFactory = (uri, proxyHost, proxyPort) =>
            Socket.startConnect(InternetAddress.loopbackIPv4, server.port);
      addTearDown(() => client.close(force: true));

      final channel = await openWebSocketChannel(
        Uri.parse('ws://peer.invalid:9/channel'),
        const Duration(seconds: 5),
        const [],
        connector: (uri, protocols) {
          opened.add((uri, protocols));
          return IOWebSocketChannel.connect(
            uri,
            protocols: protocols,
            customClient: client,
          );
        },
      );
      expect(opened.single.$1, Uri.parse('ws://peer.invalid:9/channel'));
      expect(opened.single.$2, isNull);
      expect(
        await channel.messages.first.timeout(const Duration(seconds: 5)),
        'hello',
      );
      await channel.close();
    },
  );

  test(
    'a connector that cannot reach the server is a transport that is unavailable',
    () async {
      final client = HttpClient()
        ..findProxy = ((_) => 'DIRECT')
        ..connectionFactory = (uri, proxyHost, proxyPort) =>
            Future<ConnectionTask<Socket>>.error(
              const SocketException('the proxy refused the login'),
            );
      addTearDown(() => client.close(force: true));
      await expectLater(
        openWebSocketChannel(
          Uri.parse('ws://peer.invalid:9/channel'),
          const Duration(seconds: 5),
          const [],
          connector: (uri, protocols) => IOWebSocketChannel.connect(
            uri,
            protocols: protocols,
            customClient: client,
          ),
        ),
        throwsA(
          isA<TransportUnavailable>().having(
            (e) => e.toString(),
            'message',
            contains('the proxy refused the login'),
          ),
        ),
      );
    },
  );

  test(
    'through connectWebChannel a connector rides in the WebSocket dialer',
    () async {
      final server = await _peer();
      addTearDown(() => server.close(force: true));
      var used = false;
      final channel = await connectWebChannel(
        WebEndpoints(
          webSocket: Uri.parse('ws://127.0.0.1:${server.port}/'),
          allowPlainWebSocket: true,
        ),
        webSocketDialer: (uri, timeout, pins) => openWebSocketChannel(
          uri,
          timeout,
          pins,
          connector: (uri, protocols) {
            used = true;
            return IOWebSocketChannel.connect(uri, protocols: protocols);
          },
        ),
      );
      expect(used, isTrue);
      await channel.close();
    },
  );
}
