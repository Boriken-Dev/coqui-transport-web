import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:stream_channel/stream_channel.dart';

/// A WebSocket proxy in front of the Rust peer that can add a binary message of its own to what the peer sends: someone inside the
/// TLS stream. The test sends the peer's port first and is answered with the proxy's; then `inject:<text>` adds a datagram, tagged as
/// the peer would tag it. `connected` says a page is through to the peer.
Future<void> hybridMain(StreamChannel<Object?> channel) async {
  final commands = StreamIterator(channel.stream);
  await commands.moveNext();
  final target = commands.current! as int;
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  final pages = <WebSocket>[];
  server.listen((request) async {
    final page = await WebSocketTransformer.upgrade(
      request,
      protocolSelector: (offered) => offered.first,
    );
    final peer = await WebSocket.connect(
      'ws://127.0.0.1:$target/channel',
      protocols: [page.protocol!],
    );
    pages.add(page);
    channel.sink.add('connected');
    page.listen(peer.add, onDone: () => unawaited(peer.close()));
    peer.listen(page.add, onDone: () => unawaited(page.close()));
  });
  channel.sink.add(server.port);
  while (await commands.moveNext()) {
    final command = commands.current! as String;
    if (command.startsWith('inject:')) {
      for (final page in pages) {
        page.add([1, ...utf8.encode(command.substring('inject:'.length))]);
      }
    }
  }
  await server.close(force: true);
}
