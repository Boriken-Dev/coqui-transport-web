@TestOn('browser')
@Timeout(Duration(minutes: 8))
library;

import 'dart:convert';

import 'package:coqui_web/coqui_web.dart';
import 'package:test/test.dart';

/// A real browser against the Rust drivers, over real sockets: `dart test -p chrome`.
void main() {
  late Map<String, dynamic> peer;

  setUpAll(() async {
    final hybrid = spawnHybridUri('support/echo_hybrid.dart', stayAlive: true);
    peer = jsonDecode(await hybrid.stream.first as String) as Map<String, dynamic>;
  });

  Future<void> roundTrip(WebChannel channel) async {
    final received = channel.messages.take(2).toList();
    await channel.send('{"jsonrpc":"2.0","id":1}');
    await channel.send('café');
    expect(await received.timeout(const Duration(seconds: 20)), ['{"jsonrpc":"2.0","id":1}', 'café']);
    await channel.close();
  }

  test('a browser WebTransport channel with a pinned certificate reaches the Rust listener', () async {
    final channel = await connectWebChannel(
      WebEndpoints(
        webTransport: Uri.parse('https://127.0.0.1:${peer['webtransport']}/channel'),
        certificatePins: [peer['pin'] as String],
      ),
    );
    expect(channel.kind, WebChannelKind.webTransport);
    await roundTrip(channel);
  });

  test('a browser WebSocket channel reaches the Rust listener', () async {
    final channel = await connectWebChannel(
      WebEndpoints(
        webSocket: Uri.parse('ws://127.0.0.1:${peer['websocket']}/channel'),
        allowLocalPlainWebSocket: true,
      ),
    );
    expect(channel.kind, WebChannelKind.webSocket);
    await roundTrip(channel);
  });

  test('a wrong pin never downgrades to the WebSocket endpoint', () async {
    await expectLater(
      connectWebChannel(
        WebEndpoints(
          webTransport: Uri.parse('https://127.0.0.1:${peer['webtransport']}/channel'),
          webSocket: Uri.parse('ws://127.0.0.1:${peer['websocket']}/channel'),
          allowLocalPlainWebSocket: true,
          certificatePins: ['sha256:${'ab' * 32}'],
        ),
        timeout: const Duration(seconds: 5),
      ),
      throwsA(isA<TransportSecurityFailure>()),
    );
  });
}
