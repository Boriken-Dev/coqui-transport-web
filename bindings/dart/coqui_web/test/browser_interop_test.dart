@TestOn('browser')
@Timeout(Duration(minutes: 8))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:coqui_web/coqui_web.dart';
import 'package:test/test.dart';

/// A real browser against the Rust drivers, over real sockets: `dart test -p chrome`.
void main() {
  late Map<String, dynamic> peer;

  setUpAll(() async {
    final hybrid = spawnHybridUri('support/echo_hybrid.dart', stayAlive: true);
    peer =
        jsonDecode(await hybrid.stream.first as String) as Map<String, dynamic>;
  });

  Future<void> roundTrip(WebChannel channel) async {
    final received = channel.messages.take(2).toList();
    await channel.send('{"jsonrpc":"2.0","id":1}');
    await channel.send('café');
    expect(await received.timeout(const Duration(seconds: 20)), [
      '{"jsonrpc":"2.0","id":1}',
      'café',
    ]);
    await channel.close();
  }

  test(
    'a browser WebTransport channel carries bytes that are not text',
    () async {
      final channel =
          await connectWebChannel(
                WebEndpoints(
                  webTransport: Uri.parse(
                    'https://127.0.0.1:${peer['webtransport']}/channel',
                  ),
                  certificatePins: [peer['pin'] as String],
                ),
              )
              as ByteWebChannel;
      final received = channel.bytes.first;
      await channel.sendBytes(Uint8List.fromList([0xff, 0x00, 0xfe]));
      expect(await received.timeout(const Duration(seconds: 20)), [
        0xff,
        0x00,
        0xfe,
      ]);
      await channel.close();
    },
  );

  test(
    'a browser WebTransport channel with a pinned certificate reaches the Rust listener',
    () async {
      final channel = await connectWebChannel(
        WebEndpoints(
          webTransport: Uri.parse(
            'https://127.0.0.1:${peer['webtransport']}/channel',
          ),
          certificatePins: [peer['pin'] as String],
        ),
      );
      expect(channel.kind, WebChannelKind.webTransport);
      await roundTrip(channel);
    },
  );

  test(
    'a browser WebTransport channel sends datagrams to the Rust listener and gets them back',
    () async {
      final channel = await connectWebChannel(
        WebEndpoints(
          webTransport: Uri.parse(
            'https://127.0.0.1:${peer['webtransport']}/channel',
          ),
          certificatePins: [peer['pin'] as String],
        ),
      );
      final datagrams = datagramsOf(channel)!;
      expect(datagrams.maxSize, greaterThan(1000));
      final payload = Uint8List.fromList([0xff, 0x00, 0xfe]);
      final received = datagrams.incoming.first;
      // The Rust side starts reading when the stream opens, so the first can go nowhere: sent until one comes back, as anything
      // using datagrams has to.
      await channel.send('open');
      var sent = true;
      unawaited(
        received
            .whenComplete(() => sent = false)
            .catchError((Object _) => payload),
      );
      while (sent) {
        await datagrams.send(payload);
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
      expect(await received.timeout(const Duration(seconds: 20)), payload);
      await expectLater(
        datagrams.send(Uint8List(datagrams.maxSize! + 1)),
        throwsA(isA<TransportProtocolFailure>()),
      );
      final messages = channel.messages.take(2).toList();
      await channel.send('still here');
      expect(await messages.timeout(const Duration(seconds: 20)), [
        'open',
        'still here',
      ]);
      await channel.close();
    },
  );

  test(
    'a browser WebSocket channel not asked for datagrams has none',
    () async {
      final channel = await connectWebChannel(
        WebEndpoints(
          webSocket: Uri.parse('ws://127.0.0.1:${peer['websocket']}/channel'),
          allowLocalPlainWebSocket: true,
        ),
      );
      expect(datagramsOf(channel), isNull);
      await channel.close();
    },
  );

  test(
    'a browser WebSocket channel asked for datagrams sends them to the Rust listener beside its messages',
    () async {
      final channel = await connectWebChannel(
        WebEndpoints(
          webSocket: Uri.parse('ws://127.0.0.1:${peer['websocket']}/channel'),
          allowLocalPlainWebSocket: true,
        ),
        webSocketDatagrams: true,
        maxWebSocketDatagram: 100,
      );
      final datagrams = datagramsOf(channel)!;
      expect(datagrams.delivery, WebDatagramDelivery.overStream);
      expect(datagrams.maxSize, 100);
      final back = datagrams.incoming.take(2).toList();
      final messages = channel.messages.take(2).toList();
      await channel.send('first');
      await datagrams.send(Uint8List.fromList([0xff, 0x00, 0xfe]));
      await datagrams.send(Uint8List(0));
      await channel.send('second');
      expect(await back.timeout(const Duration(seconds: 20)), [
        [0xff, 0x00, 0xfe],
        <int>[],
      ]);
      expect(await messages.timeout(const Duration(seconds: 20)), [
        'first',
        'second',
      ]);
      await expectLater(
        datagrams.send(Uint8List(101)),
        throwsA(isA<TransportProtocolFailure>()),
      );
      await channel.close();
    },
  );

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
          webTransport: Uri.parse(
            'https://127.0.0.1:${peer['webtransport']}/channel',
          ),
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
