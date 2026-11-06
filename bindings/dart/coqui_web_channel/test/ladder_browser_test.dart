@TestOn('browser')
@Timeout(Duration(minutes: 8))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:coqui_web_channel/coqui_web_channel.dart';
import 'package:test/test.dart';

@JS('eval')
external JSAny? _eval(String source);

/// A real browser against the Rust peer, over real sockets: `dart test -p chrome test/ladder_browser_test.dart`.
void main() {
  late Map<String, dynamic> peer;
  const wait = Duration(seconds: 20);

  setUpAll(() async {
    final hybrid = spawnHybridUri(
      'support/ladder_hybrid.dart',
      stayAlive: true,
    );
    peer =
        jsonDecode(await hybrid.stream.first as String) as Map<String, dynamic>;
    print('browser: ${(_eval('navigator.userAgent')! as JSString).toDart}');
    // Keeps each RTCPeerConnection a test's channel makes, so the browser's own statistics can say where it connected.
    _eval('''
      window.__real_pc = window.RTCPeerConnection;
      window.__connections = [];
      window.RTCPeerConnection = function (...args) {
        const made = new window.__real_pc(...args);
        window.__connections.push(made);
        return made;
      };
      window.RTCPeerConnection.prototype = window.__real_pc.prototype;
      window.__real_wt = window.WebTransport;
      window.__selected = () => window.__connections[window.__connections.length - 1].getStats().then((stats) => {
        let pair = null;
        for (const report of stats.values()) {
          if (report.type === 'candidate-pair' && report.nominated && report.state === 'succeeded') pair = report;
        }
        if (pair === null) return '';
        return JSON.stringify(stats.get(pair.remoteCandidateId));
      });
    ''');
  });

  /// As in a browser that has none, or has it turned off.
  void hideWebTransport() => _eval('delete window.WebTransport;');
  void showWebTransport() => _eval('window.WebTransport = window.__real_wt;');

  tearDown(showWebTransport);

  Future<Map<String, dynamic>> selectedCandidate() async {
    final text =
        (await (_eval('window.__selected()')! as JSPromise<JSString>).toDart)
            .toDart;
    return jsonDecode(text) as Map<String, dynamic>;
  }

  Uri socket(String service) =>
      Uri.parse('ws://127.0.0.1:${peer[service]}/channel');

  WebEndpoints endpoints(String service) =>
      WebEndpoints(webSocket: socket(service), allowLocalPlainWebSocket: true);

  Future<WebChannel> climbing(
    String service, {
    DataChannelSettings settings = const DataChannelSettings(),
  }) => connectWebChannel(endpoints(service), dataChannel: settings);

  /// Sends until one comes back, for a path that may lose it.
  Future<void> echoes(WebDatagrams datagrams, List<int> payload) async {
    final bytes = Uint8List.fromList(payload);
    final back = datagrams.incoming.firstWhere(
      (got) => jsonEncode(got) == jsonEncode(bytes),
    );
    var waiting = true;
    unawaited(back.whenComplete(() => waiting = false));
    final deadline = DateTime.now().add(wait);
    while (waiting) {
      if (DateTime.now().isAfter(deadline)) fail('nothing came back');
      await datagrams.send(bytes);
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    await back;
  }

  /// One command to the forwarded service, answered in order over a channel of its own that takes no datagrams.
  Future<String> command(
    WebChannel control,
    String text,
    StreamIterator<String> replies,
  ) async {
    await control.send(text);
    expect(await replies.moveNext().timeout(wait), isTrue);
    return replies.current;
  }

  test(
    'with no WebTransport a page climbs onto a data channel on the number WebTransport uses, mid-use and with an event',
    () async {
      hideWebTransport();
      final channel = await connectWebChannel(
        WebEndpoints(
          webTransport: Uri.parse(
            'https://127.0.0.1:${peer['direct']}/channel',
          ),
          webSocket: socket('direct'),
          allowLocalPlainWebSocket: true,
        ),
        dataChannel: const DataChannelSettings(),
      );
      expect(channel.kind, WebChannelKind.webSocket);
      final messages = StreamIterator(channel.messages);

      final datagrams = datagramsOf(channel)!;
      expect(datagrams.delivery, WebDatagramDelivery.overStream);
      expect(datagrams.maxSize, defaultWebSocketDatagram);
      final change = datagrams.changes.first;

      // In use from the first moment: this may cross either way, whichever is up when it goes.
      await channel.send('first');
      expect(await messages.moveNext().timeout(wait), isTrue);
      expect(messages.current, 'first');
      await echoes(datagrams, [1, 2, 3]);

      expect(await change.timeout(wait), WebDatagramDelivery.unreliable);
      expect(datagrams.delivery, WebDatagramDelivery.unreliable);
      final limit = datagrams.maxSize!;
      expect(limit, lessThan(1232));
      expect(limit, greaterThan(1000));

      final candidate = await selectedCandidate();
      expect(candidate['port'], peer['direct']);
      expect(candidate['protocol'], 'udp');

      await echoes(datagrams, [4, 5, 6]);
      await echoes(datagrams, List.filled(limit, 7));

      await expectLater(
        datagrams.send(Uint8List(limit + 1)),
        throwsA(isA<TransportProtocolFailure>()),
      );
      await channel.send('second');
      expect(await messages.moveNext().timeout(wait), isTrue);
      expect(messages.current, 'second');
      await echoes(datagrams, [8]);
      await channel.close();
    },
  );

  test(
    'an empty datagram from a page reaches the peer on a data channel',
    () async {
      final channel = await climbing('direct');
      final datagrams = datagramsOf(channel)!;
      await datagrams.changes.first.timeout(wait);
      // Rust refuses to send an empty one, so the peer says it got one in a message.
      final said = channel.messages.first;
      await datagrams.send(Uint8List(0));
      expect(await said.timeout(wait), 'an empty datagram');
      await channel.close();
    },
  );

  test(
    'the WebSocket\'s datagram setting does not limit a data channel',
    () async {
      final channel = await connectWebChannel(
        endpoints('direct'),
        maxWebSocketDatagram: 100,
        dataChannel: const DataChannelSettings(),
      );
      final datagrams = datagramsOf(channel)!;
      expect(datagrams.maxSize, 100);
      await datagrams.changes.first.timeout(wait);
      expect(datagrams.maxSize, greaterThan(100));
      await echoes(datagrams, List.filled(500, 3));
      await channel.close();
    },
  );

  test(
    'a page with WebTransport still gets WebTransport, on the same number the data channel and WebSocket use',
    () async {
      final over = await connectWebChannel(
        WebEndpoints(
          webTransport: Uri.parse(
            'https://127.0.0.1:${peer['direct']}/channel',
          ),
          certificatePins: [peer['pin'] as String],
        ),
      );
      expect(over.kind, WebChannelKind.webTransport);
      final quic = datagramsOf(over)!;
      expect(quic.delivery, WebDatagramDelivery.unreliable);

      final climbed = await climbing('direct');
      final datagrams = datagramsOf(climbed)!;
      await datagrams.changes.first.timeout(wait);
      expect((await selectedCandidate())['port'], peer['direct']);

      final plain = await connectWebChannel(endpoints('direct'));
      final plainMessages = plain.messages.first;
      await plain.send('plain');
      expect(await plainMessages.timeout(wait), 'plain');

      final overMessages = over.messages.first;
      await over.send('open');
      expect(await overMessages.timeout(wait), 'open');
      for (var round = 0; round < 20; round += 1) {
        await echoes(quic, [round]);
        await echoes(datagrams, [round]);
      }
      await Future.wait([over.close(), climbed.close(), plain.close()]);
    },
  );

  test(
    'a browser whose RTCPeerConnection throws stays on the WebSocket, with nothing left over',
    () async {
      _eval(
        'window.__saved_pc = window.RTCPeerConnection; '
        'window.RTCPeerConnection = function () { throw new Error("refused"); };',
      );
      try {
        final channel = await climbing(
          'direct',
          settings: const DataChannelSettings(
            attempt: Duration(milliseconds: 500),
          ),
        );
        final datagrams = datagramsOf(channel)!;
        await echoes(datagrams, [1]);
        await Future<void>.delayed(const Duration(seconds: 1));
        expect(datagrams.delivery, WebDatagramDelivery.overStream);
        await echoes(datagrams, [2]);
        await channel.close();
      } finally {
        _eval('window.RTCPeerConnection = window.__saved_pc;');
      }
    },
  );

  test('turned off, a page never tries', () async {
    final before =
        (_eval('window.__connections.length')! as JSNumber).toDartInt;
    final channel = await connectWebChannel(
      endpoints('direct'),
      webSocketDatagrams: true,
      dataChannel: const DataChannelSettings(enabled: false),
    );
    final datagrams = datagramsOf(channel)!;
    await echoes(datagrams, [1]);
    expect(datagrams.delivery, WebDatagramDelivery.overStream);
    expect(
      (_eval('window.__connections.length')! as JSNumber).toDartInt,
      before,
    );
    await channel.close();
  });

  test('a page not asking for a data channel makes none', () async {
    final before =
        (_eval('window.__connections.length')! as JSNumber).toDartInt;
    final channel = await connectWebChannel(
      endpoints('direct'),
      webSocketDatagrams: true,
    );
    await echoes(datagramsOf(channel)!, [1]);
    expect(
      (_eval('window.__connections.length')! as JSNumber).toDartInt,
      before,
    );
    await channel.close();
  });

  group('over a path a test controls', () {
    late WebChannel control;
    late StreamIterator<String> replies;

    setUp(() async {
      control = await connectWebChannel(endpoints('forwarded'));
      replies = StreamIterator(control.messages);
    });

    tearDown(() async {
      await command(control, '!pass', replies);
      await control.close();
    });

    test(
      'UDP blocked: the page stays on the WebSocket and keeps working',
      () async {
        await command(control, '!hole', replies);
        final channel = await climbing(
          'forwarded',
          settings: const DataChannelSettings(
            attempt: Duration(milliseconds: 1500),
          ),
        );
        final datagrams = datagramsOf(channel)!;
        var changed = false;
        datagrams.changes.listen((_) => changed = true);
        final messages = StreamIterator(channel.messages);
        await echoes(datagrams, [1]);
        await Future<void>.delayed(const Duration(milliseconds: 2500));
        expect(changed, isFalse);
        expect(datagrams.delivery, WebDatagramDelivery.overStream);
        // The attempt is over, not merely unfinished: what it held has gone.
        expect(
          (_eval(
                    'window.__connections[window.__connections.length - 1].signalingState',
                  )!
                  as JSString)
              .toDart,
          'closed',
        );
        await echoes(datagrams, [2]);
        await channel.send('still');
        expect(await messages.moveNext().timeout(wait), isTrue);
        expect(messages.current, 'still');
        await channel.close();
      },
    );

    test('a path that dies goes back to the WebSocket with an event', () async {
      final channel = await climbing('forwarded');
      final datagrams = datagramsOf(channel)!;
      final changes = StreamIterator(datagrams.changes);
      expect(await changes.moveNext().timeout(wait), isTrue);
      expect(changes.current, WebDatagramDelivery.unreliable);
      await echoes(datagrams, [1]);

      await command(control, '!hole', replies);
      expect(
        await changes.moveNext().timeout(const Duration(minutes: 1)),
        isTrue,
      );
      expect(changes.current, WebDatagramDelivery.overStream);
      expect(datagrams.delivery, WebDatagramDelivery.overStream);
      expect(datagrams.maxSize, defaultWebSocketDatagram);
      await echoes(datagrams, [2]);
      await channel.close();
    });

    test(
      'the data channel loses under loss and holds nothing up, where the WebSocket delivers all in order',
      () async {
        const sent = 300;
        Future<List<int>> burst(
          WebChannel channel,
          WebDatagrams datagrams,
        ) async {
          final got = <int>[];
          final subscription = datagrams.incoming.listen((datagram) {
            got.add(ByteData.sublistView(datagram).getUint32(0));
          });
          final done = channel.messages.firstWhere(
            (message) => message == 'burst done',
          );
          await channel.send('!burst $sent');
          await done.timeout(wait);
          await Future<void>.delayed(const Duration(seconds: 1));
          await subscription.cancel();
          return got;
        }

        final overStream = await connectWebChannel(
          endpoints('forwarded'),
          webSocketDatagrams: true,
        );
        final climbed = await climbing('forwarded');
        final climbedDatagrams = datagramsOf(climbed)!;
        await climbedDatagrams.changes.first.timeout(wait);
        await echoes(climbedDatagrams, [0, 0, 0, 0]);

        await command(control, '!loss 4', replies);
        final lossy = await burst(climbed, climbedDatagrams);
        final whole = await burst(overStream, datagramsOf(overStream)!);
        await command(control, '!pass', replies);
        print(
          'of $sent: data channel ${lossy.length}, WebSocket ${whole.length}',
        );

        expect(whole, List.generate(sent, (index) => index));
        expect(lossy.length, lessThan(sent));
        expect(lossy.length, greaterThan(0));
        // What was lost held up nothing behind it.
        expect(lossy.reduce((a, b) => a > b ? a : b), greaterThan(sent - 16));
        await Future.wait([overStream.close(), climbed.close()]);
      },
    );

    test(
      'a datagram of the largest size takes one UDP packet each way',
      () async {
        final channel = await climbing('forwarded');
        final datagrams = datagramsOf(channel)!;
        await datagrams.changes.first.timeout(wait);
        await echoes(datagrams, [1]);
        final limit = datagrams.maxSize!;

        Future<Map<String, dynamic>> counts() async =>
            jsonDecode(await command(control, '!counts', replies))
                as Map<String, dynamic>;
        final before = await counts();
        var back = 0;
        final subscription = datagrams.incoming.listen((datagram) {
          if (datagram.length == limit) back += 1;
        });
        const rounds = 20;
        for (var round = 0; round < rounds; round += 1) {
          await datagrams.send(Uint8List(limit));
          await Future<void>.delayed(const Duration(milliseconds: 40));
        }
        await Future<void>.delayed(const Duration(milliseconds: 500));
        await subscription.cancel();
        final after = await counts();
        expect(back, rounds);
        expect((after['largeUp'] as int) - (before['largeUp'] as int), rounds);
        expect(
          (after['largeDown'] as int) - (before['largeDown'] as int),
          rounds,
        );
        await channel.close();
      },
    );
  });

  group('signals the caller carries', () {
    Future<void> carry(
      WebChannel channel,
      String Function(String answer) change,
    ) async {
      final signals = signalsOf(channel)!;
      signals.outgoing.listen((signal) {
        final hex = signal
            .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
            .join();
        unawaited(channel.send('signal:$hex'));
      });
      channel.messages.listen((message) {
        if (!message.startsWith('signal:')) return;
        final hex = message.substring('signal:'.length);
        final bytes = [
          for (var at = 0; at < hex.length; at += 2)
            int.parse(hex.substring(at, at + 2), radix: 16),
        ];
        final answer = change(utf8.decode(bytes.sublist(1)));
        signals.deliver(Uint8List.fromList([bytes[0], ...utf8.encode(answer)]));
      });
    }

    test('carried through the channel\'s messages they open it', () async {
      final channel = await climbing(
        'carried',
        settings: const DataChannelSettings(carriedSignals: true),
      );
      final change = datagramsOf(channel)!.changes.first;
      await carry(channel, (answer) => answer);
      expect(await change.timeout(wait), WebDatagramDelivery.unreliable);
      await echoes(datagramsOf(channel)!, [1]);
      await channel.close();
    });

    test(
      'once the data channel is open, a datagram added inside the WebSocket is not taken',
      () async {
        final injector = spawnHybridUri(
          'support/injector_hybrid.dart',
          stayAlive: true,
        );
        final replies = StreamIterator(injector.stream);
        injector.sink.add(peer['carried']);
        expect(await replies.moveNext().timeout(wait), isTrue);
        final through = replies.current! as int;
        final channel = await connectWebChannel(
          WebEndpoints(
            webSocket: Uri.parse('ws://127.0.0.1:$through/channel'),
            allowLocalPlainWebSocket: true,
          ),
          dataChannel: const DataChannelSettings(carriedSignals: true),
        );
        expect(await replies.moveNext().timeout(wait), isTrue);
        expect(replies.current, 'connected');
        final datagrams = datagramsOf(channel)!;
        final got = <String>[];
        datagrams.incoming.listen(
          (datagram) => got.add(utf8.decode(datagram, allowMalformed: true)),
        );

        // The control: before the data channel opens a datagram in the WebSocket arrives, as documented, so the injector works.
        injector.sink.add('inject:before');
        final deadline = DateTime.now().add(wait);
        while (!got.contains('before')) {
          if (DateTime.now().isAfter(deadline)) {
            fail('the injector reached nothing');
          }
          await Future<void>.delayed(const Duration(milliseconds: 20));
        }

        final change = datagrams.changes.first;
        await carry(channel, (answer) => answer);
        expect(await change.timeout(wait), WebDatagramDelivery.unreliable);
        final dropped = datagrams.dropped;
        injector.sink.add('inject:forged');
        await Future<void>.delayed(const Duration(seconds: 1));
        expect(got, isNot(contains('forged')));
        expect(datagrams.dropped, greaterThan(dropped));
        await echoes(datagrams, [1]);
        await channel.close();
        await injector.sink.close();
      },
    );

    test(
      'a changed fingerprint never opens, and the WebSocket goes on',
      () async {
        final channel = await climbing(
          'carried',
          settings: const DataChannelSettings(
            carriedSignals: true,
            attempt: Duration(seconds: 2),
          ),
        );
        final datagrams = datagramsOf(channel)!;
        var changed = false;
        datagrams.changes.listen((_) => changed = true);
        await carry(channel, (answer) {
          const key = 'a=fingerprint:sha-256 ';
          final at = answer.indexOf(key) + key.length;
          final flipped = answer[at] == 'A' ? 'B' : 'A';
          return '${answer.substring(0, at)}$flipped${answer.substring(at + 1)}';
        });
        await Future<void>.delayed(const Duration(seconds: 4));
        expect(changed, isFalse);
        expect(datagrams.delivery, WebDatagramDelivery.overStream);
        await echoes(datagrams, [1]);
        await channel.close();
      },
    );
  });
}
