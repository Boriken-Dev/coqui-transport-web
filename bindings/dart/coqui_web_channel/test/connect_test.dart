import 'dart:async';

import 'package:coqui_web_channel/coqui_web_channel.dart';
import 'package:test/test.dart';

class FakeLink implements WebChannel {
  FakeLink(this.kind);
  @override
  final WebChannelKind kind;
  @override
  Stream<String> get messages => const Stream<String>.empty();
  @override
  Future<void> send(String message) async {}
  @override
  Future<void> close() async {}
}

void main() {
  test(
    'an opening that breaks the wire format tries the other transport',
    () async {
      var tried = false;
      final channel = await connectWebChannel(
        WebEndpoints.address(Uri.parse('https://peer.example/channel')),
        webTransportDialer: (url, timeout, pins) async =>
            throw const TransportProtocolFailure('not what was expected'),
        webSocketDialer: (url, timeout, pins) async {
          tried = true;
          return FakeLink(WebChannelKind.webSocket);
        },
      );
      expect(tried, isTrue);
      await channel.close();
    },
  );

  test('one address gives both transports on the same host, port and path', () {
    for (final given in [
      'https://peer.example/channel',
      'https://peer.example:4433/channel',
    ]) {
      final endpoints = WebEndpoints.address(Uri.parse(given));
      expect(endpoints.webTransport!.scheme, 'https');
      expect(endpoints.webSocket!.scheme, 'wss');
      expect(endpoints.webSocket!.authority, endpoints.webTransport!.authority);
      expect(endpoints.webSocket!.path, endpoints.webTransport!.path);
    }
    expect(
      () => WebEndpoints.address(Uri.parse('wss://peer.example/channel')),
      throwsArgumentError,
    );
    expect(
      () =>
          WebEndpoints(webTransport: Uri.parse('https://peer.example/channel')),
      throwsArgumentError,
    );
  });

  final wt = Uri.parse('https://peer.example:4433/channel');
  final ws = Uri.parse('wss://peer.example:4434/channel');

  test('WebTransport wins when available', () async {
    final called = <String>[];
    final link = await connectWebChannel(
      WebEndpoints(webTransport: wt, webSocket: ws),
      webTransportDialer: (url, timeout, pins) async {
        called.add('wt');
        return FakeLink(WebChannelKind.webTransport);
      },
      webSocketDialer: (url, timeout, pins) async {
        called.add('ws');
        return FakeLink(WebChannelKind.webSocket);
      },
    );
    expect(link.kind, WebChannelKind.webTransport);
    expect(called, ['wt']);
  });

  test('unavailable WebTransport falls back to configured WSS', () async {
    final called = <String>[];
    final link = await connectWebChannel(
      WebEndpoints(webTransport: wt, webSocket: ws),
      webTransportDialer: (url, timeout, pins) async {
        called.add('wt');
        throw const TransportUnavailable('HTTP/3 blocked');
      },
      webSocketDialer: (url, timeout, pins) async {
        called.add('ws');
        expect(url, ws);
        return FakeLink(WebChannelKind.webSocket);
      },
    );
    expect(link.kind, WebChannelKind.webSocket);
    expect(called, ['wt', 'ws']);
  });

  test('pinned TLS failure never silently downgrades', () async {
    var touchedWs = false;
    final endpoints = WebEndpoints(
      webTransport: wt,
      webSocket: ws,
      certificatePins: ['sha256:${'ab' * 32}'],
    );
    await expectLater(
      connectWebChannel(
        endpoints,
        webTransportDialer: (url, timeout, pins) async =>
            throw const TransportSecurityFailure('pin mismatch'),
        webSocketDialer: (url, timeout, pins) async {
          touchedWs = true;
          return FakeLink(WebChannelKind.webSocket);
        },
      ),
      throwsA(isA<TransportSecurityFailure>()),
    );
    expect(touchedWs, isFalse);
  });

  test(
    'no fallback after an unknown failure or a rejected certificate',
    () async {
      var fallback = false;
      await expectLater(
        connectWebChannel(
          WebEndpoints(webTransport: wt, webSocket: ws),
          webTransportDialer: (url, timeout, pins) async =>
              throw const TransportSecurityFailure('a pin did not match'),
          webSocketDialer: (url, timeout, pins) async {
            fallback = true;
            return FakeLink(WebChannelKind.webSocket);
          },
        ),
        throwsA(isA<TransportSecurityFailure>()),
      );
      expect(fallback, isFalse);
    },
  );

  test('only accepts explicitly named endpoints and secure defaults', () {
    expect(() => WebEndpoints(webTransport: wt), returnsNormally);
    expect(() => WebEndpoints(), throwsArgumentError);
    expect(
      () =>
          WebEndpoints(webTransport: Uri.parse('https://peer.example/channel')),
      throwsArgumentError,
    );
    expect(
      () => WebEndpoints(webSocket: Uri.parse('ws://peer.example/channel')),
      throwsArgumentError,
    );
    expect(
      () => WebEndpoints(
        webSocket: Uri.parse('wss://else.example'),
        webTransport: wt,
      ),
      throwsArgumentError,
    );
    expect(
      () => WebEndpoints(webSocket: Uri.parse('wss://peer.example?key=x')),
      throwsArgumentError,
    );
    expect(
      () => WebEndpoints(
        webSocket: Uri.parse('ws://localhost:8080/channel'),
        allowLocalPlainWebSocket: true,
      ),
      returnsNormally,
    );
  });

  test('direct WebSocket remains supported', () async {
    final link = await connectWebChannel(
      WebEndpoints(webSocket: ws),
      webSocketDialer: (url, timeout, pins) async =>
          FakeLink(WebChannelKind.webSocket),
    );
    expect(link.kind, WebChannelKind.webSocket);
  });
}
