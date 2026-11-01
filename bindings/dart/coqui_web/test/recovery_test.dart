import 'dart:async';

import 'package:coqui_web/coqui_web.dart';
import 'package:test/test.dart';

final class FakeConnection implements WebChannel {
  bool closed = false;
  final outgoing = <String>[];

  @override
  WebChannelKind get kind => WebChannelKind.webSocket;

  @override
  Stream<String> get messages => const Stream<String>.empty();

  @override
  Future<void> send(String message) async {
    outgoing.add(message);
  }

  @override
  Future<void> close() async {
    closed = true;
  }
}

void main() {
  final endpoints = WebEndpoints(
    webTransport: Uri.parse('https://peer.example:4433/channel'),
    webSocket: Uri.parse('wss://peer.example:4434/channel'),
  );

  test('stalled or MTU-blackholed WebTransport can fall back', () {
    for (final reason in [
      LinkFailure.transportUnavailable,
      LinkFailure.pathLost,
      LinkFailure.progressTimedOut,
      LinkFailure.suspectedMtuBlackhole,
    ]) {
      expect(
        decideRecovery(
          failedTransport: WebChannelKind.webTransport,
          failure: reason,
          endpoints: endpoints,
        ),
        LinkRecovery.connectWssAndVerify,
      );
    }
  });

  test('authentication, certificate and protocol failures never downgrade', () {
    for (final reason in [
      LinkFailure.peerProofRejected,
      LinkFailure.certificateRejected,
      LinkFailure.protocolRejected,
      LinkFailure.userDisconnected,
    ]) {
      expect(
        decideRecovery(
          failedTransport: WebChannelKind.webTransport,
          failure: reason,
          endpoints: endpoints,
        ),
        LinkRecovery.failClosed,
      );
    }
  });

  test(
    'fallback is impossible from WSS or without an advertised WSS endpoint',
    () {
      expect(
        decideRecovery(
          failedTransport: WebChannelKind.webSocket,
          failure: LinkFailure.suspectedMtuBlackhole,
          endpoints: endpoints,
        ),
        LinkRecovery.failClosed,
      );
      expect(
        decideRecovery(
          failedTransport: WebChannelKind.webTransport,
          failure: LinkFailure.pathLost,
          endpoints: WebEndpoints(
            webTransport: Uri.parse('https://peer.example:4433/channel'),
          ),
        ),
        LinkRecovery.failClosed,
      );
    },
  );

  test(
    'new WSS channel must prove the same peer; pending work not replayed',
    () async {
      final channel = FakeConnection();
      final result = await recoverWebTransportPath(
        endpoints: endpoints,
        failure: LinkFailure.suspectedMtuBlackhole,
        expectedPeerId: 'sha256:expected',
        remoteSessionId: 'session-42',
        verifyPeer: (opened) async {
          expect(identical(opened, channel), isTrue);
          return 'sha256:expected';
        },
        webSocketDialer: (url, timeout, pins) async {
          expect(url, endpoints.webSocket);
          return channel;
        },
      );
      expect(result.peerId, 'sha256:expected');
      expect(result.remoteSessionId, 'session-42');
      expect(result.requiresSessionReconciliation, isTrue);
      expect(channel.outgoing, isEmpty);
      expect(channel.closed, isFalse);
      await result.connection.close();
    },
  );

  test(
    'different or rejected peer is refused and its channel closed',
    () async {
      final channel = FakeConnection();
      await expectLater(
        recoverWebTransportPath(
          endpoints: endpoints,
          failure: LinkFailure.pathLost,
          expectedPeerId: 'sha256:expected',
          verifyPeer: (_) async => 'sha256:impostor',
          webSocketDialer: (_, _, _) async => channel,
        ),
        throwsStateError,
      );
      expect(channel.closed, isTrue);
      expect(channel.outgoing, isEmpty);
    },
  );

  test('peer-verification timeout closes the fallback connection', () async {
    final channel = FakeConnection();
    await expectLater(
      recoverWebTransportPath(
        endpoints: endpoints,
        failure: LinkFailure.progressTimedOut,
        expectedPeerId: 'sha256:expected',
        timeout: const Duration(milliseconds: 10),
        verifyPeer: (_) => Completer<String>().future,
        webSocketDialer: (_, _, _) async => channel,
      ),
      throwsA(isA<TimeoutException>()),
    );
    expect(channel.closed, isTrue);
  });

  test('security failure never dials WSS', () async {
    var attempts = 0;
    await expectLater(
      recoverWebTransportPath(
        endpoints: endpoints,
        failure: LinkFailure.certificateRejected,
        expectedPeerId: 'sha256:expected',
        verifyPeer: (_) async => 'sha256:expected',
        webSocketDialer: (_, _, _) async {
          attempts++;
          return FakeConnection();
        },
      ),
      throwsStateError,
    );
    expect(attempts, 0);
  });
}
