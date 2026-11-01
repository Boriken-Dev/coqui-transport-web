import 'connect.dart';
import 'websocket.dart';

/// Why an established connection stopped making useful progress.
///
/// Browser WebTransport does not reliably expose QUIC's PMTU diagnostics.
/// A measured application-level probe timeout is therefore a *suspected*
/// path failure, not proof of an MTU mismatch.
enum LinkFailure {
  transportUnavailable,
  pathLost,
  progressTimedOut,
  suspectedMtuBlackhole,
  peerProofRejected,
  certificateRejected,
  protocolRejected,
  userDisconnected,
}

enum LinkRecovery {
  /// No automatic transport change is appropriate.
  failClosed,

  /// A WSS connection may be attempted, but must independently prove the
  /// original peer identity before any application message is allowed.
  connectWssAndVerify,
}

/// Reconnection policy, independent of the application and the concrete transport API.
///
/// A failed *authenticated* session never has pending commands replayed
/// automatically. It must reconcile or load its state in the application.
LinkRecovery decideRecovery({
  required WebChannelKind failedTransport,
  required LinkFailure failure,
  required WebEndpoints endpoints,
}) {
  if (failedTransport != WebChannelKind.webTransport ||
      endpoints.webSocket == null) {
    return LinkRecovery.failClosed;
  }

  return switch (failure) {
    LinkFailure.transportUnavailable ||
    LinkFailure.pathLost ||
    LinkFailure.progressTimedOut ||
    LinkFailure.suspectedMtuBlackhole => LinkRecovery.connectWssAndVerify,
    LinkFailure.peerProofRejected ||
    LinkFailure.certificateRejected ||
    LinkFailure.protocolRejected ||
    LinkFailure.userDisconnected => LinkRecovery.failClosed,
  };
}

/// A real implementation must prove possession of the pinned peer's key
/// using the versioned coqui-peer-compatible handshake, not an asserted
/// value in a hello message, hostname, TLS certificate, or URL.
typedef VerifyEstablishedPeer = Future<String> Function(WebChannel channel);

final class RecoveredLink {
  const RecoveredLink({
    required this.connection,
    required this.peerId,
    required this.remoteSessionId,
  });

  final WebChannel connection;
  final String peerId;

  /// The existing remote session to reattach/load *if the application supports
  /// it*. This does not mean the session has already been recovered.
  final String? remoteSessionId;

  /// The last in-flight prompt/tool invocation has an unknown outcome.
  /// Never replay it merely because this new transport is connected.
  bool get requiresSessionReconciliation => remoteSessionId != null;
}

/// Establish WSS after a failed WebTransport connection and independently
/// prove the SAME expected peer before handing back the channel.
///
/// This sends no application message.
/// Callers explicitly reconcile a previous session and its in-flight work.
Future<RecoveredLink> recoverWebTransportPath({
  required WebEndpoints endpoints,
  required LinkFailure failure,
  required String expectedPeerId,
  required VerifyEstablishedPeer verifyPeer,
  String? remoteSessionId,
  Duration timeout = const Duration(seconds: 10),
  WebDialer? webSocketDialer,
}) async {
  if (expectedPeerId.isEmpty) {
    throw ArgumentError.value(expectedPeerId, 'expectedPeerId');
  }
  if (timeout <= Duration.zero) {
    throw ArgumentError.value(timeout, 'timeout');
  }
  if (decideRecovery(
        failedTransport: WebChannelKind.webTransport,
        failure: failure,
        endpoints: endpoints,
      ) !=
      LinkRecovery.connectWssAndVerify) {
    throw StateError('Transport fallback denied by recovery policy');
  }

  final channel = await (webSocketDialer ?? openWebSocketChannel)(
    endpoints.webSocket!,
    timeout,
    const [],
  );
  try {
    final proven = await verifyPeer(channel).timeout(timeout);
    if (proven != expectedPeerId) {
      throw StateError(
        'WSS fallback peer identity differs from the verified WebTransport peer',
      );
    }
    return RecoveredLink(
      connection: channel,
      peerId: proven,
      remoteSessionId: remoteSessionId,
    );
  } catch (_) {
    await channel.close();
    rethrow;
  }
}
