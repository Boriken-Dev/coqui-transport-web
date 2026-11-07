import 'dart:async';
import 'dart:collection';

/// A transport-level message queue that retains one subscription from early
/// connection setup into the application protocol.
///
/// No cryptography, peer identity, authentication method or application protocol
/// appears here. Consumers (such as coqui-peer) read setup messages, then hand off
/// any pending data to the application only after verification succeeds.
final class MessageHandoff<T> {
  MessageHandoff({
    required Stream<T> incoming,
    required Future<void> Function(T) send,
    required Future<void> Function() closeSource,
    this.maxPending = 16,
  }) : _send = send,
       _closeSource = closeSource {
    if (maxPending < 1) throw ArgumentError.value(maxPending, 'maxPending');
    _subscription = incoming.listen(
      _receive,
      onError: _fail,
      onDone: () => _fail(StateError('Transport disconnected')),
    );
  }

  final int maxPending;
  final Future<void> Function(T) _send;
  final Future<void> Function() _closeSource;
  final Queue<T> _pending = Queue<T>();
  final StreamController<T> _out = StreamController<T>(sync: true);
  late final StreamSubscription<T> _subscription;
  Completer<T>? _waiter;
  Object? _failure;
  bool _handoff = false;
  bool _closed = false;

  /// Complete, ordered application messages, available after handoff.
  Stream<T> get applicationMessages => _out.stream;

  void _receive(T message) {
    if (_closed || _failure != null) return;
    if (_handoff) {
      _out.add(message);
    } else if (_waiter case final waiter?) {
      _waiter = null;
      waiter.complete(message);
    } else if (_pending.length >= maxPending) {
      _fail(StateError('Early message queue exceeded its limit'));
    } else {
      _pending.add(message);
    }
  }

  void _fail(Object error, [StackTrace? trace]) {
    if (_closed || _failure != null) return;
    _failure = error;
    final waiter = _waiter;
    _waiter = null;
    if (waiter != null && !waiter.isCompleted) {
      waiter.completeError(error, trace);
    }
    if (_handoff && !_out.isClosed) {
      _out.addError(error, trace);
      unawaited(_out.close());
    }
  }

  /// Read one setup message. The caller must enforce a deadline and drive
  /// the appropriate coqui-peer handshake; this class does not interpret it.
  Future<T> nextSetupMessage() {
    if (_closed || _handoff) throw StateError('Setup phase ended');
    if (_waiter != null) throw StateError('Concurrent setup reads forbidden');
    if (_failure != null) return Future.error(_failure!);
    if (_pending.isNotEmpty) return Future.value(_pending.removeFirst());
    final waiter = Completer<T>();
    _waiter = waiter;
    return waiter.future;
  }

  /// Transfer remaining messages to the application. Must only be invoked
  /// by an adapter after an independent peer-authentication method succeeded.
  void handoff() {
    if (_closed || _handoff || _waiter != null || _failure != null) {
      throw StateError('Invalid message handoff');
    }
    _handoff = true;
    while (_pending.isNotEmpty) {
      _out.add(_pending.removeFirst());
    }
  }

  Future<void> send(T message) {
    if (_closed || _failure != null) {
      throw StateError('Message channel is closed');
    }
    return _send(message);
  }

  /// Throws unless this channel may still send: for a sender that goes round [send].
  void checkOpen() {
    if (_closed || _failure != null) {
      throw StateError('Message channel is closed');
    }
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final waiter = _waiter;
    _waiter = null;
    if (waiter != null && !waiter.isCompleted) {
      waiter.completeError(StateError('Transport closed during setup'));
    }
    await _subscription.cancel();
    await _closeSource();
    // Before an application subscribes, waiting for a single-subscription
    // controller's close future can hang indefinitely.
    if (!_out.isClosed) unawaited(_out.close());
  }
}
