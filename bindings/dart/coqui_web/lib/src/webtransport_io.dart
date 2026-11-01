import 'contracts.dart';

/// Dart VM has no browser WebTransport constructor. Prefer a WSS fallback.
Future<WebChannel> openWebTransportChannel(
  Uri uri,
  Duration timeout,
  List<String> certificatePins,
) async => throw const TransportUnavailable('WebTransport requires a compatible browser');
