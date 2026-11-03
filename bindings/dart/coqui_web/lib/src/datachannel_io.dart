import 'contracts.dart';
import 'datachannel_path.dart';

/// The Dart VM has no WebRTC, so a channel stays on its WebSocket.
DataChannelPath? startDataChannel(
  Uri endpoint,
  DataChannelSettings settings,
  DataChannelEvents events,
) => null;
