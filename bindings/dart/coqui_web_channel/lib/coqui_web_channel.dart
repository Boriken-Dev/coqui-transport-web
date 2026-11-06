/// Reliable message channels a browser can open natively: WebTransport first,
/// WebSocket as an explicit fallback, and a safe policy between them.
library;

export 'src/connect.dart';
export 'src/message_handoff.dart';
export 'src/recovery.dart';
export 'src/staged_channel.dart';
export 'src/websocket.dart';
