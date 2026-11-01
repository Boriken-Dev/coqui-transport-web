import 'dart:convert';
import 'dart:io';

import 'package:stream_channel/stream_channel.dart';

/// Runs the Rust echo peer on the VM side of a test and hands its first line (ports, pin) to the test.
/// The test ending closes the channel, which ends the peer.
Future<void> hybridMain(StreamChannel<Object?> channel) async {
  final peer = await Process.start(
    'cargo',
    ['run', '--quiet', '--all-features', '--example', 'echo'],
    workingDirectory: '../../..',
    runInShell: true,
  );
  peer.stderr.transform(utf8.decoder).listen(stderr.write);
  peer.stdout
      .transform(utf8.decoder)
      .transform(const LineSplitter())
      .listen(channel.sink.add);
  await channel.stream.drain<void>();
  peer.kill();
}
