@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:coqui_transport_web/coqui_transport_web.dart';
import 'package:test/test.dart';

Uint8List _bytes(String hex) => Uint8List.fromList([
  for (var at = 0; at < hex.length; at += 2)
    int.parse(hex.substring(at, at + 2), radix: 16),
]);

String _hex(List<int> bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

void main() {
  final vectors =
      jsonDecode(File('../../../tests/vectors/frames.json').readAsStringSync())
          as Map<String, dynamic>;

  for (final raw in vectors['encode'] as List<dynamic>) {
    final item = raw as Map<String, dynamic>;
    test('encode: ${item['name']}', () {
      final text = item['text'] as String;
      final max = item['max'] as int;
      if (item['error'] == true) {
        expect(
          () => encodeFrame(text, maxBytes: max),
          throwsA(isA<TransportProtocolFailure>()),
        );
      } else {
        expect(_hex(encodeFrame(text, maxBytes: max)), item['hex']);
      }
    });
  }

  for (final raw in vectors['decode'] as List<dynamic>) {
    final item = raw as Map<String, dynamic>;
    test('decode: ${item['name']}', () {
      final decoder = FrameDecoder(maxBytes: item['max'] as int);
      final got = <String>[];
      var failed = false;
      for (final chunk in item['chunks'] as List<dynamic>) {
        decoder.push(_bytes(chunk as String));
        try {
          for (
            var text = decoder.nextText();
            text != null;
            text = decoder.nextText()
          ) {
            got.add(text);
          }
        } on TransportProtocolFailure {
          failed = true;
        }
      }
      expect(got, item['messages']);
      expect(failed, item['error'] == true || item['text_error'] == true);
    });
  }
}
