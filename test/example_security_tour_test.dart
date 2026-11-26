import 'package:flutter_test/flutter_test.dart';

// Exercise the shipped example as an integration client of the public API.
// ignore: avoid_relative_lib_imports
import '../example/lib/main.dart' as example;

void main() {
  test('example executes the ten hardening checks against the native library',
      () async {
    final messages = <String>[];
    // The example throws if a rejection is missing, an unrelated error occurs,
    // or the valid control for an operation fails.
    await example.runExample(writeLog: messages.add);
    expect(messages.where((line) => line.startsWith('[PASS] ')), hasLength(10));
    expect(messages, contains('[CHECKS] 10/10 demonstrations passed.'));
    // Critical Contract is 17 UTF-8 bytes: attached ML-DSA-65 output is 3309+17.
    expect(messages, contains('[DSA] Attached signed message: 3326 bytes'));
    expect(
        messages,
        contains(
            '[KEM] Using Algorithm: ML-KEM-768 (NIST Security Category 3)'));
    expect(messages.any((line) => line.startsWith('[SCOPE]')), isTrue);
  });
}
