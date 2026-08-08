import 'dart:developer';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> main() async {
  await RustLib.init();
  final KemService kemService = const MlKemService();
  const algorithm = KemAlgorithm.mlKem768;

  log('=== Running ${algorithm.name} ===');

  final keyPair = await kemService.generateKeyPair(algorithm);
  log('Public Key Length: ${keyPair.publicKey.length} bytes');
  log('Secret Key Length: ${keyPair.secretKey.length} bytes');

  final encapsulation = await kemService.encapsulate(
    algorithm: algorithm,
    publicKey: keyPair.publicKey,
  );

  log('Ciphertext Length: ${encapsulation.ciphertext.length} bytes');
  log('Sender Shared Secret: ${encapsulation.sharedSecret}');

  final derivedSharedSecret = await kemService.decapsulate(
    algorithm: algorithm,
    ciphertext: encapsulation.ciphertext,
    secretKey: keyPair.secretKey,
  );

  log('Receiver Shared Secret: $derivedSharedSecret');

  final isMatched = _bytesEquals(
    encapsulation.sharedSecret,
    derivedSharedSecret,
  );
  log('Result: Key Exchange ${isMatched ? "SUCCESSFUL 🎉" : "FAILED ❌"}');
}

bool _bytesEquals(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
