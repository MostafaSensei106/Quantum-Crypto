import 'dart:convert';
import 'dart:developer';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> main() async {
  await QuantumCrypto.init();
  // === 1. KEM Test ===
  final KemService kemService = const MlKemService();
  final kemKeyPair = await kemService.generateKeyPair(KemAlgorithm.mlKem768);
  final encapsulation = await kemService.encapsulate(
    algorithm: KemAlgorithm.mlKem768,
    publicKey: kemKeyPair.publicKey,
  );
  final derivedSecret = await kemService.decapsulate(
    algorithm: KemAlgorithm.mlKem768,
    ciphertext: encapsulation.ciphertext,
    secretKey: kemKeyPair.secretKey,
  );
  log(
    'KEM Exchange Success: ${_bytesEquals(encapsulation.sharedSecret, derivedSecret)}',
  );

  // === 2. Digital Signature (ML-DSA) Test ===
  final DsaService dsaService = const MlDsaService();
  const dsaAlgorithm = DsaAlgorithm.mlDsa65;

  log('\n=== Running ${dsaAlgorithm.name} ===');

  final dsaKeyPair = await dsaService.generateKeyPair(dsaAlgorithm);
  log('DSA Public Key Length: ${dsaKeyPair.publicKey.length} bytes');
  log('DSA Secret Key Length: ${dsaKeyPair.secretKey.length} bytes');

  final message = Uint8List.fromList(
    utf8.encode('Post-Quantum Secure Payload'),
  );

  final signature = await dsaService.sign(
    algorithm: dsaAlgorithm,
    message: message,
    secretKey: dsaKeyPair.secretKey,
  );

  log('Signature Length: ${signature.length} bytes');

  final isValid = await dsaService.verify(
    algorithm: dsaAlgorithm,
    message: message,
    signature: signature,
    publicKey: dsaKeyPair.publicKey,
  );

  log(
    'Digital Signature Verification Result: ${isValid ? "VALID 📜✅" : "INVALID ❌"}',
  );
}

bool _bytesEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
