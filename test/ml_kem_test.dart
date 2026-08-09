import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

void main() {
  setUpAll(() async {
    await QuantumCrypto.init();
  });

  group('ML-KEM Operations', () {
    for (final algorithm in KemAlgorithm.values) {
      test('${algorithm.name} KeyGen, Encapsulation, and Decapsulation',
          () async {
        // 1. Key Generation
        final keyPair = await QuantumCrypto.kem.generateKeyPair(algorithm);
        expect(keyPair.publicKey, isNotEmpty,
            reason: 'Public key should not be empty');
        expect(keyPair.secretKey, isNotEmpty,
            reason: 'Secret key should not be empty');

        // 2. Encapsulation
        final encResult = await QuantumCrypto.kem.encapsulate(
          algorithm: algorithm,
          publicKey: keyPair.publicKey,
        );
        expect(encResult.ciphertext, isNotEmpty,
            reason: 'Ciphertext should not be empty');
        expect(encResult.sharedSecret, isNotEmpty,
            reason: 'Shared secret should not be empty');

        // 3. Decapsulation
        final decapsulatedSecret = await QuantumCrypto.kem.decapsulate(
          algorithm: algorithm,
          ciphertext: encResult.ciphertext,
          secretKey: keyPair.secretKey,
        );

        // 4. Verification
        expect(
          decapsulatedSecret,
          equals(encResult.sharedSecret),
          reason: 'Decapsulated secret must match original shared secret',
        );
      });
    }
  });
}
