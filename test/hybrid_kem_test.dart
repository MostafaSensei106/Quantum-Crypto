import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

void main() {
  setUpAll(() async {
    await QuantumCrypto.init();
  });

  group('Hybrid KEM Operations', () {
    for (final algorithm in HybridKemAlgorithm.values) {
      test('${algorithm.name} KeyGen, Encapsulation, and Decapsulation',
          () async {
        // 1. Key Generation
        final keyPair = await QuantumCrypto.hybrid.generateKeyPair(algorithm);

        expect(keyPair.mlKemPublicKey, isNotEmpty,
            reason: 'ML-KEM public key should not be empty');
        expect(keyPair.mlKemSecretKey, isNotEmpty,
            reason: 'ML-KEM secret key should not be empty');
        expect(keyPair.x25519PublicKey, isNotEmpty,
            reason: 'X25519 public key should not be empty');
        expect(keyPair.x25519SecretKey, isNotEmpty,
            reason: 'X25519 secret key should not be empty');

        // 2. Encapsulation
        final encResult = await QuantumCrypto.hybrid.encapsulate(
          algorithm: algorithm,
          mlKemPublicKey: keyPair.mlKemPublicKey,
          x25519PublicKey: keyPair.x25519PublicKey,
        );

        expect(encResult.mlKemCiphertext, isNotEmpty,
            reason: 'ML-KEM ciphertext should not be empty');
        expect(encResult.x25519EphemeralPk, isNotEmpty,
            reason: 'X25519 ephemeral pk should not be empty');
        expect(encResult.sharedSecret, isNotEmpty,
            reason: 'Shared secret should not be empty');

        // 3. Decapsulation
        final decapsulatedSecret = await QuantumCrypto.hybrid.decapsulate(
          algorithm: algorithm,
          mlKemCiphertext: encResult.mlKemCiphertext,
          x25519EphemeralPk: encResult.x25519EphemeralPk,
          mlKemSecretKey: keyPair.mlKemSecretKey,
          x25519SecretKey: keyPair.x25519SecretKey,
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
