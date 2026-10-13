import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

void main() {
  setUpAll(() async {
    await QuantumCrypto.init();
  });

  group('SLH-DSA Operations (FIPS 205, detached signatures)', () {
    final message =
        Uint8List.fromList(utf8.encode('Top Secret Quantum Message!'));

    for (final algorithm in SlhDsaAlgorithm.values) {
      test('${algorithm.name} KeyGen, Sign, and Verify', () async {
        // 1. Key Generation
        final keyPair = await QuantumCrypto.slhDsa.generateKeyPair(algorithm);
        expect(keyPair.publicKey, isNotEmpty,
            reason: 'Public key should not be empty');
        expect(keyPair.secretKey, isNotEmpty,
            reason: 'Secret key should not be empty');

        // 2. Signing (detached: signature does NOT embed the message)
        final signature = await QuantumCrypto.slhDsa.sign(
          algorithm: algorithm,
          message: message,
          secretKey: keyPair.secretKey,
        );
        expect(signature, isNotEmpty, reason: 'Signature should not be empty');

        // 3. Verification - Valid
        final isValid = await QuantumCrypto.slhDsa.verify(
          algorithm: algorithm,
          message: message,
          signature: signature,
          publicKey: keyPair.publicKey,
        );
        expect(isValid, isTrue,
            reason: 'Valid signature should verify successfully');

        // 4. Verification - Invalid Signature
        final modifiedSignature = Uint8List.fromList(signature);
        if (modifiedSignature.isNotEmpty) {
          modifiedSignature[0] ^= 0x01; // flip a bit
        }

        final isInvalidSig = await QuantumCrypto.slhDsa.verify(
          algorithm: algorithm,
          message: message,
          signature: modifiedSignature,
          publicKey: keyPair.publicKey,
        );
        expect(isInvalidSig, isFalse,
            reason: 'Tampered signature should fail verification');

        // 5. Verification - Tampered Message
        final tamperedMessage =
            Uint8List.fromList(utf8.encode('Top Secret Quantum Message?'));
        final isInvalidMsg = await QuantumCrypto.slhDsa.verify(
          algorithm: algorithm,
          message: tamperedMessage,
          signature: signature,
          publicKey: keyPair.publicKey,
        );
        expect(isInvalidMsg, isFalse,
            reason: 'Tampered message should fail verification');
      });
    }
  });
}
