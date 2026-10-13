import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  setUpAll(() async {
    await QuantumCrypto.init();
  });

  group('Hash API (SHA-2 / SHA-3)', () {
    test('digest lengths match the algorithm', () async {
      final data = Uint8List.fromList(utf8.encode('abc'));
      for (final algorithm in HashAlgorithm.values) {
        final digest = await QuantumCrypto.hash.digest(algorithm, data);
        expect(digest.length, algorithm.digestLength,
            reason: '${algorithm.name} digest length mismatch');
      }
    });

    test('SHA-256 empty string known answer', () async {
      final digest =
          await QuantumCrypto.hash.digest(HashAlgorithm.sha256, Uint8List(0));
      expect(_hex(digest),
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });
  });

  group('XChaCha20-Poly1305 AEAD', () {
    test('encrypt/decrypt roundtrip with 24-byte nonce', () async {
      final key = Uint8List(32);
      final plaintext =
          Uint8List.fromList(utf8.encode('extended-nonce payload'));
      final ciphertext = await QuantumCrypto.aead.encrypt(
        algorithm: AeadAlgorithm.xChaCha20Poly1305,
        key: key,
        plaintext: plaintext,
      );
      // 24-byte nonce + plaintext + 16-byte tag.
      expect(ciphertext.length, 24 + plaintext.length + 16);
      final decrypted = await QuantumCrypto.aead.decrypt(
        algorithm: AeadAlgorithm.xChaCha20Poly1305,
        key: key,
        ciphertextWithNonce: ciphertext,
      );
      expect(decrypted, plaintext);
    });
  });

  group('HKDF hash agility', () {
    test('SHA-384 and SHA-512 derive requested lengths', () async {
      final ikm = Uint8List.fromList(utf8.encode('input key material'));
      final info = Uint8List.fromList(utf8.encode('test'));
      for (final hash in HkdfHash.values) {
        final okm = await QuantumCrypto.kdf.derive(
          sharedSecret: ikm,
          info: info,
          outputLength: 64,
          hash: hash,
        );
        expect(okm.length, 64, reason: '${hash.name} length mismatch');
      }
      // Different digests must produce different output.
      final sha256 = await QuantumCrypto.kdf.derive(
        sharedSecret: ikm,
        info: info,
        outputLength: 32,
      );
      final sha512 = await QuantumCrypto.kdf.derive(
        sharedSecret: ikm,
        info: info,
        outputLength: 32,
        hash: HkdfHash.sha512,
      );
      expect(sha256, isNot(equals(sha512)));
    });
  });
}
