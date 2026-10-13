import 'dart:convert';
import 'dart:developer';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';

Future<void> main() async {
  log('=============================================');
  log('    🚀 Quantum Crypto Example 🚀    ');
  log('=============================================\n');

  // Initialize the FFI bindings
  log('[INFO] Initializing QuantumCrypto Rust bindings...');
  await QuantumCrypto.init();
  log('[INFO] Initialization completed.\n');

  // =========================================================
  // 1. Pure ML-KEM (Key Encapsulation Mechanism)
  // =========================================================
  log('--- 1. Pure ML-KEM (Post-Quantum Key Exchange) ---');
  final kemAlgo = KemAlgorithm.mlKem768; // NIST Security Level 3
  log('[KEM] Using Algorithm: ${kemAlgo.name}');

  final kemKeyPair = await QuantumCrypto.kem.generateKeyPair(kemAlgo);
  log(
    '[KEM] KeyPair generated. Public Key: ${kemKeyPair.publicKey.length} bytes | Secret Key: ${kemKeyPair.secretKey.length} bytes',
  );

  final kemEncapsulation = await QuantumCrypto.kem.encapsulate(
    algorithm: kemAlgo,
    publicKey: kemKeyPair.publicKey,
  );
  log(
    '[KEM] Encapsulated. Ciphertext: ${kemEncapsulation.ciphertext.length} bytes',
  );

  final kemDecapsulated = await QuantumCrypto.kem.decapsulate(
    algorithm: kemAlgo,
    ciphertext: kemEncapsulation.ciphertext,
    secretKey: kemKeyPair.secretKey,
  );
  final kemMatch = _bytesEquals(kemEncapsulation.sharedSecret, kemDecapsulated);
  log('[KEM] Shared Secret Match: ${kemMatch ? "✅ SUCCESS" : "❌ FAILED"}\n');

  // =========================================================
  // 2. Pure ML-DSA (Digital Signature Algorithm)
  // =========================================================
  log('--- 2. Pure ML-DSA (Post-Quantum Digital Signatures) ---');
  final dsaAlgo = DsaAlgorithm.mlDsa65;
  log('[DSA] Using Algorithm: ${dsaAlgo.name}');

  final dsaKeyPair = await QuantumCrypto.dsa.generateKeyPair(dsaAlgo);
  log(
    '[DSA] KeyPair generated. Public Key: ${dsaKeyPair.publicKey.length} bytes | Secret Key: ${dsaKeyPair.secretKey.length} bytes',
  );

  final document = Uint8List.fromList(utf8.encode('Critical Contract'));
  final signature = await QuantumCrypto.dsa.sign(
    algorithm: dsaAlgo,
    message: document,
    secretKey: dsaKeyPair.secretKey,
  );
  log('[DSA] Signed document. Signature size: ${signature.length} bytes');

  final dsaValid = await QuantumCrypto.dsa.verify(
    algorithm: dsaAlgo,
    message: document,
    signature: signature,
    publicKey: dsaKeyPair.publicKey,
  );
  log('[DSA] Signature Verification: ${dsaValid ? "✅ VALID" : "❌ INVALID"}\n');

  // =========================================================
  // 3. SLH-DSA (FIPS 205 Stateless Hash-Based Signatures) [NEW in 0.0.2]
  // =========================================================
  log('--- 3. SLH-DSA (Hash-Based Signatures, FIPS 205) ---');
  final slhAlgo = SlhDsaAlgorithm.slhDsaSha2_128f; // NIST Security Level 1
  log('[SLH-DSA] Using Algorithm: ${slhAlgo.name}');
  log('[SLH-DSA] Note: detached signatures (message NOT embedded).');

  final slhKeyPair = await QuantumCrypto.slhDsa.generateKeyPair(slhAlgo);
  log(
    '[SLH-DSA] KeyPair generated. Public Key: ${slhKeyPair.publicKey.length} bytes | Secret Key: ${slhKeyPair.secretKey.length} bytes',
  );

  final slhSignature = await QuantumCrypto.slhDsa.sign(
    algorithm: slhAlgo,
    message: document,
    secretKey: slhKeyPair.secretKey,
  );
  log(
    '[SLH-DSA] Signed document. Detached signature: ${slhSignature.length} bytes',
  );

  final slhValid = await QuantumCrypto.slhDsa.verify(
    algorithm: slhAlgo,
    message: document,
    signature: slhSignature,
    publicKey: slhKeyPair.publicKey,
  );
  log(
    '[SLH-DSA] Signature Verification: ${slhValid ? "✅ VALID" : "❌ INVALID"}\n',
  );

  // =========================================================
  // 4. Hybrid KEM (ML-KEM + X25519)
  // =========================================================
  log('--- 4. Hybrid KEM (ML-KEM-768 + X25519) ---');
  final hybridAlgo = HybridKemAlgorithm.mlKem768X25519;
  log('[HYBRID] Using Algorithm: ${hybridAlgo.name}');

  final hybridKeyPair = await QuantumCrypto.hybrid.generateKeyPair(hybridAlgo);
  log('[HYBRID] KeyPair generated.');

  final hybridEncapsulation = await QuantumCrypto.hybrid.encapsulate(
    algorithm: hybridAlgo,
    mlKemPublicKey: hybridKeyPair.mlKemPublicKey,
    x25519PublicKey: hybridKeyPair.x25519PublicKey,
  );
  log('[HYBRID] Encapsulated.');

  final hybridDecapsulated = await QuantumCrypto.hybrid.decapsulate(
    algorithm: hybridAlgo,
    mlKemCiphertext: hybridEncapsulation.mlKemCiphertext,
    x25519EphemeralPk: hybridEncapsulation.x25519EphemeralPk,
    mlKemSecretKey: hybridKeyPair.mlKemSecretKey,
    x25519SecretKey: hybridKeyPair.x25519SecretKey,
  );

  final hybridMatch = _bytesEquals(
    hybridEncapsulation.sharedSecret,
    hybridDecapsulated,
  );
  log(
    '[HYBRID] Shared Secret Match: ${hybridMatch ? "✅ SUCCESS" : "❌ FAILED"}\n',
  );

  // =========================================================
  // 5. AEAD Symmetric Encryption (+ XChaCha20-Poly1305) [NEW in 0.0.2]
  // =========================================================
  log('--- 5. AEAD Encryption (AES-256-GCM + XChaCha20-Poly1305) ---');
  final aeadAlgo = AeadAlgorithm.aes256Gcm;
  log('[AEAD] Using Algorithm: ${aeadAlgo.name}');

  final symmetricKey = hybridEncapsulation.sharedSecret; // 32-byte key
  final payload = Uint8List.fromList(utf8.encode('Secret Data'));

  final ciphertextWithNonce = await QuantumCrypto.aead.encrypt(
    algorithm: aeadAlgo,
    key: symmetricKey,
    plaintext: payload,
  );
  log('[AEAD] Encrypted payload size: ${ciphertextWithNonce.length} bytes');

  final decryptedPayload = await QuantumCrypto.aead.decrypt(
    algorithm: aeadAlgo,
    key: symmetricKey,
    ciphertextWithNonce: ciphertextWithNonce,
  );

  final aeadMatch = _bytesEquals(payload, decryptedPayload);
  log('[AEAD] Decrypted text: "${utf8.decode(decryptedPayload)}"');
  log('[AEAD] Decryption Match: ${aeadMatch ? "✅ SUCCESS" : "❌ FAILED"}');

  // XChaCha20-Poly1305: 24-byte random nonce, safe without a counter.
  // Wire format: 24-byte nonce || ciphertext+tag.
  final xPayload = Uint8List.fromList(utf8.encode('Extended-nonce secret'));
  final xCiphertext = await QuantumCrypto.aead.encrypt(
    algorithm: AeadAlgorithm.xChaCha20Poly1305,
    key: symmetricKey,
    plaintext: xPayload,
  );
  log(
    '[AEAD:XChaCha20] Encrypted size: ${xCiphertext.length} bytes '
    '(24 nonce + ${xPayload.length} plaintext + 16 tag)',
  );

  final xDecrypted = await QuantumCrypto.aead.decrypt(
    algorithm: AeadAlgorithm.xChaCha20Poly1305,
    key: symmetricKey,
    ciphertextWithNonce: xCiphertext,
  );
  final xMatch = _bytesEquals(xPayload, xDecrypted);
  log(
    '[AEAD:XChaCha20] Decryption Match: ${xMatch ? "✅ SUCCESS" : "❌ FAILED"}\n',
  );

  // =========================================================
  // 6. Key Serialization & Utilities
  // =========================================================
  log('--- 6. Key Serialization Helpers ---');
  final hexKey = await QuantumCrypto.keys.bytesToHex(kemKeyPair.publicKey);
  log('[SERIALIZE] Public Key (Hex)    [${hexKey.length} chars]: ...');

  final b64Key = await QuantumCrypto.keys.bytesToBase64(kemKeyPair.publicKey);
  log('[SERIALIZE] Public Key (Base64) [${b64Key.length} chars]: ...\n');

  // =========================================================
  // 7. Secure Messaging (Sign-then-Encrypt)
  // =========================================================
  log('--- 7. Secure Messaging ---');
  final messageToMostafa = Uint8List.fromList(utf8.encode('Top Secret'));

  // We use signAndEncrypt as defined in the library
  final securePackage = await QuantumCrypto.messaging.signAndEncrypt(
    message: messageToMostafa,
    senderDsaSecretKey: dsaKeyPair.secretKey,
    recipientMlKemPublicKey: hybridKeyPair.mlKemPublicKey,
    recipientX25519PublicKey: hybridKeyPair.x25519PublicKey,
    dsaAlgorithm: dsaAlgo,
    kemAlgorithm: HybridKemAlgorithm.mlKem768X25519,
    aeadAlgorithm: AeadAlgorithm.aes256Gcm,
  );
  log('[MESSAGING] Generated Secure Package.');

  final verifiedDecryptedMessage = await QuantumCrypto.messaging
      .decryptAndVerify(
        package: securePackage,
        recipientMlKemSecretKey: hybridKeyPair.mlKemSecretKey,
        recipientX25519SecretKey: hybridKeyPair.x25519SecretKey,
        senderDsaPublicKey: dsaKeyPair.publicKey,
      );

  final messagingMatch = _bytesEquals(
    messageToMostafa,
    verifiedDecryptedMessage,
  );
  log(
    '[MESSAGING] Message verified and decrypted: "${utf8.decode(verifiedDecryptedMessage)}"',
  );
  log('[MESSAGING] Pipeline: ${messagingMatch ? "✅ SUCCESS" : "❌ FAILED"}\n');

  // =========================================================
  // 8. Streaming AEAD Encryption
  // =========================================================
  log('--- 8. Streaming AEAD Encryption ---');
  final largeData = Uint8List.fromList(utf8.encode('Large Data Chunk ' * 100));

  final encryptedStream = await QuantumCrypto.streaming.streamEncrypt(
    algorithm: AeadAlgorithm.chaCha20Poly1305,
    key: symmetricKey,
    plaintext: largeData,
    chunkSize: 65536,
  );
  log('[STREAMING] Encrypted stream parts: ${encryptedStream.length}');

  final decryptedStream = await QuantumCrypto.streaming.streamDecrypt(
    key: symmetricKey,
    encryptedData: encryptedStream,
  );
  final streamMatch = _bytesEquals(largeData, decryptedStream);
  log('[STREAMING] Match: ${streamMatch ? "✅ SUCCESS" : "❌ FAILED"}\n');

  // =========================================================
  // 9. Key Derivation Function (HKDF + Hash Agility) [UPDATED in 0.0.2]
  // =========================================================
  log('--- 9. Key Derivation Function (HKDF-SHA256/384/512) ---');
  final derivedKey = await QuantumCrypto.kdf.derive(
    sharedSecret: kemEncapsulation.sharedSecret,
    info: Uint8List.fromList(utf8.encode('app_encryption_key')),
    outputLength: 32,
  );
  log('[KDF] Derived Key (default SHA-256) length: ${derivedKey.length} bytes');

  // Explicit digest selection (NEW in 0.0.2).
  final derivedKey512 = await QuantumCrypto.kdf.derive(
    sharedSecret: kemEncapsulation.sharedSecret,
    info: Uint8List.fromList(utf8.encode('app_encryption_key')),
    outputLength: 64,
    hash: HkdfHash.sha512,
  );
  log(
    '[KDF] Derived Key (SHA-512) length: ${derivedKey512.length} bytes',
  );

  // Derive multiple keys in one call.
  final multiKeys = await QuantumCrypto.kdf.deriveMulti(
    sharedSecret: kemEncapsulation.sharedSecret,
    infoStrings: const ['enc_key', 'mac_key'],
    keyLength: 32,
    hash: HkdfHash.sha384,
  );
  log('[KDF] deriveMulti (SHA-384) produced ${multiKeys.length} keys\n');

  // =========================================================
  // 10. Cryptographic Hashing (SHA-2 / SHA-3) [NEW in 0.0.2]
  // =========================================================
  log('--- 10. One-Shot Hashing ---');
  final hashInput = Uint8List.fromList(utf8.encode('hello'));
  final sha256Digest = await QuantumCrypto.hash.digest(
    HashAlgorithm.sha256,
    hashInput,
  );
  final sha3Digest = await QuantumCrypto.hash.digest(
    HashAlgorithm.sha3_512,
    hashInput,
  );
  log(
    '[HASH] SHA-256: ${sha256Digest.length} bytes | '
    'SHA3-512: ${sha3Digest.length} bytes',
  );
  log('[HASH] SHA-256("hello") first byte: ${sha256Digest[0]}\n');

  // =========================================================
  // 11. Deterministic Seed Generation
  // =========================================================
  log('--- 11. Deterministic Seed Generation ---');
  final masterSeed = await QuantumCrypto.seed.generateSeed();
  log('[SEED] Master Seed length: ${masterSeed.length} bytes');

  await QuantumCrypto.seed.deriveKey(
    seed: masterSeed,
    purpose: 'ml-kem-key',
    keyIndex: 0,
  );
  log('[SEED] Derived ML-KEM Key pair generated.');

  await QuantumCrypto.seed.deriveX25519Key(seed: masterSeed, keyIndex: 0);
  log('[SEED] Derived X25519 Key pair generated.');

  final derivedAeadKey = await QuantumCrypto.seed.deriveAeadKey(
    seed: masterSeed,
    keyIndex: 0,
  );
  log('[SEED] Derived AEAD Key length: ${derivedAeadKey.length} bytes\n');

  // =========================================================
  // 12. SLH-DSA Benchmark [NEW in 0.0.2]
  // =========================================================
  log('--- 12. SLH-DSA Benchmark (1 iteration, signing is ~100x ML-DSA) ---');
  final slhBench = await QuantumCrypto.benchmark.benchmarkSlhDsa(
    algorithmName: 'SLH-DSA-SHA2-128f',
    iterations: 1,
  );
  for (final r in slhBench) {
    log('[BENCH] ${r.algorithm} ${r.operation}: '
        '${r.avgUs} μs avg (${r.opsPerSec.toStringAsFixed(1)} ops/sec)');
  }
  log('');

  log('=============================================');
  log('    ✅ All examples completed successfully ✅    ');
  log('=============================================');
}

bool _bytesEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
