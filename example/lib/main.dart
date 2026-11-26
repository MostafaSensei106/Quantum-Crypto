import 'dart:convert';
import 'dart:developer';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';

import 'security_checks.dart';

Future<void> main() => runExample();

/// Runs the public API tour; logging can be captured by integration tests.
Future<void> runExample({void Function(String) writeLog = log}) async {
  writeLog('=============================================');
  writeLog('    🚀 Quantum Crypto Example 🚀    ');
  writeLog('=============================================\n');

  // Initialize the FFI bindings
  writeLog('[INFO] Initializing QuantumCrypto Rust bindings...');
  await QuantumCrypto.init();
  writeLog('[INFO] Initialization completed.\n');

  // Native signing: the private key never crosses into Dart.
  final nativeKey = await QuantumCrypto.nativeKeys.generateDsa(
    algorithm: DsaAlgorithm.mlDsa65,
    exportable: false,
  );
  try {
    final message = Uint8List.fromList(utf8.encode('Native key example'));
    final signature = await nativeKey.sign(message);
    final publicKey = await nativeKey.publicKey();
    final valid = await QuantumCrypto.dsa.verify(
      algorithm: DsaAlgorithm.mlDsa65,
      message: message,
      signature: signature,
      publicKey: publicKey,
    );
    if (!valid) throw StateError('Native signature verification failed');
    writeLog('[NATIVE] Signature verified: $valid');
  } finally {
    await nativeKey.dispose();
  }

  // The remaining sections demonstrate the explicit byte-key compatibility APIs.
  // Their secrets reside in Dart and have no secure-erasure guarantee.
  // =========================================================
  // 1. Pure ML-KEM (Key Encapsulation Mechanism)
  // =========================================================
  writeLog('--- 1. Pure ML-KEM (Post-Quantum Key Exchange) ---');
  final kemAlgo = KemAlgorithm.mlKem768; // NIST Security Category 3
  writeLog('[KEM] Using Algorithm: ${kemAlgo.name}');

  final kemKeyPair = await QuantumCrypto.kem.generateKeyPair(kemAlgo);
  writeLog(
    '[KEM] KeyPair generated. Public Key: ${kemKeyPair.publicKey.length} bytes | Secret Key: ${kemKeyPair.secretKey.length} bytes',
  );

  final kemEncapsulation = await QuantumCrypto.kem.encapsulate(
    algorithm: kemAlgo,
    publicKey: kemKeyPair.publicKey,
  );
  writeLog(
    '[KEM] Encapsulated. Ciphertext: ${kemEncapsulation.ciphertext.length} bytes',
  );

  final kemDecapsulated = await QuantumCrypto.kem.decapsulate(
    algorithm: kemAlgo,
    ciphertext: kemEncapsulation.ciphertext,
    secretKey: kemKeyPair.secretKey,
  );
  final kemMatch = _bytesEquals(kemEncapsulation.sharedSecret, kemDecapsulated);
  if (!kemMatch) throw StateError('kemMatch verification failed');
  writeLog(
    '[KEM] Shared Secret Match: ${kemMatch ? "✅ SUCCESS" : "❌ FAILED"}\n',
  );

  // =========================================================
  // 2. Pure ML-DSA (Digital Signature Algorithm)
  // =========================================================
  writeLog('--- 2. Pure ML-DSA (Post-Quantum Digital Signatures) ---');
  final dsaAlgo = DsaAlgorithm.mlDsa65;
  writeLog('[DSA] Using Algorithm: ${dsaAlgo.name}');

  final dsaKeyPair = await QuantumCrypto.dsa.generateKeyPair(dsaAlgo);
  writeLog(
    '[DSA] KeyPair generated. Public Key: ${dsaKeyPair.publicKey.length} bytes | Secret Key: ${dsaKeyPair.secretKey.length} bytes',
  );

  final document = Uint8List.fromList(utf8.encode('Critical Contract'));
  final signature = await QuantumCrypto.dsa.sign(
    algorithm: dsaAlgo,
    message: document,
    secretKey: dsaKeyPair.secretKey,
  );
  writeLog('[DSA] Signed document.');
  writeLog('[DSA] Attached signed message: ${signature.length} bytes');

  final dsaValid = await QuantumCrypto.dsa.verify(
    algorithm: dsaAlgo,
    message: document,
    signature: signature,
    publicKey: dsaKeyPair.publicKey,
  );
  if (!dsaValid) throw StateError('dsaValid verification failed');
  writeLog(
    '[DSA] Signature Verification: ${dsaValid ? "✅ VALID" : "❌ INVALID"}\n',
  );

  // =========================================================
  // 3. SPHINCS+ (historical SLH-DSA API names) [NEW in 0.0.2]
  // =========================================================
  writeLog('--- 3. SPHINCS+ (final FIPS 205 equivalence unverified) ---');
  final slhAlgo = SlhDsaAlgorithm.slhDsaSha2_128f; // NIST Security Category 1
  writeLog('[SLH-DSA] Using Algorithm: ${slhAlgo.name}');
  writeLog('[SLH-DSA] Note: detached signatures (message NOT embedded).');

  final slhKeyPair = await QuantumCrypto.slhDsa.generateKeyPair(slhAlgo);
  writeLog(
    '[SLH-DSA] KeyPair generated. Public Key: ${slhKeyPair.publicKey.length} bytes | Secret Key: ${slhKeyPair.secretKey.length} bytes',
  );

  final slhSignature = await QuantumCrypto.slhDsa.sign(
    algorithm: slhAlgo,
    message: document,
    secretKey: slhKeyPair.secretKey,
  );
  writeLog(
    '[SLH-DSA] Signed document. Detached signature: ${slhSignature.length} bytes',
  );

  final slhValid = await QuantumCrypto.slhDsa.verify(
    algorithm: slhAlgo,
    message: document,
    signature: slhSignature,
    publicKey: slhKeyPair.publicKey,
  );
  if (!slhValid) throw StateError('slhValid verification failed');
  writeLog(
    '[SLH-DSA] Signature Verification: ${slhValid ? "✅ VALID" : "❌ INVALID"}\n',
  );

  // =========================================================
  // 4. Hybrid KEM (ML-KEM + X25519)
  // =========================================================
  writeLog('--- 4. Hybrid KEM (ML-KEM-768 + X25519) ---');
  final hybridAlgo = HybridKemAlgorithm.mlKem768X25519;
  writeLog('[HYBRID] Using Algorithm: ${hybridAlgo.name}');

  final hybridKeyPair = await QuantumCrypto.hybrid.generateKeyPair(hybridAlgo);
  writeLog('[HYBRID] KeyPair generated.');

  final hybridEncapsulation = await QuantumCrypto.hybrid.encapsulate(
    algorithm: hybridAlgo,
    mlKemPublicKey: hybridKeyPair.mlKemPublicKey,
    x25519PublicKey: hybridKeyPair.x25519PublicKey,
  );
  writeLog('[HYBRID] Encapsulated.');

  final hybridDecapsulated = await QuantumCrypto.hybrid.decapsulate(
    algorithm: hybridAlgo,
    mlKemCiphertext: hybridEncapsulation.mlKemCiphertext,
    x25519EphemeralPk: hybridEncapsulation.x25519EphemeralPk,
    mlKemPublicKey: hybridKeyPair.mlKemPublicKey,
    x25519PublicKey: hybridKeyPair.x25519PublicKey,
    mlKemSecretKey: hybridKeyPair.mlKemSecretKey,
    x25519SecretKey: hybridKeyPair.x25519SecretKey,
  );

  final hybridMatch = _bytesEquals(
    hybridEncapsulation.sharedSecret,
    hybridDecapsulated,
  );
  if (!hybridMatch) throw StateError('hybridMatch verification failed');
  writeLog(
    '[HYBRID] Shared Secret Match: ${hybridMatch ? "✅ SUCCESS" : "❌ FAILED"}\n',
  );

  // =========================================================
  // 5. AEAD Symmetric Encryption (+ XChaCha20-Poly1305) [NEW in 0.0.2]
  // =========================================================
  writeLog('--- 5. AEAD Encryption (AES-256-GCM + XChaCha20-Poly1305) ---');
  final aeadAlgo = AeadAlgorithm.aes256Gcm;
  writeLog('[AEAD] Using Algorithm: ${aeadAlgo.name}');

  final symmetricKey = await QuantumCrypto.kdf.derive(
    sharedSecret: hybridEncapsulation.sharedSecret,
    info: Uint8List.fromList(utf8.encode('example/aes256gcm/v2')),
    outputLength: 32,
  );
  final payload = Uint8List.fromList(utf8.encode('Secret Data'));

  final ciphertextWithNonce = await QuantumCrypto.aead.encrypt(
    algorithm: aeadAlgo,
    key: symmetricKey,
    plaintext: payload,
  );
  writeLog(
    '[AEAD] Encrypted payload size: ${ciphertextWithNonce.length} bytes',
  );

  final decryptedPayload = await QuantumCrypto.aead.decrypt(
    algorithm: aeadAlgo,
    key: symmetricKey,
    ciphertextWithNonce: ciphertextWithNonce,
  );

  final aeadMatch = _bytesEquals(payload, decryptedPayload);
  writeLog('[AEAD] Decrypted text: "${utf8.decode(decryptedPayload)}"');
  if (!aeadMatch) throw StateError('aeadMatch verification failed');
  writeLog('[AEAD] Decryption Match: ${aeadMatch ? "✅ SUCCESS" : "❌ FAILED"}');

  // XChaCha20-Poly1305: 24-byte random nonce with a larger collision margin.
  // Wire format: 24-byte nonce || ciphertext+tag.
  final xKey = await QuantumCrypto.kdf.derive(
    sharedSecret: hybridEncapsulation.sharedSecret,
    info: Uint8List.fromList(utf8.encode('example/xchacha20poly1305/v2')),
    outputLength: 32,
  );
  final xPayload = Uint8List.fromList(utf8.encode('Extended-nonce secret'));
  final xCiphertext = await QuantumCrypto.aead.encrypt(
    algorithm: AeadAlgorithm.xChaCha20Poly1305,
    key: xKey,
    plaintext: xPayload,
  );
  writeLog(
    '[AEAD:XChaCha20] Encrypted size: ${xCiphertext.length} bytes '
    '(24 nonce + ${xPayload.length} plaintext + 16 tag)',
  );

  final xDecrypted = await QuantumCrypto.aead.decrypt(
    algorithm: AeadAlgorithm.xChaCha20Poly1305,
    key: xKey,
    ciphertextWithNonce: xCiphertext,
  );
  final xMatch = _bytesEquals(xPayload, xDecrypted);
  if (!xMatch) throw StateError('xMatch verification failed');
  writeLog(
    '[AEAD:XChaCha20] Decryption Match: ${xMatch ? "✅ SUCCESS" : "❌ FAILED"}\n',
  );

  // =========================================================
  // 6. Key Serialization & Utilities
  // =========================================================
  writeLog('--- 6. Key Serialization Helpers ---');
  final hexKey = await QuantumCrypto.keys.bytesToHex(kemKeyPair.publicKey);
  writeLog('[SERIALIZE] Public Key (Hex)    [${hexKey.length} chars]: ...');

  final b64Key = await QuantumCrypto.keys.bytesToBase64(kemKeyPair.publicKey);
  writeLog('[SERIALIZE] Public Key (Base64) [${b64Key.length} chars]: ...\n');

  // =========================================================
  // 7. Secure Messaging (Sign-then-Encrypt)
  // =========================================================
  writeLog('--- 7. Secure Messaging ---');
  final messageToMostafa = Uint8List.fromList(utf8.encode('Top Secret'));

  // We use signAndEncrypt as defined in the library
  final securePackage = await QuantumCrypto.messaging.signAndEncrypt(
    message: messageToMostafa,
    senderDsaPublicKey: dsaKeyPair.publicKey,
    senderDsaSecretKey: dsaKeyPair.secretKey,
    recipientMlKemPublicKey: hybridKeyPair.mlKemPublicKey,
    recipientX25519PublicKey: hybridKeyPair.x25519PublicKey,
    dsaAlgorithm: dsaAlgo,
    kemAlgorithm: HybridKemAlgorithm.mlKem768X25519,
    aeadAlgorithm: AeadAlgorithm.aes256Gcm,
  );
  writeLog('[MESSAGING] Generated Secure Package.');

  final verifiedDecryptedMessage = await QuantumCrypto.messaging
      .decryptAndVerify(
        package: securePackage,
        recipientMlKemPublicKey: hybridKeyPair.mlKemPublicKey,
        recipientX25519PublicKey: hybridKeyPair.x25519PublicKey,
        recipientMlKemSecretKey: hybridKeyPair.mlKemSecretKey,
        recipientX25519SecretKey: hybridKeyPair.x25519SecretKey,
        senderDsaPublicKey: dsaKeyPair.publicKey,
      );

  final messagingMatch = _bytesEquals(
    messageToMostafa,
    verifiedDecryptedMessage,
  );
  writeLog(
    '[MESSAGING] Message verified and decrypted: "${utf8.decode(verifiedDecryptedMessage)}"',
  );
  if (!messagingMatch) throw StateError('messagingMatch verification failed');
  writeLog(
    '[MESSAGING] Pipeline: ${messagingMatch ? "✅ SUCCESS" : "❌ FAILED"}\n',
  );

  // =========================================================
  // 8. Streaming AEAD Encryption
  // =========================================================
  writeLog('--- 8. Streaming AEAD Encryption ---');
  final largeData = Uint8List.fromList(utf8.encode('Large Data Chunk ' * 100));

  final encryptedStream = await QuantumCrypto.streaming.streamEncrypt(
    algorithm: AeadAlgorithm.chaCha20Poly1305,
    key: symmetricKey,
    plaintext: largeData,
    chunkSize: 65536,
  );
  writeLog('[STREAMING] Encoded stream: ${encryptedStream.length} bytes');

  final decryptedStream = await QuantumCrypto.streaming.streamDecrypt(
    key: symmetricKey,
    encryptedData: encryptedStream,
  );
  final streamMatch = _bytesEquals(largeData, decryptedStream);
  if (!streamMatch) throw StateError('streamMatch verification failed');
  writeLog('[STREAMING] Match: ${streamMatch ? "✅ SUCCESS" : "❌ FAILED"}\n');

  // =========================================================
  // 9. Key Derivation Function (HKDF + Hash Agility) [UPDATED in 0.0.2]
  // =========================================================
  writeLog('--- 9. Key Derivation Function (HKDF-SHA256/384/512) ---');
  final derivedKey = await QuantumCrypto.kdf.derive(
    sharedSecret: kemEncapsulation.sharedSecret,
    info: Uint8List.fromList(utf8.encode('app_encryption_key')),
    outputLength: 32,
  );
  writeLog(
    '[KDF] Derived Key (default SHA-256) length: ${derivedKey.length} bytes',
  );

  // Explicit digest selection (NEW in 0.0.2).
  final derivedKey512 = await QuantumCrypto.kdf.derive(
    sharedSecret: kemEncapsulation.sharedSecret,
    info: Uint8List.fromList(utf8.encode('app_encryption_key')),
    outputLength: 64,
    hash: HkdfHash.sha512,
  );
  writeLog('[KDF] Derived Key (SHA-512) length: ${derivedKey512.length} bytes');

  // Derive multiple keys in one call.
  final multiKeys = await QuantumCrypto.kdf.deriveMulti(
    sharedSecret: kemEncapsulation.sharedSecret,
    infoStrings: const ['enc_key', 'mac_key'],
    keyLength: 32,
    hash: HkdfHash.sha384,
  );
  writeLog('[KDF] deriveMulti (SHA-384) produced ${multiKeys.length} keys\n');

  // =========================================================
  // 10. Cryptographic Hashing (SHA-2 / SHA-3) [NEW in 0.0.2]
  // =========================================================
  writeLog('--- 10. One-Shot Hashing ---');
  final hashInput = Uint8List.fromList(utf8.encode('hello'));
  final sha256Digest = await QuantumCrypto.hash.digest(
    HashAlgorithm.sha256,
    hashInput,
  );
  final sha3Digest = await QuantumCrypto.hash.digest(
    HashAlgorithm.sha3_512,
    hashInput,
  );
  writeLog(
    '[HASH] SHA-256: ${sha256Digest.length} bytes | '
    'SHA3-512: ${sha3Digest.length} bytes',
  );
  writeLog('[HASH] SHA-256("hello") first byte: ${sha256Digest[0]}\n');

  // =========================================================
  // 11. Random Seed Generation & Deterministic Derivation
  // =========================================================
  writeLog('--- 11. Random Seed Generation & Deterministic Derivation ---');
  final masterSeed = await QuantumCrypto.seed.generateSeed();
  writeLog('[SEED] Master Seed length: ${masterSeed.length} bytes');

  final derivedMaterial = await QuantumCrypto.seed.deriveKey(
    seed: masterSeed,
    purpose: 'example/key-material/v2',
    keyIndex: 0,
  );
  writeLog(
    '[SEED] Derived key material: ${derivedMaterial.length} bytes (not an ML-KEM key pair).',
  );

  final derivedX25519 = await QuantumCrypto.seed.deriveX25519Key(
    seed: masterSeed,
    keyIndex: 0,
  );
  writeLog(
    '[SEED] Derived X25519 private-key bytes: ${derivedX25519.length} bytes (public key not generated here).',
  );

  final derivedAeadKey = await QuantumCrypto.seed.deriveAeadKey(
    seed: masterSeed,
    keyIndex: 0,
  );
  writeLog('[SEED] Derived AEAD Key length: ${derivedAeadKey.length} bytes\n');

  // =========================================================
  // 12. SLH-DSA Benchmark [NEW in 0.0.2]
  // =========================================================
  writeLog('--- 12. SLH-DSA Benchmark (SPHINCS+ backend, 1 iteration) ---');
  final slhBench = await QuantumCrypto.benchmark.benchmarkSlhDsa(
    algorithmName: 'SLH-DSA-SHA2-128f',
    iterations: 1,
  );
  for (final r in slhBench) {
    writeLog(
      '[BENCH] ${r.algorithm} ${r.operation}: '
      '${r.avgUs} μs avg (${r.opsPerSec.toStringAsFixed(1)} ops/sec)',
    );
  }
  writeLog('');

  writeLog('--- 13. Security Hardening Checks (0.0.3) ---');
  final passedChecks = await runSecurityChecks(writeLog: writeLog);
  writeLog('[CHECKS] $passedChecks/10 demonstrations passed.');
  writeLog(
    '[SCOPE] These logs confirm only the displayed operations and rejection cases.',
  );
  writeLog(
    '[SCOPE] They do not establish full standards conformance, complete memory erasure, or closure of every prior finding.',
  );

  writeLog('=============================================');
  writeLog('    ✅ Displayed operations and checks completed ✅    ');
  writeLog('=============================================');
}

bool _bytesEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
