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
  final initStopwatch = Stopwatch()..start();
  await QuantumCrypto.init();
  log(
    '[INFO] Initialization completed in ${initStopwatch.elapsedMilliseconds} ms.\n',
  );

  // =========================================================
  // 1. Pure ML-KEM (Key Encapsulation Mechanism)
  // =========================================================
  log('--- 1. Pure ML-KEM (Post-Quantum Key Exchange) ---');
  final kemAlgo =
      KemAlgorithm.mlKem1024; // Using highest security level for demonstration
  log('[KEM] Using Algorithm: ${kemAlgo.name}');

  final kemWatch = Stopwatch()..start();
  final kemKeyPair = await QuantumCrypto.kem.generateKeyPair(kemAlgo);
  log(
    '[KEM] KeyPair generated. Public Key: ${kemKeyPair.publicKey.length} bytes | Secret Key: ${kemKeyPair.secretKey.length} bytes',
  );

  final kemEncapsulation = await QuantumCrypto.kem.encapsulate(
    algorithm: kemAlgo,
    publicKey: kemKeyPair.publicKey,
  );
  log(
    '[KEM] Encapsulated. Ciphertext: ${kemEncapsulation.ciphertext.length} bytes | Shared Secret: ${kemEncapsulation.sharedSecret.length} bytes',
  );

  final kemDecapsulated = await QuantumCrypto.kem.decapsulate(
    algorithm: kemAlgo,
    ciphertext: kemEncapsulation.ciphertext,
    secretKey: kemKeyPair.secretKey,
  );
  final kemMatch = _bytesEquals(kemEncapsulation.sharedSecret, kemDecapsulated);
  log(
    '[KEM] Decapsulated Shared Secret length: ${kemDecapsulated.length} bytes',
  );
  log(
    '[KEM] Shared Secret Match: ${kemMatch ? "✅ SUCCESS" : "❌ FAILED"} (took ${kemWatch.elapsedMilliseconds} ms)\n',
  );

  // =========================================================
  // 2. Pure ML-DSA (Digital Signature Algorithm)
  // =========================================================
  log('--- 2. Pure ML-DSA (Post-Quantum Digital Signatures) ---');
  final dsaAlgo = DsaAlgorithm.mlDsa87; // Using highest security level
  log('[DSA] Using Algorithm: ${dsaAlgo.name}');

  final dsaWatch = Stopwatch()..start();
  final dsaKeyPair = await QuantumCrypto.dsa.generateKeyPair(dsaAlgo);
  log(
    '[DSA] KeyPair generated. Public Key: ${dsaKeyPair.publicKey.length} bytes | Secret Key: ${dsaKeyPair.secretKey.length} bytes',
  );

  final document = Uint8List.fromList(
    utf8.encode('Highly sensitive document requiring PQ signature.'),
  );
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
  log(
    '[DSA] Signature Verification: ${dsaValid ? "✅ VALID" : "❌ INVALID"} (took ${dsaWatch.elapsedMilliseconds} ms)\n',
  );

  // =========================================================
  // 3. Hybrid KEM (ML-KEM + X25519)
  // =========================================================
  log('--- 3. Hybrid KEM (ML-KEM-768 + X25519) ---');
  final hybridAlgo = HybridKemAlgorithm.mlKem768X25519;
  log('[HYBRID] Using Algorithm: ${hybridAlgo.name}');

  final hybridWatch = Stopwatch()..start();
  final hybridKeyPair = await QuantumCrypto.hybrid.generateKeyPair(hybridAlgo);
  log('[HYBRID] KeyPair generated.');
  log(
    '         - ML-KEM Public Key: ${hybridKeyPair.mlKemPublicKey.length} bytes',
  );
  log(
    '         - X25519 Public Key: ${hybridKeyPair.x25519PublicKey.length} bytes',
  );
  log(
    '         - ML-KEM Secret Key: ${hybridKeyPair.mlKemSecretKey.length} bytes',
  );
  log(
    '         - X25519 Secret Key: ${hybridKeyPair.x25519SecretKey.length} bytes',
  );

  final hybridEncapsulation = await QuantumCrypto.hybrid.encapsulate(
    algorithm: hybridAlgo,
    mlKemPublicKey: hybridKeyPair.mlKemPublicKey,
    x25519PublicKey: hybridKeyPair.x25519PublicKey,
  );
  log('[HYBRID] Encapsulated.');
  log(
    '         - ML-KEM Ciphertext: ${hybridEncapsulation.mlKemCiphertext.length} bytes',
  );
  log(
    '         - X25519 Ephemeral PK: ${hybridEncapsulation.x25519EphemeralPk.length} bytes',
  );
  log(
    '         - Derived Shared Secret: ${hybridEncapsulation.sharedSecret.length} bytes',
  );

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
    '[HYBRID] Shared Secret Match: ${hybridMatch ? "✅ SUCCESS" : "❌ FAILED"} (took ${hybridWatch.elapsedMilliseconds} ms)\n',
  );

  // =========================================================
  // 4. AEAD Symmetric Encryption
  // =========================================================
  log('--- 4. AEAD Encryption (ChaCha20-Poly1305) ---');
  final aeadAlgo = AeadAlgorithm.chaCha20Poly1305;
  log('[AEAD] Using Algorithm: ${aeadAlgo.name}');

  // We use the 32-byte shared secret from the Hybrid KEM step
  final symmetricKey = hybridEncapsulation.sharedSecret;
  final payload = Uint8List.fromList(
    utf8.encode('Top Secret Post-Quantum Data 🕵️‍♂️'),
  );
  log('[AEAD] Original payload size: ${payload.length} bytes');
  log('[AEAD] Symmetric key size: ${symmetricKey.length} bytes');

  final aeadWatch = Stopwatch()..start();
  final ciphertextWithNonce = await QuantumCrypto.aead.encrypt(
    algorithm: aeadAlgo,
    key: symmetricKey,
    plaintext: payload,
  );
  log(
    '[AEAD] Encrypted payload size: ${ciphertextWithNonce.length} bytes (Payload + 12-byte Nonce + 16-byte Poly1305 Tag)',
  );

  final decryptedPayload = await QuantumCrypto.aead.decrypt(
    algorithm: aeadAlgo,
    key: symmetricKey,
    ciphertextWithNonce: ciphertextWithNonce,
  );

  final aeadMatch = _bytesEquals(payload, decryptedPayload);
  log('[AEAD] Decrypted text: "${utf8.decode(decryptedPayload)}"');
  log(
    '[AEAD] Decryption Match: ${aeadMatch ? "✅ SUCCESS" : "❌ FAILED"} (took ${aeadWatch.elapsedMilliseconds} ms)\n',
  );

  // =========================================================
  // 5. Key Serialization & Utilities
  // =========================================================
  log('--- 5. Key Serialization Helpers ---');
  final hexKey = await QuantumCrypto.keys.bytesToHex(symmetricKey);
  log('[SERIALIZE] Symmetric Key (Hex)    [${hexKey.length} chars]: $hexKey');

  final b64Key = await QuantumCrypto.keys.bytesToBase64(symmetricKey);
  log('[SERIALIZE] Symmetric Key (Base64) [${b64Key.length} chars]: $b64Key\n');

  // =========================================================
  // 6. High-Level Secure Messaging API (Sign-then-Encrypt)
  // =========================================================
  log('--- 6. High-Level Secure Messaging API (Sign-then-Encrypt) ---');
  log(
    '[MESSAGING] Scenario: Rawda wants to send a secure, signed message to Mostafa.',
  );

  final messagingWatch = Stopwatch()..start();

  // Rawda Signs and Encrypts the message in one step (Using existing Rawda DSA & Mostafa Hybrid keys)
  final messageToMostafa = Uint8List.fromList(
    utf8.encode(
      'Hello Mostafa, this is Rawda. Quantum computers cannot read this! 🔒',
    ),
  );
  log('[MESSAGING] Plaintext size: ${messageToMostafa.length} bytes');

  final securePackage = await QuantumCrypto.messaging.signAndEncrypt(
    message: messageToMostafa,
    senderDsaSecretKey: dsaKeyPair.secretKey, // Rawda's signing key
    recipientMlKemPublicKey:
        hybridKeyPair.mlKemPublicKey, // Mostafa's KEM public key
    recipientX25519PublicKey:
        hybridKeyPair.x25519PublicKey, // Mostafa's X25519 public key
    dsaAlgorithm: dsaAlgo, // Use the same algorithm (ML-DSA-87) as the key pair
    kemAlgorithm: HybridKemAlgorithm.mlKem768X25519,
    aeadAlgorithm: AeadAlgorithm.aes256Gcm,
  );

  log('[MESSAGING] Generated Secure Package:');
  log(
    '            - ML-KEM Ciphertext: ${securePackage.mlKemCiphertext.length} bytes',
  );
  log(
    '            - X25519 Ephemeral PK: ${securePackage.x25519EphemeralPk.length} bytes',
  );
  log(
    '            - Encrypted Payload: ${securePackage.encryptedPayload.length} bytes',
  );
  log(
    '            - Algorithms: ${securePackage.dsaAlgorithm.name} | ${securePackage.kemAlgorithm.name} | ${securePackage.aeadAlgorithm.name}',
  );

  // Mostafa Decrypts and Verifies the signature in one step
  final verifiedDecryptedMessage = await QuantumCrypto.messaging
      .decryptAndVerify(
        package: securePackage,
        recipientMlKemSecretKey:
            hybridKeyPair.mlKemSecretKey, // Mostafa's KEM secret key
        recipientX25519SecretKey:
            hybridKeyPair.x25519SecretKey, // Mostafa's X25519 secret key
        senderDsaPublicKey: dsaKeyPair.publicKey, // Rawda's signing public key
      );

  final messagingMatch = _bytesEquals(
    messageToMostafa,
    verifiedDecryptedMessage,
  );
  log(
    '[MESSAGING] Mostafa verified and decrypted: "${utf8.decode(verifiedDecryptedMessage)}"',
  );
  log(
    '[MESSAGING] Sign-then-Encrypt Pipeline: ${messagingMatch ? "✅ SUCCESS" : "❌ FAILED"} (took ${messagingWatch.elapsedMilliseconds} ms)\n',
  );

  log('=============================================');
}

bool _bytesEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
