import 'dart:convert';
import 'dart:developer';
import 'dart:typed_data';

import 'package:quantum_crypto/quantum_crypto.dart';

/// Runs the ten 0.0.3 demonstrations after QuantumCrypto.init().
/// Throws on unexpected acceptance, unexpected errors or a failed round trip.
/// These observations are not a security audit or conformance certification.
Future<int> runSecurityChecks({void Function(String) writeLog = log}) async {
  var passed = 0;
  final ownedKeys = <NativeKey>[];
  Future<NativeKey> own(Future<NativeKey> pending) async {
    final key = await pending;
    ownedKeys.add(key);
    return key;
  }

  Future<void> check(String name, Future<void> Function() action) async {
    await action();
    passed++;
    writeLog('[PASS] $name');
  }

  final message = Uint8List.fromList(utf8.encode('Native security demo'));
  try {
    final signingKey = await own(
      QuantumCrypto.nativeKeys.generateDsa(
        algorithm: DsaAlgorithm.mlDsa65,
        exportable: false,
      ),
    );
    await check('Native Key Export Rejection', () async {
      await _expectRejection(signingKey.exportSecret, 'Key is not exportable');
    });
    await check('Native Key Use After Dispose Rejection', () async {
      await signingKey.dispose();
      await _expectRejection(
        () => signingKey.sign(message),
        'Native key disposed',
      );
    });

    final kemKey = await own(
      QuantumCrypto.nativeKeys.generateKem(algorithm: KemAlgorithm.mlKem768),
    );
    await check('Native Shared Secret Handles', () async {
      final enc = await QuantumCrypto.nativeKeys.encapsulateKem(
        algorithm: KemAlgorithm.mlKem768,
        publicKey: await kemKey.publicKey(),
      );
      ownedKeys.add(enc.sharedSecret);
      final recovered = await own(
        kemKey.decapsulate(ciphertext: enc.ciphertext),
      );
      await _expectRejection(
        enc.sharedSecret.exportSecret,
        'Key is not exportable',
      );
      await _expectRejection(recovered.exportSecret, 'Key is not exportable');
      final context = Uint8List.fromList(utf8.encode('example/native-kem/v2'));
      final senderKey = await own(
        enc.sharedSecret.deriveAead(
          algorithm: AeadAlgorithm.xChaCha20Poly1305,
          context: context,
        ),
      );
      final recipientKey = await own(
        recovered.deriveAead(
          algorithm: AeadAlgorithm.xChaCha20Poly1305,
          context: context,
        ),
      );
      final encrypted = await senderKey.encrypt(
        message,
        associatedData: context,
      );
      _requireEqual(
        await recipientKey.decrypt(encrypted, associatedData: context),
        message,
        'Native shared-secret derivation',
      );
      writeLog(
        '[NATIVE] Both shared secrets stayed in native handles; derived AEAD keys interoperated.',
      );
    });

    final hybrid = await own(
      QuantumCrypto.nativeKeys.generateHybrid(
        algorithm: HybridKemAlgorithm.mlKem768X25519,
      ),
    );
    final mlKemPublicKey = await hybrid.publicKey();
    final x25519PublicKey = await hybrid.secondaryPublicKey();
    await check('Hybrid KEM v2 Roundtrip', () async {
      final enc = await QuantumCrypto.nativeKeys.encapsulateHybrid(
        algorithm: HybridKemAlgorithm.mlKem768X25519,
        mlKemPublicKey: mlKemPublicKey,
        x25519PublicKey: x25519PublicKey,
      );
      ownedKeys.add(enc.sharedSecret);
      if (enc.ciphertext.isEmpty || enc.ciphertext.first != 2) {
        throw StateError('Expected a version 2 hybrid ciphertext');
      }
      final recovered = await own(
        hybrid.decapsulate(
          ciphertext: enc.ciphertext,
          x25519EphemeralPk: enc.x25519EphemeralPk,
        ),
      );
      final context = Uint8List.fromList(
        utf8.encode('example/native-hybrid/v2'),
      );
      final senderKey = await own(
        enc.sharedSecret.deriveAead(
          algorithm: AeadAlgorithm.aes256Gcm,
          context: context,
        ),
      );
      final recipientKey = await own(
        recovered.deriveAead(
          algorithm: AeadAlgorithm.aes256Gcm,
          context: context,
        ),
      );
      _requireEqual(
        await recipientKey.decrypt(await senderKey.encrypt(message)),
        message,
        'Hybrid v2 key confirmation',
      );
    });
    await check('X25519 Invalid Key Rejection', () async {
      // A correctly-sized all-zero key tests contribution, not just length.
      await _expectRejection(
        () => QuantumCrypto.hybrid.encapsulate(
          algorithm: HybridKemAlgorithm.mlKem768X25519,
          mlKemPublicKey: mlKemPublicKey,
          x25519PublicKey: Uint8List(32),
        ),
        'Non-contributory X25519 public key',
      );
      await _expectRejection(
        () => QuantumCrypto.hybrid.encapsulate(
          algorithm: HybridKemAlgorithm.mlKem768X25519,
          mlKemPublicKey: mlKemPublicKey,
          x25519PublicKey: Uint8List(1),
        ),
        'Invalid X25519 public key length',
      );
    });

    final aead = await own(
      QuantumCrypto.nativeKeys.generateAead(algorithm: AeadAlgorithm.aes256Gcm),
    );
    final data = Uint8List.fromList(List.generate(257, (i) => i % 256));
    final stream = await aead.streamEncrypt(data, chunkSize: 64);
    _requireEqual(
      await aead.streamDecrypt(stream),
      data,
      'Streaming v2 baseline',
    );
    await check('Streaming v2 Tamper Detection', () async {
      final modified = Uint8List.fromList(stream);
      modified[modified.length - 1] ^= 1;
      await _expectRejection(
        () => aead.streamDecrypt(modified),
        'Stream authentication failed',
      );
    });
    await check('Streaming v2 Truncation Detection', () async {
      await _expectRejection(
        () => aead.streamDecrypt(
          Uint8List.sublistView(stream, 0, stream.length - 1),
        ),
        'Truncated stream or trailing data',
      );
    });
    await check('AEAD Incorrect AAD Rejection', () async {
      final aad = Uint8List.fromList(utf8.encode('document/123'));
      final encrypted = await aead.encrypt(message, associatedData: aad);
      _requireEqual(
        await aead.decrypt(encrypted, associatedData: aad),
        message,
        'AEAD baseline',
      );
      await _expectRejection(
        () => aead.decrypt(
          encrypted,
          associatedData: Uint8List.fromList(utf8.encode('document/456')),
        ),
        'Decryption failed',
      );
    });

    final sender = await own(
      QuantumCrypto.nativeKeys.generateDsa(algorithm: DsaAlgorithm.mlDsa65),
    );
    final senderPublicKey = await sender.publicKey();
    final context = Uint8List.fromList(utf8.encode('example/message/v2'));
    final wrongContext = Uint8List.fromList(
      utf8.encode('example/other-context/v2'),
    );
    final package = await sender.signAndEncrypt(
      message: message,
      recipientAlgorithm: HybridKemAlgorithm.mlKem768X25519,
      recipientMlKemPublicKey: mlKemPublicKey,
      recipientX25519PublicKey: x25519PublicKey,
      associatedData: context,
    );
    await check('Secure Messaging v2 Context Tampering', () async {
      _requireEqual(
        await hybrid.decryptAndVerify(
          package: package,
          senderDsaPublicKey: senderPublicKey,
          associatedData: context,
        ),
        message,
        'Sign-then-Encrypt baseline',
      );
      await _expectRejection(
        () => hybrid.decryptAndVerify(
          package: package,
          senderDsaPublicKey: senderPublicKey,
          associatedData: wrongContext,
        ),
        'Decryption failed',
      );
      final signed = await sender.encryptAndSign(
        message: message,
        recipientAlgorithm: HybridKemAlgorithm.mlKem768X25519,
        recipientMlKemPublicKey: mlKemPublicKey,
        recipientX25519PublicKey: x25519PublicKey,
        associatedData: context,
      );
      _requireEqual(
        await hybrid.verifyAndDecrypt(
          package: signed,
          senderDsaPublicKey: senderPublicKey,
          associatedData: context,
        ),
        message,
        'Encrypt-then-Sign baseline',
      );
      await _expectRejection(
        () => hybrid.verifyAndDecrypt(
          package: signed,
          senderDsaPublicKey: senderPublicKey,
          associatedData: wrongContext,
        ),
        'Signature verification failed',
      );
    });
    await check('Legacy v1 Format Rejection', () async {
      // Actual v1 header for an empty AES stream: version, chunk size, count, algorithm.
      final legacyStream = Uint8List.fromList([1, 0, 0, 0, 64, 0, 0, 0, 0, 0]);
      await _expectRejection(
        () => aead.streamDecrypt(legacyStream),
        'v2 required',
      );
      // Exercise the message version gate independently of payload authentication.
      final legacyPackage = SecurePackage(
        version: 1,
        mlKemCiphertext: package.mlKemCiphertext,
        x25519EphemeralPk: package.x25519EphemeralPk,
        encryptedPayload: package.encryptedPayload,
        dsaAlgorithm: package.dsaAlgorithm,
        kemAlgorithm: package.kemAlgorithm,
        aeadAlgorithm: package.aeadAlgorithm,
      );
      await _expectRejection(
        () => hybrid.decryptAndVerify(
          package: legacyPackage,
          senderDsaPublicKey: senderPublicKey,
          associatedData: context,
        ),
        'Unsupported message version (v2 required)',
      );
    });
    return passed;
  } finally {
    // Future.wait waits for all disposals, even if one fails. Close is idempotent.
    await Future.wait(ownedKeys.reversed.map((key) => key.dispose()));
  }
}

Future<void> _expectRejection(
  Future<Object?> Function() operation,
  String reason,
) async {
  try {
    await operation();
  } catch (error) {
    if (!error.toString().contains(reason)) {
      throw StateError('Expected rejection "$reason", received: $error');
    }
    return;
  }
  throw StateError(
    'Operation unexpectedly accepted; expected rejection "$reason"',
  );
}

void _requireEqual(List<int> actual, List<int> expected, String operation) {
  if (actual.length != expected.length) {
    throw StateError('$operation length mismatch');
  }
  for (var i = 0; i < actual.length; i++) {
    if (actual[i] != expected[i]) throw StateError('$operation mismatch');
  }
}
