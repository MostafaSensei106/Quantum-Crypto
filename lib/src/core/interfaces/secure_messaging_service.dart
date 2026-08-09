import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';
import 'package:quantum_crypto/src/core/models/secure_package.dart';

abstract interface class SecureMessagingService {
  Future<SecurePackage> signAndEncrypt({
    required Uint8List message,
    required Uint8List senderDsaSecretKey,
    required Uint8List recipientMlKemPublicKey,
    required Uint8List recipientX25519PublicKey,
    DsaAlgorithm dsaAlgorithm,
    HybridKemAlgorithm kemAlgorithm,
    AeadAlgorithm aeadAlgorithm,
  });

  Future<Uint8List> decryptAndVerify({
    required SecurePackage package,
    required Uint8List recipientMlKemSecretKey,
    required Uint8List recipientX25519SecretKey,
    required Uint8List senderDsaPublicKey,
  });
}
