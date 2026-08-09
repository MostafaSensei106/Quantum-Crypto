// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';
import 'package:quantum_crypto/src/core/models/secure_package.dart';
import 'package:quantum_crypto/src/core/models/encrypt_then_sign_package.dart';

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

  Future<EncryptThenSignPackage> encryptAndSign({
    required Uint8List message,
    required Uint8List senderDsaSecretKey,
    required Uint8List recipientMlKemPublicKey,
    required Uint8List recipientX25519PublicKey,
    DsaAlgorithm dsaAlgorithm,
    HybridKemAlgorithm kemAlgorithm,
    AeadAlgorithm aeadAlgorithm,
  });

  Future<Uint8List> verifyAndDecrypt({
    required EncryptThenSignPackage package,
    required Uint8List recipientMlKemSecretKey,
    required Uint8List recipientX25519SecretKey,
    required Uint8List senderDsaPublicKey,
  });
}
