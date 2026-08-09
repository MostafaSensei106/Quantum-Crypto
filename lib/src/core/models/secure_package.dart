import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';

final class SecurePackage {
  final Uint8List mlKemCiphertext;
  final Uint8List x25519EphemeralPk;
  final Uint8List encryptedPayload;
  final DsaAlgorithm dsaAlgorithm;
  final HybridKemAlgorithm kemAlgorithm;
  final AeadAlgorithm aeadAlgorithm;

  const SecurePackage({
    required this.mlKemCiphertext,
    required this.x25519EphemeralPk,
    required this.encryptedPayload,
    required this.dsaAlgorithm,
    required this.kemAlgorithm,
    required this.aeadAlgorithm,
  });
}
