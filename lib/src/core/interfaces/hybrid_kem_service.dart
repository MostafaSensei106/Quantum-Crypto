import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';
import 'package:quantum_crypto/src/core/models/hybrid_key_pair.dart';
import 'package:quantum_crypto/src/core/models/hybrid_encapsulation_result.dart';

abstract interface class HybridKemService {
  Future<HybridKeyPair> generateKeyPair(HybridKemAlgorithm algorithm);

  Future<HybridEncapsulationResult> encapsulate({
    required HybridKemAlgorithm algorithm,
    required Uint8List mlKemPublicKey,
    required Uint8List x25519PublicKey,
  });

  Future<Uint8List> decapsulate({
    required HybridKemAlgorithm algorithm,
    required Uint8List mlKemCiphertext,
    required Uint8List x25519EphemeralPk,
    required Uint8List mlKemSecretKey,
    required Uint8List x25519SecretKey,
  });
}
