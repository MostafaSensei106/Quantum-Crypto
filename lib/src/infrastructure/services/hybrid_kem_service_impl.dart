import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/hybrid_kem_service.dart';
import 'package:quantum_crypto/src/core/models/hybrid_encapsulation_result.dart';
import 'package:quantum_crypto/src/core/models/hybrid_key_pair.dart';
import '../../rust/api/hybrid_kem_api.dart' as rust_api;

final class HybridKemServiceImpl implements HybridKemService {
  const HybridKemServiceImpl();

  rust_api.TargetHybridKemAlgorithm _mapToRustAlgorithm(
      HybridKemAlgorithm algorithm) {
    return switch (algorithm) {
      HybridKemAlgorithm.mlKem512X25519 =>
        rust_api.TargetHybridKemAlgorithm.mlKem512X25519,
      HybridKemAlgorithm.mlKem768X25519 =>
        rust_api.TargetHybridKemAlgorithm.mlKem768X25519,
      HybridKemAlgorithm.mlKem1024X25519 =>
        rust_api.TargetHybridKemAlgorithm.mlKem1024X25519,
    };
  }

  @override
  Future<HybridKeyPair> generateKeyPair(HybridKemAlgorithm algorithm) async {
    final targetAlgo = _mapToRustAlgorithm(algorithm);
    final result =
        await rust_api.generateHybridKemKeypair(algorithm: targetAlgo);

    return HybridKeyPair(
      mlKemPublicKey: Uint8List.fromList(result.mlkemPublicKey),
      x25519PublicKey: Uint8List.fromList(result.x25519PublicKey),
      mlKemSecretKey: Uint8List.fromList(result.mlkemSecretKey),
      x25519SecretKey: Uint8List.fromList(result.x25519SecretKey),
    );
  }

  @override
  Future<HybridEncapsulationResult> encapsulate({
    required HybridKemAlgorithm algorithm,
    required Uint8List mlKemPublicKey,
    required Uint8List x25519PublicKey,
  }) async {
    final targetAlgo = _mapToRustAlgorithm(algorithm);
    final result = await rust_api.hybridKemEncapsulate(
      algorithm: targetAlgo,
      mlkemPublicKey: mlKemPublicKey,
      x25519PublicKey: x25519PublicKey,
    );

    return HybridEncapsulationResult(
      mlKemCiphertext: Uint8List.fromList(result.mlkemCiphertext),
      x25519EphemeralPk: Uint8List.fromList(result.x25519EphemeralPk),
      sharedSecret: Uint8List.fromList(result.sharedSecret),
    );
  }

  @override
  Future<Uint8List> decapsulate({
    required HybridKemAlgorithm algorithm,
    required Uint8List mlKemCiphertext,
    required Uint8List x25519EphemeralPk,
    required Uint8List mlKemSecretKey,
    required Uint8List x25519SecretKey,
  }) async {
    final targetAlgo = _mapToRustAlgorithm(algorithm);
    final result = await rust_api.hybridKemDecapsulate(
      algorithm: targetAlgo,
      mlkemCiphertext: mlKemCiphertext,
      x25519EphemeralPk: x25519EphemeralPk,
      mlkemSecretKey: mlKemSecretKey,
      x25519SecretKey: x25519SecretKey,
    );

    return Uint8List.fromList(result);
  }
}
