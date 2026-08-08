import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/kem_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/kem_service.dart';
import 'package:quantum_crypto/src/core/models/encapsulation_result.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

import '../../rust/api/kem_api.dart' as rust_api;

final class MlKemService implements KemService {
  const MlKemService();

  @override
  Future<PqcKeyPair> generateKeyPair(KemAlgorithm algorithm) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    final dto = await rust_api.generateKemKeypair(algorithm: rustAlgorithm);

    return PqcKeyPair(
      publicKey: Uint8List.fromList(dto.publicKey),
      secretKey: Uint8List.fromList(dto.secretKey),
    );
  }

  @override
  Future<PqcEncapsulationResult> encapsulate({
    required KemAlgorithm algorithm,
    required Uint8List publicKey,
  }) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    final dto = await rust_api.kemEncapsulate(
      algorithm: rustAlgorithm,
      publicKey: publicKey,
    );

    return PqcEncapsulationResult(
      ciphertext: Uint8List.fromList(dto.ciphertext),
      sharedSecret: Uint8List.fromList(dto.sharedSecret),
    );
  }

  @override
  Future<Uint8List> decapsulate({
    required KemAlgorithm algorithm,
    required Uint8List ciphertext,
    required Uint8List secretKey,
  }) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    final sharedSecretBytes = await rust_api.kemDecapsulate(
      algorithm: rustAlgorithm,
      ciphertext: ciphertext,
      secretKey: secretKey,
    );

    return Uint8List.fromList(sharedSecretBytes);
  }

  rust_api.TargetKemAlgorithm _mapToRustAlgorithm(KemAlgorithm algorithm) {
    return switch (algorithm) {
      KemAlgorithm.mlKem512 => rust_api.TargetKemAlgorithm.mlKem512,
      KemAlgorithm.mlKem768 => rust_api.TargetKemAlgorithm.mlKem768,
      KemAlgorithm.mlKem1024 => rust_api.TargetKemAlgorithm.mlKem1024,
    };
  }
}
