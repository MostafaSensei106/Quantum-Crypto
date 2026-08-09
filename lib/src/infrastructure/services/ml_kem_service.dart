// ignore_for_file: public_member_api_docs
import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/kem_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/kem_service.dart';
import 'package:quantum_crypto/src/core/models/encapsulation_result.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

import '../../rust/api/kem_api.dart' as rust_api;

final

    /// Internal implementation of `MlKemService`.
    ///
    /// **Warning**: Do not use this class directly. Always interact with
    /// the cryptographic functions via the [QuantumCrypto] facade to ensure
    /// correct initialization and memory safety.
    ///
    /// Example:
    /// ```dart
    /// // Correct usage:
    /// final result = await QuantumCrypto.kem.generateKeyPair(KemAlgorithm.mlKem768);
    /// ```
    class MlKemService implements KemService {
  /// Creates an internal instance of [MlKemService].
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
