// ignore_for_file: public_member_api_docs
import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/slh_dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/slh_dsa_service.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

import '../../rust/api/slh_dsa_api.dart' as rust_api;

final

    /// Internal implementation of `SlhDsaServiceImpl`.
    ///
    /// **Warning**: Do not use this class directly. Always interact with
    /// the cryptographic functions via the [QuantumCrypto] facade to ensure
    /// correct initialization and memory safety.
    ///
    /// Example:
    /// ```dart
    /// // Correct usage:
    /// final keyPair = await QuantumCrypto.slhDsa.generateKeyPair(
    ///   SlhDsaAlgorithm.slhDsaSha2_128f,
    /// );
    /// ```
    class SlhDsaServiceImpl implements SlhDsaService {
  /// Creates an internal instance of [SlhDsaServiceImpl].
  const SlhDsaServiceImpl();

  @override
  Future<PqcKeyPair> generateKeyPair(SlhDsaAlgorithm algorithm) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    final dto = await rust_api.generateSlhDsaKeypair(algorithm: rustAlgorithm);

    return PqcKeyPair(
      publicKey: Uint8List.fromList(dto.publicKey),
      secretKey: Uint8List.fromList(dto.secretKey),
    );
  }

  @override
  Future<Uint8List> sign({
    required SlhDsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List secretKey,
  }) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    final signatureBytes = await rust_api.slhDsaSign(
      algorithm: rustAlgorithm,
      message: message,
      secretKey: secretKey,
    );

    return Uint8List.fromList(signatureBytes);
  }

  @override
  Future<bool> verify({
    required SlhDsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  }) async {
    final rustAlgorithm = _mapToRustAlgorithm(algorithm);
    return await rust_api.slhDsaVerify(
      algorithm: rustAlgorithm,
      message: message,
      signature: signature,
      publicKey: publicKey,
    );
  }

  rust_api.TargetSlhDsaAlgorithm _mapToRustAlgorithm(
      SlhDsaAlgorithm algorithm) {
    return switch (algorithm) {
      SlhDsaAlgorithm.slhDsaSha2_128f =>
        rust_api.TargetSlhDsaAlgorithm.slhDsaSha2128F,
      SlhDsaAlgorithm.slhDsaSha2_192f =>
        rust_api.TargetSlhDsaAlgorithm.slhDsaSha2192F,
      SlhDsaAlgorithm.slhDsaSha2_256f =>
        rust_api.TargetSlhDsaAlgorithm.slhDsaSha2256F,
    };
  }
}
