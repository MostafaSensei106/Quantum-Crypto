// ignore_for_file: public_member_api_docs
import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/hash_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/hash_service.dart';

import '../../rust/api/hash_api.dart' as rust_api;

final

    /// Internal implementation of `HashServiceImpl`.
    ///
    /// **Warning**: Do not use this class directly. Always interact with
    /// the cryptographic functions via the [QuantumCrypto] facade to ensure
    /// correct initialization and memory safety.
    ///
    /// Example:
    /// ```dart
    /// // Correct usage:
    /// final digest = await QuantumCrypto.hash.digest(HashAlgorithm.sha256, data);
    /// ```
    class HashServiceImpl implements HashService {
  /// Creates an internal instance of [HashServiceImpl].
  const HashServiceImpl();

  @override
  Future<Uint8List> digest(HashAlgorithm algorithm, Uint8List data) async {
    final result = await rust_api.hashData(
      algorithm: _mapToRustAlgorithm(algorithm),
      data: data,
    );
    return Uint8List.fromList(result);
  }

  rust_api.TargetHashAlgorithm _mapToRustAlgorithm(HashAlgorithm algorithm) {
    return switch (algorithm) {
      HashAlgorithm.sha256 => rust_api.TargetHashAlgorithm.sha256,
      HashAlgorithm.sha384 => rust_api.TargetHashAlgorithm.sha384,
      HashAlgorithm.sha512 => rust_api.TargetHashAlgorithm.sha512,
      HashAlgorithm.sha3_256 => rust_api.TargetHashAlgorithm.sha3256,
      HashAlgorithm.sha3_512 => rust_api.TargetHashAlgorithm.sha3512,
    };
  }
}
