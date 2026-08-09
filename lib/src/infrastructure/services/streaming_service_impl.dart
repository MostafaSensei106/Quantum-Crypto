// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/streaming_service.dart';
import '../../rust/api/streaming_api.dart' as rust_api;
import '../../rust/api/aead_api.dart' as aead_rust_api;

final

    /// Internal implementation of `StreamingServiceImpl`.
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
    class StreamingServiceImpl implements StreamingService {
  /// Creates an internal instance of [StreamingServiceImpl].
  const StreamingServiceImpl();

  @override
  Future<Uint8List> streamEncrypt({
    required AeadAlgorithm algorithm,
    required Uint8List key,
    required Uint8List plaintext,
    int? chunkSize,
  }) async {
    final result = await rust_api.streamAeadEncrypt(
      algorithm: _mapAeadAlgorithm(algorithm),
      key: key,
      plaintext: plaintext,
      chunkSize: chunkSize,
    );
    return Uint8List.fromList(result);
  }

  @override
  Future<Uint8List> streamDecrypt({
    required Uint8List key,
    required Uint8List encryptedData,
  }) async {
    final result = await rust_api.streamAeadDecrypt(
      key: key,
      encryptedData: encryptedData,
    );
    return Uint8List.fromList(result);
  }

  aead_rust_api.TargetAeadAlgorithm _mapAeadAlgorithm(AeadAlgorithm algo) {
    return switch (algo) {
      AeadAlgorithm.aes256Gcm => aead_rust_api.TargetAeadAlgorithm.aes256Gcm,
      AeadAlgorithm.chaCha20Poly1305 =>
        aead_rust_api.TargetAeadAlgorithm.chaCha20Poly1305,
    };
  }
}
