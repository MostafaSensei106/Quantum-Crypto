import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/interfaces/aead_service.dart';
import '../../rust/api/aead_api.dart' as rust_api;

final class AeadServiceImpl implements AeadService {
  const AeadServiceImpl();

  rust_api.TargetAeadAlgorithm _mapToRustAlgorithm(AeadAlgorithm algorithm) {
    return switch (algorithm) {
      AeadAlgorithm.aes256Gcm => rust_api.TargetAeadAlgorithm.aes256Gcm,
      AeadAlgorithm.chaCha20Poly1305 =>
        rust_api.TargetAeadAlgorithm.chaCha20Poly1305,
    };
  }

  @override
  Future<Uint8List> encrypt({
    required AeadAlgorithm algorithm,
    required Uint8List key,
    required Uint8List plaintext,
  }) async {
    final result = await rust_api.aeadEncrypt(
      algorithm: _mapToRustAlgorithm(algorithm),
      key: key,
      plaintext: plaintext,
    );
    return Uint8List.fromList(result);
  }

  @override
  Future<Uint8List> decrypt({
    required AeadAlgorithm algorithm,
    required Uint8List key,
    required Uint8List ciphertextWithNonce,
  }) async {
    final result = await rust_api.aeadDecrypt(
      algorithm: _mapToRustAlgorithm(algorithm),
      key: key,
      ciphertextWithNonce: ciphertextWithNonce,
    );
    return Uint8List.fromList(result);
  }
}
