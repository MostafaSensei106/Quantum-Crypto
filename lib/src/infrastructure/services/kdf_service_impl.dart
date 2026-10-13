// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/hkdf_hash.dart';
import 'package:quantum_crypto/src/core/interfaces/kdf_service.dart';
import '../../rust/api/kdf_api.dart' as rust_api;

final

    /// Internal implementation of `KdfServiceImpl`.
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
    class KdfServiceImpl implements KdfService {
  /// Creates an internal instance of [KdfServiceImpl].
  const KdfServiceImpl();

  rust_api.TargetHkdfHash _mapHash(HkdfHash hash) {
    return switch (hash) {
      HkdfHash.sha256 => rust_api.TargetHkdfHash.sha256,
      HkdfHash.sha384 => rust_api.TargetHkdfHash.sha384,
      HkdfHash.sha512 => rust_api.TargetHkdfHash.sha512,
    };
  }

  @override
  Future<Uint8List> derive({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required Uint8List info,
    required int outputLength,
    HkdfHash hash = HkdfHash.sha256,
  }) async {
    final result = await rust_api.hkdfDeriveWithHash(
      sharedSecret: sharedSecret,
      salt: salt ?? Uint8List(0),
      info: info,
      outputLen: outputLength,
      hash: _mapHash(hash),
    );
    return Uint8List.fromList(result);
  }

  @override
  Future<List<Uint8List>> deriveMulti({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required List<String> infoStrings,
    required int keyLength,
    HkdfHash hash = HkdfHash.sha256,
  }) async {
    final result = await rust_api.hkdfDeriveMultiWithHash(
      sharedSecret: sharedSecret,
      salt: salt ?? Uint8List(0),
      infoStrings: infoStrings,
      keyLength: keyLength,
      hash: _mapHash(hash),
    );
    return result.map((e) => Uint8List.fromList(e)).toList();
  }
}
