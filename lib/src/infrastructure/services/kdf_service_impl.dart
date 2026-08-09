// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
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

  @override
  Future<Uint8List> derive({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required Uint8List info,
    required int outputLength,
  }) async {
    final result = await rust_api.hkdfDerive(
      sharedSecret: sharedSecret,
      salt: salt ?? Uint8List(0),
      info: info,
      outputLen: outputLength,
    );
    return Uint8List.fromList(result);
  }

  @override
  Future<List<Uint8List>> deriveMulti({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required List<String> infoStrings,
    required int keyLength,
  }) async {
    final result = await rust_api.hkdfDeriveMulti(
      sharedSecret: sharedSecret,
      salt: salt ?? Uint8List(0),
      infoStrings: infoStrings,
      keyLength: keyLength,
    );
    return result.map((e) => Uint8List.fromList(e)).toList();
  }
}
