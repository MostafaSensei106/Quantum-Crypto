// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
import 'package:quantum_crypto/src/core/interfaces/seed_service.dart';
import '../../rust/api/seed_keygen_api.dart' as rust_api;

/// Internal implementation of `SeedServiceImpl`.
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
final class SeedServiceImpl implements SeedService {
  /// Creates an internal instance of [SeedServiceImpl].
  const SeedServiceImpl();

  @override
  Future<Uint8List> generateSeed() async {
    final result = await rust_api.generateMasterSeed();
    return Uint8List.fromList(result);
  }

  @override
  Future<Uint8List> deriveKey({
    required Uint8List seed,
    required String purpose,
    int keyIndex = 0,
    int outputLength = 32,
  }) async {
    final result = await rust_api.deriveKeyFromSeed(
      seed: seed,
      purpose: purpose,
      keyIndex: keyIndex,
      outputLen: outputLength,
    );
    return Uint8List.fromList(result);
  }

  @override
  Future<Uint8List> deriveX25519Key({
    required Uint8List seed,
    int keyIndex = 0,
  }) async {
    final result = await rust_api.deriveX25519FromSeed(
      seed: seed,
      keyIndex: keyIndex,
    );
    return Uint8List.fromList(result);
  }

  @override
  Future<Uint8List> deriveAeadKey({
    required Uint8List seed,
    int keyIndex = 0,
  }) async {
    final result = await rust_api.deriveAeadKeyFromSeed(
      seed: seed,
      keyIndex: keyIndex,
    );
    return Uint8List.fromList(result);
  }
}
