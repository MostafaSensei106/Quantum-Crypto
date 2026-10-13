import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/slh_dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

/// Service for SLH-DSA (FIPS 205) stateless hash-based signatures.
///
/// Unlike ML-DSA, SLH-DSA signatures are **detached**: [sign] returns the
/// raw signature bytes only, and [verify] expects exactly those bytes.
abstract interface class SlhDsaService {
  /// Generates a new SLH-DSA Key Pair for the specified [algorithm].
  ///
  /// Example:
  /// ```dart
  /// final keyPair = await QuantumCrypto.slhDsa.generateKeyPair(
  ///   SlhDsaAlgorithm.slhDsaSha2_128f,
  /// );
  /// ```
  Future<PqcKeyPair> generateKeyPair(SlhDsaAlgorithm algorithm);

  /// Signs the [message] using the provided [secretKey].
  ///
  /// Returns the detached signature as bytes (message NOT included).
  Future<Uint8List> sign({
    required SlhDsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List secretKey,
  });

  /// Verifies that the detached [signature] is valid for the [message]
  /// and [publicKey].
  ///
  /// Returns `true` if the signature is authentic and the message is untampered.
  Future<bool> verify({
    required SlhDsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  });
}
