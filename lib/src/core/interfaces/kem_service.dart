import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/kem_algorithm.dart';
import 'package:quantum_crypto/src/core/models/encapsulation_result.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

/// Service for Key Encapsulation Mechanism (KEM) operations.
///
/// Provides methods for generating keys, encapsulating secrets, and decapsulating them
/// using algorithms like ML-KEM.
abstract interface class KemService {
  /// Generates a new PQC Key Pair for the specified [algorithm].
  ///
  /// Example:
  /// ```dart
  /// final keyPair = await QuantumCrypto.kem.generateKeyPair(KemAlgorithm.mlKem768);
  /// ```
  Future<PqcKeyPair> generateKeyPair(KemAlgorithm algorithm);

  /// Encapsulates a shared secret for the given [publicKey].
  ///
  /// Returns a [PqcEncapsulationResult] containing the ciphertext (to be sent)
  /// and the shared secret (to be kept).
  Future<PqcEncapsulationResult> encapsulate({
    required KemAlgorithm algorithm,
    required Uint8List publicKey,
  });

  /// Decapsulates the [ciphertext] using the [secretKey] to recover the shared secret.
  ///
  /// **WARNING**: This will throw an exception or return invalid data if the ciphertext
  /// was modified or the wrong secret key is used.
  Future<Uint8List> decapsulate({
    required KemAlgorithm algorithm,
    required Uint8List ciphertext,
    required Uint8List secretKey,
  });
}
