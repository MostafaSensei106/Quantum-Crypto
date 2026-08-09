import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

/// Service for Digital Signature Algorithm (DSA) operations.
///
/// Provides methods for generating keys, signing messages, and verifying signatures
/// using algorithms like ML-DSA.
abstract interface class DsaService {
  /// Generates a new PQC Key Pair for the specified [algorithm].
  ///
  /// Example:
  /// ```dart
  /// final keyPair = await QuantumCrypto.dsa.generateKeyPair(DsaAlgorithm.mlDsa65);
  /// ```
  Future<PqcKeyPair> generateKeyPair(DsaAlgorithm algorithm);

  /// Signs the [message] using the provided [secretKey].
  ///
  /// Returns the cryptographic signature as bytes.
  Future<Uint8List> sign({
    required DsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List secretKey,
  });

  /// Verifies that the [signature] is valid for the [message] and [publicKey].
  ///
  /// Returns `true` if the signature is authentic and the message is untampered.
  Future<bool> verify({
    required DsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  });
}
