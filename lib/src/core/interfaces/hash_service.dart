import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/hash_algorithm.dart';

/// Service for one-shot cryptographic hashing (SHA-2 / SHA-3).
abstract interface class HashService {
  /// Compute the digest of [data] with [algorithm].
  ///
  /// Example:
  /// ```dart
  /// final digest = await QuantumCrypto.hash.digest(
  ///   HashAlgorithm.sha256,
  ///   Uint8List.fromList(utf8.encode('hello')),
  /// );
  /// ```
  Future<Uint8List> digest(HashAlgorithm algorithm, Uint8List data);
}
