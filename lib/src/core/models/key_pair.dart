import 'dart:typed_data';

/// A standardized Key Pair for Post-Quantum Cryptography (PQC).
///
/// Contains the raw bytes for both the public and secret keys.
/// Used universally across ML-KEM and ML-DSA algorithms.
final class PqcKeyPair {
  /// The public key bytes, used for encapsulation or signature verification.
  final Uint8List publicKey;

  /// The private/secret key bytes, used for decapsulation or signing.
  ///
  /// **WARNING**: Never expose or transmit this key. It must remain secure.
  final Uint8List secretKey;

  /// Creates a new [PqcKeyPair] from the given [publicKey] and [secretKey].
  const PqcKeyPair({
    required this.publicKey,
    required this.secretKey,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PqcKeyPair &&
          runtimeType == other.runtimeType &&
          _bytesEqual(publicKey, other.publicKey) &&
          _bytesEqual(secretKey, other.secretKey);

  @override
  int get hashCode => Object.hash(
        Object.hashAll(publicKey),
        Object.hashAll(secretKey),
      );

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
