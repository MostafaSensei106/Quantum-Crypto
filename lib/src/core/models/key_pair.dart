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
  PqcKeyPair({
    required Uint8List publicKey,
    required Uint8List secretKey,
  })  : publicKey = Uint8List.fromList(publicKey).asUnmodifiableView(),
        secretKey = Uint8List.fromList(secretKey).asUnmodifiableView();
}
