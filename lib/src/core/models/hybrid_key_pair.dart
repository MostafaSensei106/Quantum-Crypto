import 'dart:typed_data';

/// A Hybrid Key Pair combining classical (X25519) and PQC (ML-KEM) keys.
///
/// Experimental hybrid composition. No forward-secrecy guarantee.
final class HybridKeyPair {
  /// The ML-KEM public key bytes.
  final Uint8List mlKemPublicKey;

  /// The X25519 classical public key bytes.
  final Uint8List x25519PublicKey;

  /// The ML-KEM secret key bytes. Keep this secure!
  final Uint8List mlKemSecretKey;

  /// The X25519 classical secret key bytes. Keep this secure!
  final Uint8List x25519SecretKey;

  /// Creates a new [HybridKeyPair] containing both classical and PQC keys.
  HybridKeyPair({
    required Uint8List mlKemPublicKey,
    required Uint8List x25519PublicKey,
    required Uint8List mlKemSecretKey,
    required Uint8List x25519SecretKey,
  })  : mlKemPublicKey =
            Uint8List.fromList(mlKemPublicKey).asUnmodifiableView(),
        x25519PublicKey =
            Uint8List.fromList(x25519PublicKey).asUnmodifiableView(),
        mlKemSecretKey =
            Uint8List.fromList(mlKemSecretKey).asUnmodifiableView(),
        x25519SecretKey =
            Uint8List.fromList(x25519SecretKey).asUnmodifiableView();
}
