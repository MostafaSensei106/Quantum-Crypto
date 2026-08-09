import 'dart:typed_data';

/// The result of a Hybrid Key Encapsulation Mechanism (KEM) operation.
///
/// Contains the ciphertexts and the derived shared secret.
final class HybridEncapsulationResult {
  /// The ciphertext from the ML-KEM encapsulation.
  final Uint8List mlKemCiphertext;

  /// The ephemeral public key from the X25519 exchange.
  final Uint8List x25519EphemeralPk;

  /// The combined, derived shared secret.
  final Uint8List sharedSecret;

  /// Creates a new [HybridEncapsulationResult].
  const HybridEncapsulationResult({
    required this.mlKemCiphertext,
    required this.x25519EphemeralPk,
    required this.sharedSecret,
  });
}
