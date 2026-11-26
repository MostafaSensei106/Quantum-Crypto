// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';

/// A standardized package for secure, encrypted data transmission.
///
/// Contains the encrypted payload along with the necessary ephemeral keys
/// and ciphertexts required for the recipient to decrypt the data.
final class SecurePackage {
  final int version;
  final Uint8List mlKemCiphertext;

  /// The ephemeral X25519 public key used for the classical key exchange.
  final Uint8List x25519EphemeralPk;

  /// The actual AEAD encrypted data payload.
  final Uint8List encryptedPayload;
  final DsaAlgorithm dsaAlgorithm;
  final HybridKemAlgorithm kemAlgorithm;
  final AeadAlgorithm aeadAlgorithm;

  /// Creates a new [SecurePackage].
  SecurePackage({
    required this.version,
    required Uint8List mlKemCiphertext,
    required Uint8List x25519EphemeralPk,
    required Uint8List encryptedPayload,
    required this.dsaAlgorithm,
    required this.kemAlgorithm,
    required this.aeadAlgorithm,
  })  : mlKemCiphertext =
            Uint8List.fromList(mlKemCiphertext).asUnmodifiableView(),
        x25519EphemeralPk =
            Uint8List.fromList(x25519EphemeralPk).asUnmodifiableView(),
        encryptedPayload =
            Uint8List.fromList(encryptedPayload).asUnmodifiableView();
}
