// ignore_for_file: public_member_api_docs
import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/enums/hybrid_kem_algorithm.dart';

/// Package produced by the Encrypt-then-Sign messaging mode.
/// Unlike [SecurePackage], this includes a separate [signature] field
/// that signs the encrypted payload (not the plaintext).
/// A standardized package for Encrypt-then-Sign secure messaging.
///
/// Contains the AEAD encrypted payload, ephemeral keys, and the digital signature
/// of the sender to ensure both confidentiality and authenticity.
final class EncryptThenSignPackage {
  final int version;
  final Uint8List mlKemCiphertext;

  /// The ephemeral X25519 public key.
  final Uint8List x25519EphemeralPk;

  /// The AEAD encrypted payload.
  final Uint8List encryptedPayload;

  /// The digital signature verifying the sender's authenticity.
  final Uint8List signature;
  final DsaAlgorithm dsaAlgorithm;
  final HybridKemAlgorithm kemAlgorithm;
  final AeadAlgorithm aeadAlgorithm;

  /// Creates a new [EncryptThenSignPackage].
  EncryptThenSignPackage({
    required this.version,
    required Uint8List mlKemCiphertext,
    required Uint8List x25519EphemeralPk,
    required Uint8List encryptedPayload,
    required Uint8List signature,
    required this.dsaAlgorithm,
    required this.kemAlgorithm,
    required this.aeadAlgorithm,
  })  : mlKemCiphertext =
            Uint8List.fromList(mlKemCiphertext).asUnmodifiableView(),
        x25519EphemeralPk =
            Uint8List.fromList(x25519EphemeralPk).asUnmodifiableView(),
        encryptedPayload =
            Uint8List.fromList(encryptedPayload).asUnmodifiableView(),
        signature = Uint8List.fromList(signature).asUnmodifiableView();
}
