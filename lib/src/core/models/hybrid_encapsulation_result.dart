import 'dart:typed_data';

final class HybridEncapsulationResult {
  final Uint8List mlKemCiphertext;
  final Uint8List x25519EphemeralPk;
  final Uint8List sharedSecret;

  const HybridEncapsulationResult({
    required this.mlKemCiphertext,
    required this.x25519EphemeralPk,
    required this.sharedSecret,
  });
}
