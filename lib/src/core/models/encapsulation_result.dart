import 'dart:typed_data';

final class PqcEncapsulationResult {
  final Uint8List ciphertext;
  final Uint8List sharedSecret;

  const PqcEncapsulationResult({
    required this.ciphertext,
    required this.sharedSecret,
  });
}
