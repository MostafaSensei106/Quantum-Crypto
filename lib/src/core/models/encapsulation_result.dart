// ignore_for_file: public_member_api_docs
import 'dart:typed_data';

final class PqcEncapsulationResult {
  final Uint8List ciphertext;
  final Uint8List sharedSecret;

  PqcEncapsulationResult({
    required Uint8List ciphertext,
    required Uint8List sharedSecret,
  })  : ciphertext = Uint8List.fromList(ciphertext).asUnmodifiableView(),
        sharedSecret = Uint8List.fromList(sharedSecret).asUnmodifiableView();
}
