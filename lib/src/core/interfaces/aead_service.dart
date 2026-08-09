import 'dart:typed_data';
import 'package:quantum_crypto/src/core/enums/aead_algorithm.dart';

abstract interface class AeadService {
  Future<Uint8List> encrypt({
    required AeadAlgorithm algorithm,
    required Uint8List key,
    required Uint8List plaintext,
  });

  Future<Uint8List> decrypt({
    required AeadAlgorithm algorithm,
    required Uint8List key,
    required Uint8List ciphertextWithNonce,
  });
}
