import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/kem_algorithm.dart';
import 'package:quantum_crypto/src/core/models/encapsulation_result.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

abstract interface class KemService {
  Future<PqcKeyPair> generateKeyPair(KemAlgorithm algorithm);

  Future<PqcEncapsulationResult> encapsulate({
    required KemAlgorithm algorithm,
    required Uint8List publicKey,
  });

  Future<Uint8List> decapsulate({
    required KemAlgorithm algorithm,
    required Uint8List ciphertext,
    required Uint8List secretKey,
  });
}
