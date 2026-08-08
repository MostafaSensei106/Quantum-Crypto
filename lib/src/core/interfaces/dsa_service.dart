import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/dsa_algorithm.dart';
import 'package:quantum_crypto/src/core/models/key_pair.dart';

abstract interface class DsaService {
  Future<PqcKeyPair> generateKeyPair(DsaAlgorithm algorithm);

  Future<Uint8List> sign({
    required DsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List secretKey,
  });

  Future<bool> verify({
    required DsaAlgorithm algorithm,
    required Uint8List message,
    required Uint8List signature,
    required Uint8List publicKey,
  });
}
