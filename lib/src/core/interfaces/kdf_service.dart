import 'dart:typed_data';

import 'package:quantum_crypto/src/core/enums/hkdf_hash.dart';

/// Service for HKDF key derivation.
abstract interface class KdfService {
  /// Derive key material from a shared secret using HKDF.
  Future<Uint8List> derive({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required Uint8List info,
    required int outputLength,
    HkdfHash hash = HkdfHash.sha256,
  });

  /// Derive multiple keys from a shared secret in one call.
  Future<List<Uint8List>> deriveMulti({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required List<String> infoStrings,
    required int keyLength,
    HkdfHash hash = HkdfHash.sha256,
  });
}
