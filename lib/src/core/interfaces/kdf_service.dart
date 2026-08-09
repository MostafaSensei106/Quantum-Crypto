import 'dart:typed_data';

/// Service for HKDF-SHA256 key derivation.
abstract interface class KdfService {
  /// Derive key material from a shared secret using HKDF-SHA256.
  Future<Uint8List> derive({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required Uint8List info,
    required int outputLength,
  });

  /// Derive multiple keys from a shared secret in one call.
  Future<List<Uint8List>> deriveMulti({
    required Uint8List sharedSecret,
    Uint8List? salt,
    required List<String> infoStrings,
    required int keyLength,
  });
}
