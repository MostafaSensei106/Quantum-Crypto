import 'dart:typed_data';

/// Service for deterministic key derivation from a master seed.
abstract interface class SeedService {
  /// Generate a cryptographically secure random 32-byte master seed.
  Future<Uint8List> generateSeed();

  /// Derive key material from a master seed.
  Future<Uint8List> deriveKey({
    required Uint8List seed,
    required String purpose,
    int keyIndex = 0,
    int outputLength = 32,
  });

  /// Derive a 32-byte X25519 private key from seed.
  Future<Uint8List> deriveX25519Key({
    required Uint8List seed,
    int keyIndex = 0,
  });

  /// Derive a 32-byte AEAD symmetric key from seed.
  Future<Uint8List> deriveAeadKey({
    required Uint8List seed,
    int keyIndex = 0,
  });
}
