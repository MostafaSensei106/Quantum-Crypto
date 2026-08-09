import 'dart:typed_data';

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (identical(a, b)) return true;
  if (a.length != b.length) return false;
  for (int i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

final class HybridKeyPair {
  final Uint8List mlKemPublicKey;
  final Uint8List x25519PublicKey;
  final Uint8List mlKemSecretKey;
  final Uint8List x25519SecretKey;

  const HybridKeyPair({
    required this.mlKemPublicKey,
    required this.x25519PublicKey,
    required this.mlKemSecretKey,
    required this.x25519SecretKey,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is HybridKeyPair &&
          _bytesEqual(mlKemPublicKey, other.mlKemPublicKey) &&
          _bytesEqual(x25519PublicKey, other.x25519PublicKey) &&
          _bytesEqual(mlKemSecretKey, other.mlKemSecretKey) &&
          _bytesEqual(x25519SecretKey, other.x25519SecretKey);

  @override
  int get hashCode => Object.hash(
        mlKemPublicKey,
        x25519PublicKey,
        mlKemSecretKey,
        x25519SecretKey,
      );
}
