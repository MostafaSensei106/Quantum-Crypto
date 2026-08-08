import 'dart:typed_data';

final class PqcKeyPair {
  final Uint8List publicKey;
  final Uint8List secretKey;

  const PqcKeyPair({
    required this.publicKey,
    required this.secretKey,
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PqcKeyPair &&
          runtimeType == other.runtimeType &&
          _bytesEqual(publicKey, other.publicKey) &&
          _bytesEqual(secretKey, other.secretKey);

  @override
  int get hashCode => Object.hash(
        Object.hashAll(publicKey),
        Object.hashAll(secretKey),
      );

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}
