// ignore_for_file: public_member_api_docs
enum AeadAlgorithm {
  aes256Gcm,
  chaCha20Poly1305,
}

extension AeadAlgorithmExt on AeadAlgorithm {
  String get name => switch (this) {
        AeadAlgorithm.aes256Gcm => 'AES-256-GCM',
        AeadAlgorithm.chaCha20Poly1305 => 'ChaCha20-Poly1305',
      };

  int get keyLength => 32;
  int get nonceLength => 12;
}
