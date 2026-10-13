// ignore_for_file: public_member_api_docs
/// Digest used inside HKDF-Extract/Expand.
enum HkdfHash {
  sha256,
  sha384,
  sha512,
}

extension HkdfHashExt on HkdfHash {
  String get name => switch (this) {
        HkdfHash.sha256 => 'HKDF-SHA-256',
        HkdfHash.sha384 => 'HKDF-SHA-384',
        HkdfHash.sha512 => 'HKDF-SHA-512',
      };
}
