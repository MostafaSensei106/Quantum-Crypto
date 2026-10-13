// ignore_for_file: public_member_api_docs
enum HashAlgorithm {
  sha256,
  sha384,
  sha512,
  sha3_256,
  sha3_512,
}

extension HashAlgorithmExt on HashAlgorithm {
  String get name => switch (this) {
        HashAlgorithm.sha256 => 'SHA-256',
        HashAlgorithm.sha384 => 'SHA-384',
        HashAlgorithm.sha512 => 'SHA-512',
        HashAlgorithm.sha3_256 => 'SHA3-256',
        HashAlgorithm.sha3_512 => 'SHA3-512',
      };

  int get digestLength => switch (this) {
        HashAlgorithm.sha256 => 32,
        HashAlgorithm.sha384 => 48,
        HashAlgorithm.sha512 => 64,
        HashAlgorithm.sha3_256 => 32,
        HashAlgorithm.sha3_512 => 64,
      };
}
