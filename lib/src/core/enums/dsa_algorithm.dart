// ignore_for_file: public_member_api_docs
enum DsaAlgorithm {
  mlDsa44,
  mlDsa65,
  mlDsa87,
}

extension DsaAlgorithmExtension on DsaAlgorithm {
  String get name => switch (this) {
        DsaAlgorithm.mlDsa44 => 'ML-DSA-44 (NIST Security Level 2)',
        DsaAlgorithm.mlDsa65 => 'ML-DSA-65 (NIST Security Level 3)',
        DsaAlgorithm.mlDsa87 => 'ML-DSA-87 (NIST Security Level 5)',
      };
}
