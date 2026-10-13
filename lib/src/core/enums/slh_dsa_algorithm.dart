// ignore_for_file: public_member_api_docs
enum SlhDsaAlgorithm {
  slhDsaSha2_128f,
  slhDsaSha2_192f,
  slhDsaSha2_256f,
}

extension SlhDsaAlgorithmExtension on SlhDsaAlgorithm {
  String get name => switch (this) {
        SlhDsaAlgorithm.slhDsaSha2_128f =>
          'SLH-DSA-SHA2-128f (NIST Security Level 1)',
        SlhDsaAlgorithm.slhDsaSha2_192f =>
          'SLH-DSA-SHA2-192f (NIST Security Level 3)',
        SlhDsaAlgorithm.slhDsaSha2_256f =>
          'SLH-DSA-SHA2-256f (NIST Security Level 5)',
      };
}
