// ignore_for_file: public_member_api_docs
enum SlhDsaAlgorithm {
  slhDsaSha2_128f,
  slhDsaSha2_192f,
  slhDsaSha2_256f,
}

extension SlhDsaAlgorithmExtension on SlhDsaAlgorithm {
  String get name => switch (this) {
        SlhDsaAlgorithm.slhDsaSha2_128f =>
          'SPHINCS+-SHA2-128f (NIST Security Category 1)',
        SlhDsaAlgorithm.slhDsaSha2_192f =>
          'SPHINCS+-SHA2-192f (NIST Security Category 3)',
        SlhDsaAlgorithm.slhDsaSha2_256f =>
          'SPHINCS+-SHA2-256f (NIST Security Category 5)',
      };
}
