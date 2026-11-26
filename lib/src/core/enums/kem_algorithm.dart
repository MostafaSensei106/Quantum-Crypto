// ignore_for_file: public_member_api_docs
enum KemAlgorithm {
  mlKem512,
  mlKem768,
  mlKem1024,
}

extension KemAlgorithmExt on KemAlgorithm {
  String get name => switch (this) {
        KemAlgorithm.mlKem512 => 'ML-KEM-512 (NIST Security Category 1)',
        KemAlgorithm.mlKem768 => 'ML-KEM-768 (NIST Security Category 3)',
        KemAlgorithm.mlKem1024 => 'ML-KEM-1024 (NIST Security Category 5)',
      };
}
