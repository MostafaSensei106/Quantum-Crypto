enum KemAlgorithm {
  mlKem512,
  mlKem768,
  mlKem1024,
}

extension KemAlgorithmExt on KemAlgorithm {
  String get name => switch (this) {
        KemAlgorithm.mlKem512 => 'ML-KEM-512 (AES-128 Equivalent)',
        KemAlgorithm.mlKem768 => 'ML-KEM-768 (AES-192 Equivalent)',
        KemAlgorithm.mlKem1024 => 'ML-KEM-1024 (AES-256 Equivalent)',
      };
}
