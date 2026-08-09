// ignore_for_file: public_member_api_docs
enum HybridKemAlgorithm {
  mlKem512X25519,
  mlKem768X25519,
  mlKem1024X25519,
}

extension HybridKemAlgorithmExt on HybridKemAlgorithm {
  String get name => switch (this) {
        HybridKemAlgorithm.mlKem512X25519 => 'Hybrid ML-KEM-512 + X25519',
        HybridKemAlgorithm.mlKem768X25519 => 'Hybrid ML-KEM-768 + X25519',
        HybridKemAlgorithm.mlKem1024X25519 => 'Hybrid ML-KEM-1024 + X25519',
      };

  /// The NIST security level
  int get securityLevel => switch (this) {
        HybridKemAlgorithm.mlKem512X25519 => 1,
        HybridKemAlgorithm.mlKem768X25519 => 3,
        HybridKemAlgorithm.mlKem1024X25519 => 5,
      };
}
