import 'package:quantum_crypto/src/core/models/benchmark_result.dart';

/// Service for running cryptographic benchmarks.
abstract interface class BenchmarkService {
  /// Run the full benchmark suite.
  Future<PqcBenchmarkSuiteResult> runFullSuite({
    int kemIterations = 10,
    int dsaIterations = 10,
    int aeadIterations = 100,
  });

  /// Benchmark a specific KEM algorithm.
  Future<List<PqcBenchmarkResult>> benchmarkKem({
    required String algorithmName,
    int iterations = 10,
  });

  /// Benchmark a specific DSA algorithm.
  Future<List<PqcBenchmarkResult>> benchmarkDsa({
    required String algorithmName,
    int iterations = 10,
  });

  /// Benchmark a specific SLH-DSA parameter set.
  ///
  /// Sign iterations are clamped inside the native suite (SLH-DSA signing
  /// is ~100× slower than ML-DSA by design); prefer small [iterations].
  Future<List<PqcBenchmarkResult>> benchmarkSlhDsa({
    required String algorithmName,
    int iterations = 5,
  });
}
