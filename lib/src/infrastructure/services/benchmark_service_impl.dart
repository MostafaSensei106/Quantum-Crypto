// ignore_for_file: public_member_api_docs
import 'package:quantum_crypto/src/core/interfaces/benchmark_service.dart';
import 'package:quantum_crypto/src/core/models/benchmark_result.dart';
import '../../rust/api/benchmark_api.dart' as rust_api;

final

    /// Internal implementation of `BenchmarkServiceImpl`.
    ///
    /// **Warning**: Do not use this class directly. Always interact with
    /// the cryptographic functions via the [QuantumCrypto] facade to ensure
    /// correct initialization and memory safety.
    ///
    /// Example:
    /// ```dart
    /// // Correct usage:
    /// final result = await QuantumCrypto.kem.generateKeyPair(KemAlgorithm.mlKem768);
    /// ```
    class BenchmarkServiceImpl implements BenchmarkService {
  /// Creates an internal instance of [BenchmarkServiceImpl].
  const BenchmarkServiceImpl();

  @override
  Future<PqcBenchmarkSuiteResult> runFullSuite({
    int kemIterations = 10,
    int dsaIterations = 10,
    int aeadIterations = 100,
  }) async {
    final result = await rust_api.runBenchmarkSuite(
      kemIterations: kemIterations,
      dsaIterations: dsaIterations,
      aeadIterations: aeadIterations,
    );
    return PqcBenchmarkSuiteResult(
      results: result.results
          .map((r) => PqcBenchmarkResult(
                operation: r.operation,
                algorithm: r.algorithm,
                iterations: r.iterations,
                totalUs: r.totalUs.toInt(),
                avgUs: r.avgUs.toInt(),
                opsPerSec: r.opsPerSec,
              ))
          .toList(),
      platform: result.platform,
      totalDurationMs: result.totalDurationMs.toInt(),
    );
  }

  @override
  Future<List<PqcBenchmarkResult>> benchmarkKem({
    required String algorithmName,
    int iterations = 10,
  }) async {
    final results = await rust_api.benchmarkKemByName(
      algorithmName: algorithmName,
      iterations: iterations,
    );
    return results
        .map((r) => PqcBenchmarkResult(
              operation: r.operation,
              algorithm: r.algorithm,
              iterations: r.iterations,
              totalUs: r.totalUs.toInt(),
              avgUs: r.avgUs.toInt(),
              opsPerSec: r.opsPerSec,
            ))
        .toList();
  }

  @override
  Future<List<PqcBenchmarkResult>> benchmarkDsa({
    required String algorithmName,
    int iterations = 10,
  }) async {
    final results = await rust_api.benchmarkDsaByName(
      algorithmName: algorithmName,
      iterations: iterations,
    );
    return results
        .map((r) => PqcBenchmarkResult(
              operation: r.operation,
              algorithm: r.algorithm,
              iterations: r.iterations,
              totalUs: r.totalUs.toInt(),
              avgUs: r.avgUs.toInt(),
              opsPerSec: r.opsPerSec,
            ))
        .toList();
  }
}
