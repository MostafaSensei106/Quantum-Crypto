// ignore_for_file: public_member_api_docs
/// Result of a single benchmark operation.
final class PqcBenchmarkResult {
  final String operation;
  final String algorithm;
  final int iterations;
  final int totalUs;
  final int avgUs;
  final double opsPerSec;

  const PqcBenchmarkResult({
    required this.operation,
    required this.algorithm,
    required this.iterations,
    required this.totalUs,
    required this.avgUs,
    required this.opsPerSec,
  });

  @override
  String toString() =>
      '$operation [$algorithm]: avgUsμs avg, ${opsPerSec.toStringAsFixed(1)} ops/s ($iterations iterations)';
}

/// Full benchmark suite results.
final class PqcBenchmarkSuiteResult {
  final List<PqcBenchmarkResult> results;
  final String platform;
  final int totalDurationMs;

  const PqcBenchmarkSuiteResult({
    required this.results,
    required this.platform,
    required this.totalDurationMs,
  });
}
