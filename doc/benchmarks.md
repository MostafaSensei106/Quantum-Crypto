# Benchmark methodology

The harness remains at `test/benchmark_test.dart`; run it explicitly with
`flutter test test/benchmark_test.dart`. Correctness CI excludes this timing suite.
Default counts are 100 warmups and 1000 timed iterations per operation. Optional
`--dart-define=BENCHMARK_WARMUP=3 --dart-define=BENCHMARK_ITERATIONS=5` provides a
smoke run, not publishable performance data.

Record CPU model/features, RAM, device model, OS/version, architecture, power and
thermal state, compiler versions, Rust profile/flags, Flutter mode, commit,
parameter set, message sizes and iteration counts with every published result.
The Rust release profile has LTO; Flutter test timings are not release-mode
mobile UI measurements. Dart measurements include bridge and wrapper work;
Rust benchmark API measurements time native operations separately. Do not
subtract unrelated measurements to claim precise FFI overhead.

Report distributions over repeated runs, peak RSS, allocations, and warmup
policy. A debug/profile Flutter application on physical Android/iOS devices is
needed to assess frame timing and UI responsiveness; release native throughput
alone cannot establish that. Include a semantically equivalent Dart baseline
with matching algorithms, parameters, input sizes and execution strategy before
claiming a comparative advantage. NTT optimizations come from dependencies.

Parameter-set timing need not be monotonic in one noisy run. CPU dispatch,
cache, build configuration and measurement variance can affect results; investigate
and repeat unexpected orderings rather than inventing an explanation. Keep
ML-KEM key generation separate from HKDF seed-byte derivation and label the
Encrypt-then-Sign pipeline correctly.

[Historical numbers](benchmarks-legacy.md) lack environment details. They are
retained as historical observations, not measurements for 0.0.3 or a Dart baseline.
