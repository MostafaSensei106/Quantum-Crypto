import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'package:flutter_test/flutter_test.dart';
import 'package:quantum_crypto/quantum_crypto.dart';

class BenchmarkResult {
  final String name;
  final String step;
  final double avgUs;
  final double minUs;
  final double maxUs;
  final double medianUs;
  final double opsPerSec;

  BenchmarkResult({
    required this.name,
    required this.step,
    required this.avgUs,
    required this.minUs,
    required this.maxUs,
    required this.medianUs,
    required this.opsPerSec,
  });
}

class BenchmarkRunner {
  final List<BenchmarkResult> results = [];
  final int warmupIterations = 100;
  final int runIterations = 1000;

  Future<void> measure(
      String name, String step, Future<void> Function() operation) async {
    // Warm-up Phase
    for (int i = 0; i < warmupIterations; i++) {
      await operation();
    }

    List<double> timesUs = [];
    final stopwatch = Stopwatch();

    // Evaluation Phase
    for (int i = 0; i < runIterations; i++) {
      stopwatch.reset();
      stopwatch.start();
      await operation();
      stopwatch.stop();
      timesUs.add(stopwatch.elapsedMicroseconds.toDouble());
    }

    timesUs.sort();
    double sum = timesUs.fold(0, (a, b) => a + b);
    double avg = sum / runIterations;
    double minTime = timesUs.first;
    double maxTime = timesUs.last;
    double median = timesUs[runIterations ~/ 2];
    double opsPerSec = avg > 0 ? 1000000.0 / avg : 0.0;

    results.add(BenchmarkResult(
      name: name,
      step: step,
      avgUs: avg,
      minUs: minTime,
      maxUs: maxTime,
      medianUs: median,
      opsPerSec: opsPerSec,
    ));
  }

  void printTable() {
    print('=' * 135);
    print(
        '| ${'Algorithm / Operation'.padRight(35)} | ${'Step'.padRight(15)} | ${'Avg (\u03bcs)'.padLeft(12)} | ${'Min (\u03bcs)'.padLeft(12)} | ${'Max (\u03bcs)'.padLeft(12)} | ${'Median (\u03bcs)'.padLeft(12)} | ${'Ops/sec'.padLeft(14)} |');
    print('-' * 135);

    for (var r in results) {
      String name =
          r.name.length > 35 ? '${r.name.substring(0, 32)}...' : r.name;
      String step =
          r.step.length > 15 ? '${r.step.substring(0, 12)}...' : r.step;

      print(
          '| ${name.padRight(35)} | ${step.padRight(15)} | ${r.avgUs.toStringAsFixed(1).padLeft(12)} | ${r.minUs.toStringAsFixed(1).padLeft(12)} | ${r.maxUs.toStringAsFixed(1).padLeft(12)} | ${r.medianUs.toStringAsFixed(1).padLeft(12)} | ${r.opsPerSec.toStringAsFixed(1).padLeft(14)} |');
    }
    print('=' * 135);
  }
}

Future<void> runKemBenchmarks(
    BenchmarkRunner runner, KemAlgorithm algo, String name) async {
  late PqcKeyPair keyPair;
  late PqcEncapsulationResult encapsulation;

  await runner.measure(name, 'KeyGen', () async {
    keyPair = await QuantumCrypto.kem.generateKeyPair(algo);
  });

  await runner.measure(name, 'Encapsulate', () async {
    encapsulation = await QuantumCrypto.kem
        .encapsulate(algorithm: algo, publicKey: keyPair.publicKey);
  });

  await runner.measure(name, 'Decapsulate', () async {
    await QuantumCrypto.kem.decapsulate(
        algorithm: algo,
        ciphertext: encapsulation.ciphertext,
        secretKey: keyPair.secretKey);
  });

  await runner.measure(name, 'Roundtrip', () async {
    final kp = await QuantumCrypto.kem.generateKeyPair(algo);
    final enc = await QuantumCrypto.kem
        .encapsulate(algorithm: algo, publicKey: kp.publicKey);
    await QuantumCrypto.kem.decapsulate(
        algorithm: algo, ciphertext: enc.ciphertext, secretKey: kp.secretKey);
  });
}

Future<void> runDsaBenchmarks(
    BenchmarkRunner runner, DsaAlgorithm algo, String name) async {
  late PqcKeyPair keyPair;
  late Uint8List signature;
  final message = Uint8List.fromList(utf8.encode("Benchmark Test Message"));

  await runner.measure(name, 'KeyGen', () async {
    keyPair = await QuantumCrypto.dsa.generateKeyPair(algo);
  });

  await runner.measure(name, 'Sign', () async {
    signature = await QuantumCrypto.dsa
        .sign(algorithm: algo, message: message, secretKey: keyPair.secretKey);
  });

  await runner.measure(name, 'Verify', () async {
    await QuantumCrypto.dsa.verify(
        algorithm: algo,
        message: message,
        signature: signature,
        publicKey: keyPair.publicKey);
  });

  await runner.measure(name, 'Roundtrip', () async {
    final kp = await QuantumCrypto.dsa.generateKeyPair(algo);
    final sig = await QuantumCrypto.dsa
        .sign(algorithm: algo, message: message, secretKey: kp.secretKey);
    await QuantumCrypto.dsa.verify(
        algorithm: algo,
        message: message,
        signature: sig,
        publicKey: kp.publicKey);
  });
}

Future<void> runHybridKemBenchmarks(
    BenchmarkRunner runner, HybridKemAlgorithm algo, String name) async {
  late HybridKeyPair keyPair;
  late HybridEncapsulationResult encapsulation;

  await runner.measure(name, 'KeyGen', () async {
    keyPair = await QuantumCrypto.hybrid.generateKeyPair(algo);
  });

  await runner.measure(name, 'Encapsulate', () async {
    encapsulation = await QuantumCrypto.hybrid.encapsulate(
      algorithm: algo,
      mlKemPublicKey: keyPair.mlKemPublicKey,
      x25519PublicKey: keyPair.x25519PublicKey,
    );
  });

  await runner.measure(name, 'Decapsulate', () async {
    await QuantumCrypto.hybrid.decapsulate(
      algorithm: algo,
      mlKemCiphertext: encapsulation.mlKemCiphertext,
      x25519EphemeralPk: encapsulation.x25519EphemeralPk,
      mlKemSecretKey: keyPair.mlKemSecretKey,
      x25519SecretKey: keyPair.x25519SecretKey,
    );
  });

  await runner.measure(name, 'Roundtrip', () async {
    final kp = await QuantumCrypto.hybrid.generateKeyPair(algo);
    final enc = await QuantumCrypto.hybrid.encapsulate(
      algorithm: algo,
      mlKemPublicKey: kp.mlKemPublicKey,
      x25519PublicKey: kp.x25519PublicKey,
    );
    await QuantumCrypto.hybrid.decapsulate(
      algorithm: algo,
      mlKemCiphertext: enc.mlKemCiphertext,
      x25519EphemeralPk: enc.x25519EphemeralPk,
      mlKemSecretKey: kp.mlKemSecretKey,
      x25519SecretKey: kp.x25519SecretKey,
    );
  });
}

Uint8List _generateRandomBytes(int size) {
  final rnd = Random.secure();
  final data = Uint8List(size);
  for (int i = 0; i < size; i++) {
    data[i] = rnd.nextInt(256);
  }
  return data;
}

Future<void> runAeadBenchmarks(
    BenchmarkRunner runner, AeadAlgorithm algo, String name) async {
  final key = _generateRandomBytes(32);

  // 1 KB
  final pt1k = _generateRandomBytes(1024);
  late Uint8List ct1k;
  await runner.measure('$name (1 KB)', 'Encrypt', () async {
    ct1k = await QuantumCrypto.aead
        .encrypt(algorithm: algo, key: key, plaintext: pt1k);
  });
  await runner.measure('$name (1 KB)', 'Decrypt', () async {
    await QuantumCrypto.aead
        .decrypt(algorithm: algo, key: key, ciphertextWithNonce: ct1k);
  });

  // 64 KB
  final pt64k = _generateRandomBytes(64 * 1024);
  late Uint8List ct64k;
  await runner.measure('$name (64 KB)', 'Encrypt', () async {
    ct64k = await QuantumCrypto.aead
        .encrypt(algorithm: algo, key: key, plaintext: pt64k);
  });
  await runner.measure('$name (64 KB)', 'Decrypt', () async {
    await QuantumCrypto.aead
        .decrypt(algorithm: algo, key: key, ciphertextWithNonce: ct64k);
  });

  // 1 MB (limit iterations for 1MB to avoid too long tests)
  // We'll adjust iterations dynamically if needed, but 1000 iterations for 1MB is fine on Desktop.
  final pt1m = _generateRandomBytes(1024 * 1024);
  late Uint8List ct1m;
  await runner.measure('$name (1 MB)', 'Encrypt', () async {
    ct1m = await QuantumCrypto.aead
        .encrypt(algorithm: algo, key: key, plaintext: pt1m);
  });
  await runner.measure('$name (1 MB)', 'Decrypt', () async {
    await QuantumCrypto.aead
        .decrypt(algorithm: algo, key: key, ciphertextWithNonce: ct1m);
  });
}

Future<void> runDataProcessingBenchmarks(BenchmarkRunner runner) async {
  final key = _generateRandomBytes(32);
  final largeData = _generateRandomBytes(1024 * 1024); // 1MB
  late Uint8List encryptedStream;

  await runner.measure('Streaming Encrypt (1MB, 64k)', 'Process', () async {
    encryptedStream = await QuantumCrypto.streaming.streamEncrypt(
      algorithm: AeadAlgorithm.chaCha20Poly1305,
      key: key,
      plaintext: largeData,
      chunkSize: 65536,
    );
  });

  await runner.measure('Streaming Decrypt (1MB, 64k)', 'Process', () async {
    await QuantumCrypto.streaming
        .streamDecrypt(key: key, encryptedData: encryptedStream);
  });

  final sharedSecret = _generateRandomBytes(32);
  final info = Uint8List.fromList(utf8.encode("benchmark_info"));
  await runner.measure('HKDF-SHA256', 'Derive', () async {
    await QuantumCrypto.kdf
        .derive(sharedSecret: sharedSecret, info: info, outputLength: 32);
  });

  late Uint8List masterSeed;
  await runner.measure('Seed Generation', 'Generate', () async {
    masterSeed = await QuantumCrypto.seed.generateSeed();
  });

  await runner.measure('Deterministic Key', 'Derive (Kem)', () async {
    await QuantumCrypto.seed
        .deriveKey(seed: masterSeed, purpose: "ml-kem", keyIndex: 0);
  });
}

Future<void> runPipelineBenchmarks(BenchmarkRunner runner) async {
  final senderDsa =
      await QuantumCrypto.dsa.generateKeyPair(DsaAlgorithm.mlDsa65);
  final recipientHybrid = await QuantumCrypto.hybrid
      .generateKeyPair(HybridKemAlgorithm.mlKem768X25519);
  final message = _generateRandomBytes(1024); // 1KB Message

  late dynamic package;

  await runner.measure('Sign-then-Encrypt Pipeline', 'EncryptAndSign',
      () async {
    package = await QuantumCrypto.messaging.encryptAndSign(
      message: message,
      senderDsaSecretKey: senderDsa.secretKey,
      recipientMlKemPublicKey: recipientHybrid.mlKemPublicKey,
      recipientX25519PublicKey: recipientHybrid.x25519PublicKey,
    );
  });

  await runner.measure('Sign-then-Encrypt Pipeline', 'VerifyAndDecr', () async {
    await QuantumCrypto.messaging.verifyAndDecrypt(
      package: package,
      recipientMlKemSecretKey: recipientHybrid.mlKemSecretKey,
      recipientX25519SecretKey: recipientHybrid.x25519SecretKey,
      senderDsaPublicKey: senderDsa.publicKey,
    );
  });
}

void main() {
  setUpAll(() async {
    await QuantumCrypto.init();
  });

  test('Comprehensive Cryptography Benchmark', () async {
    final runner = BenchmarkRunner();

    print('Starting ML-KEM Benchmarks...');
    await runKemBenchmarks(runner, KemAlgorithm.mlKem512, 'ML-KEM-512');
    await runKemBenchmarks(runner, KemAlgorithm.mlKem768, 'ML-KEM-768');
    await runKemBenchmarks(runner, KemAlgorithm.mlKem1024, 'ML-KEM-1024');

    print('Starting ML-DSA Benchmarks...');
    await runDsaBenchmarks(runner, DsaAlgorithm.mlDsa44, 'ML-DSA-44');
    await runDsaBenchmarks(runner, DsaAlgorithm.mlDsa65, 'ML-DSA-65');
    await runDsaBenchmarks(runner, DsaAlgorithm.mlDsa87, 'ML-DSA-87');

    print('Starting Hybrid KEM Benchmarks...');
    await runHybridKemBenchmarks(
        runner, HybridKemAlgorithm.mlKem512X25519, 'Hybrid ML-KEM-512');
    await runHybridKemBenchmarks(
        runner, HybridKemAlgorithm.mlKem768X25519, 'Hybrid ML-KEM-768');
    await runHybridKemBenchmarks(
        runner, HybridKemAlgorithm.mlKem1024X25519, 'Hybrid ML-KEM-1024');

    print('Starting AEAD Benchmarks...');
    await runAeadBenchmarks(runner, AeadAlgorithm.aes256Gcm, 'AES-256-GCM');
    await runAeadBenchmarks(
        runner, AeadAlgorithm.chaCha20Poly1305, 'ChaCha20-Poly1305');

    print('Starting Data Processing Benchmarks...');
    await runDataProcessingBenchmarks(runner);

    print('Starting High-Level Pipeline Benchmarks...');
    await runPipelineBenchmarks(runner);

    print('\n\n--- BENCHMARK RESULTS ---\n');
    runner.printTable();
  },
      timeout: Timeout(Duration(
          minutes:
              15))); // Extended timeout since we run 1000 iterations per op
}
