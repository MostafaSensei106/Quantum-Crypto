use std::time::Instant;

use crate::core::aead::{AeadAlgorithmVariant, AeadEngine};
use crate::core::hybrid_kem::{HybridKemEngine, HybridKemVariant};
use crate::factory::dsa_factory::{DsaAlgorithm, DsaFactory};
use crate::factory::kem_factory::{KemAlgorithm, KemFactory};

/// Result of a single benchmark operation.
pub struct BenchmarkResult {
    /// Name of the operation benchmarked.
    pub operation: String,
    /// Algorithm or variant used.
    pub algorithm: String,
    /// Number of iterations performed.
    pub iterations: u32,
    /// Total time in microseconds.
    pub total_us: u64,
    /// Average time per operation in microseconds.
    pub avg_us: u64,
    /// Operations per second.
    pub ops_per_sec: f64,
}

/// Full benchmark suite results.
pub struct BenchmarkSuiteResult {
    pub results: Vec<BenchmarkResult>,
    pub platform: String,
    pub total_duration_ms: u64,
}

fn bench<F: Fn() -> Result<(), String>>(
    operation: &str,
    algorithm: &str,
    iterations: u32,
    f: F,
) -> Result<BenchmarkResult, String> {
    // Warmup
    for _ in 0..3 {
        f()?;
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f()?;
    }
    let elapsed = start.elapsed();
    let total_us = elapsed.as_micros() as u64;
    let avg_us = if iterations > 0 { total_us / iterations as u64 } else { 0 };
    let ops_per_sec = if total_us > 0 {
        (iterations as f64 / total_us as f64) * 1_000_000.0
    } else {
        0.0
    };

    Ok(BenchmarkResult {
        operation: operation.to_string(),
        algorithm: algorithm.to_string(),
        iterations,
        total_us,
        avg_us,
        ops_per_sec,
    })
}

fn kem_algorithm_from_name(name: &str) -> KemAlgorithm {
    match name {
        "ML-KEM-512" => KemAlgorithm::MlKem512,
        "ML-KEM-768" => KemAlgorithm::MlKem768,
        "ML-KEM-1024" => KemAlgorithm::MlKem1024,
        _ => KemAlgorithm::MlKem768,
    }
}

fn dsa_algorithm_from_name(name: &str) -> DsaAlgorithm {
    match name {
        "ML-DSA-44" => DsaAlgorithm::MlDsa44,
        "ML-DSA-65" => DsaAlgorithm::MlDsa65,
        "ML-DSA-87" => DsaAlgorithm::MlDsa87,
        _ => DsaAlgorithm::MlDsa65,
    }
}

fn hybrid_variant_from_name(name: &str) -> HybridKemVariant {
    match name {
        "Hybrid-ML-KEM-512-X25519" => HybridKemVariant::MlKem512X25519,
        "Hybrid-ML-KEM-768-X25519" => HybridKemVariant::MlKem768X25519,
        "Hybrid-ML-KEM-1024-X25519" => HybridKemVariant::MlKem1024X25519,
        _ => HybridKemVariant::MlKem768X25519,
    }
}

fn aead_variant_from_name(name: &str) -> AeadAlgorithmVariant {
    match name {
        "AES-256-GCM" => AeadAlgorithmVariant::Aes256Gcm,
        "ChaCha20-Poly1305" => AeadAlgorithmVariant::ChaCha20Poly1305,
        _ => AeadAlgorithmVariant::Aes256Gcm,
    }
}

/// Run the full benchmark suite covering KEM, DSA, Hybrid KEM, and AEAD operations.
///
/// * `kem_iterations` - Number of iterations for KEM benchmarks
/// * `dsa_iterations` - Number of iterations for DSA benchmarks
/// * `aead_iterations` - Number of iterations for AEAD benchmarks
pub fn run_benchmark_suite(
    kem_iterations: u32,
    dsa_iterations: u32,
    aead_iterations: u32,
) -> Result<BenchmarkSuiteResult, String> {
    let suite_start = Instant::now();
    let mut results = Vec::new();

    // === ML-KEM Benchmarks ===
    let kem_names = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];

    for name in &kem_names {
        // KeyGen
        results.push(bench("keygen", name, kem_iterations, || {
            let strategy = KemFactory::create_strategy(kem_algorithm_from_name(name));
            strategy.generate_keypair()?;
            Ok(())
        })?);

        // Encapsulate + Decapsulate
        let strategy = KemFactory::create_strategy(kem_algorithm_from_name(name));
        let kp = strategy.generate_keypair()?;
        let pk = kp.public_key.clone();
        let sk = kp.secret_key.bytes.clone();

        results.push(bench("encapsulate", name, kem_iterations, || {
            let s = KemFactory::create_strategy(kem_algorithm_from_name(name));
            s.encapsulate(&pk)?;
            Ok(())
        })?);

        let enc_res = strategy.encapsulate(&pk)?;
        let ct = enc_res.ciphertext.clone();

        results.push(bench("decapsulate", name, kem_iterations, || {
            let s = KemFactory::create_strategy(kem_algorithm_from_name(name));
            s.decapsulate(&ct, &sk)?;
            Ok(())
        })?);
    }

    // === ML-DSA Benchmarks ===
    let dsa_names = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
    let test_message = b"Benchmark test message for quantum_crypto library".to_vec();

    for name in &dsa_names {
        // KeyGen
        results.push(bench("keygen", name, dsa_iterations, || {
            let s = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
            s.generate_keypair()?;
            Ok(())
        })?);

        // Sign
        let strategy = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
        let kp = strategy.generate_keypair()?;
        let sk = kp.secret_key.bytes.clone();
        let pk = kp.public_key.clone();
        let msg = test_message.clone();

        results.push(bench("sign", name, dsa_iterations, || {
            let s = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
            s.sign(&msg, &sk)?;
            Ok(())
        })?);

        // Verify
        let sig = strategy.sign(&msg, &sk)?;

        results.push(bench("verify", name, dsa_iterations, || {
            let s = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
            s.verify(&msg, &sig, &pk)?;
            Ok(())
        })?);
    }

    // === Hybrid KEM Benchmarks ===
    let hybrid_names = [
        "Hybrid-ML-KEM-512-X25519",
        "Hybrid-ML-KEM-768-X25519",
        "Hybrid-ML-KEM-1024-X25519",
    ];

    for name in &hybrid_names {
        let engine = HybridKemEngine::new(hybrid_variant_from_name(name));

        // KeyGen
        results.push(bench("keygen", name, kem_iterations, || {
            let e = HybridKemEngine::new(hybrid_variant_from_name(name));
            e.generate_keypair()?;
            Ok(())
        })?);

        // Encapsulate
        let kp = engine.generate_keypair()?;
        let mlkem_pk = kp.mlkem_public_key.clone();
        let x25519_pk = kp.x25519_public_key.clone();

        results.push(bench("encapsulate", name, kem_iterations, || {
            let e = HybridKemEngine::new(hybrid_variant_from_name(name));
            e.encapsulate(&mlkem_pk, &x25519_pk)?;
            Ok(())
        })?);

        // Decapsulate
        let enc = engine.encapsulate(&mlkem_pk, &x25519_pk)?;
        let mlkem_ct = enc.mlkem_ciphertext.clone();
        let x25519_eph = enc.x25519_ephemeral_pk.clone();
        let mlkem_sk = kp.mlkem_secret_key.clone();
        let x25519_sk = kp.x25519_secret_key.clone();

        results.push(bench("decapsulate", name, kem_iterations, || {
            let e = HybridKemEngine::new(hybrid_variant_from_name(name));
            e.decapsulate(&mlkem_ct, &x25519_eph, &mlkem_sk, &x25519_sk)?;
            Ok(())
        })?);
    }

    // === AEAD Benchmarks ===
    let aead_names = ["AES-256-GCM", "ChaCha20-Poly1305"];
    let payload_sizes: Vec<(usize, &str)> = vec![
        (64, "64B"),
        (1024, "1KB"),
        (65536, "64KB"),
        (1048576, "1MB"),
    ];

    for algo_name in &aead_names {
        for (size, size_name) in &payload_sizes {
            let key = vec![0x42u8; 32];
            let plaintext = vec![0xABu8; *size];
            let label = format!("{} ({})", algo_name, size_name);
            let variant = aead_variant_from_name(algo_name);

            let engine = AeadEngine::new(variant);

            // Encrypt
            results.push(bench("encrypt", &label, aead_iterations, || {
                let e = AeadEngine::new(aead_variant_from_name(algo_name));
                e.encrypt(&key, &plaintext)?;
                Ok(())
            })?);

            // Decrypt
            let ct = engine.encrypt(&key, &plaintext)?;
            results.push(bench("decrypt", &label, aead_iterations, || {
                let e = AeadEngine::new(aead_variant_from_name(algo_name));
                e.decrypt(&key, &ct)?;
                Ok(())
            })?);
        }
    }

    let total_duration_ms = suite_start.elapsed().as_millis() as u64;

    Ok(BenchmarkSuiteResult {
        results,
        platform: get_platform_info(),
        total_duration_ms,
    })
}

/// Run a quick benchmark for a single KEM algorithm variant.
pub fn benchmark_kem_by_name(
    algorithm_name: String,
    iterations: u32,
) -> Result<Vec<BenchmarkResult>, String> {
    let name = algorithm_name.as_str();
    let mut results = Vec::new();

    let strategy = KemFactory::create_strategy(kem_algorithm_from_name(name));
    let kp = strategy.generate_keypair()?;

    results.push(bench("keygen", name, iterations, || {
        let s = KemFactory::create_strategy(kem_algorithm_from_name(name));
        s.generate_keypair()?;
        Ok(())
    })?);

    let pk = kp.public_key.clone();
    results.push(bench("encapsulate", name, iterations, || {
        let s = KemFactory::create_strategy(kem_algorithm_from_name(name));
        s.encapsulate(&pk)?;
        Ok(())
    })?);

    let enc_res = strategy.encapsulate(&pk)?;
    let ct = enc_res.ciphertext.clone();
    let sk = kp.secret_key.bytes.clone();
    results.push(bench("decapsulate", name, iterations, || {
        let s = KemFactory::create_strategy(kem_algorithm_from_name(name));
        s.decapsulate(&ct, &sk)?;
        Ok(())
    })?);

    Ok(results)
}

/// Run a quick benchmark for a single DSA algorithm variant.
pub fn benchmark_dsa_by_name(
    algorithm_name: String,
    iterations: u32,
) -> Result<Vec<BenchmarkResult>, String> {
    let name = algorithm_name.as_str();
    let mut results = Vec::new();

    let strategy = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
    let kp = strategy.generate_keypair()?;
    let msg = b"Benchmark test message".to_vec();

    results.push(bench("keygen", name, iterations, || {
        let s = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
        s.generate_keypair()?;
        Ok(())
    })?);

    let sk = kp.secret_key.bytes.clone();
    results.push(bench("sign", name, iterations, || {
        let s = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
        s.sign(&msg, &sk)?;
        Ok(())
    })?);

    let sig = strategy.sign(&msg, &sk)?;
    let pk = kp.public_key.clone();
    results.push(bench("verify", name, iterations, || {
        let s = DsaFactory::create_strategy(dsa_algorithm_from_name(name));
        s.verify(&msg, &sig, &pk)?;
        Ok(())
    })?);

    Ok(results)
}

fn get_platform_info() -> String {
    format!(
        "{} {} ({})",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    )
}
