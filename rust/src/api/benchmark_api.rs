//! Benchmark suite — FFI boundary.
//!
//! Every `run_*` entry point takes explicit iteration counts so callers
//! (and CI) control suite cost. SLH-DSA signing is clamped to a handful of
//! iterations internally — it is ~100× slower than ML-DSA by design — and
//! the actual iteration count is always reported back per result.

use std::time::Instant;

use crate::core::aead::{AeadAlgorithmVariant, AeadEngine};
use crate::core::hash::{digest, HashAlgorithm};
use crate::core::hybrid_kem::{HybridKemEngine, HybridKemVariant};
use crate::core::slhdsa::SlhDsaVariant;
use crate::core::traits::{DsaStrategy, KemStrategy};
use crate::factory::dsa_factory::{DsaAlgorithm, DsaFactory};
use crate::factory::kem_factory::{KemAlgorithm, KemFactory};

/// Result of a single benchmark operation.
pub struct BenchmarkResult {
    /// Name of the operation benchmarked.
    pub operation: String,
    /// Algorithm or variant used.
    pub algorithm: String,
    /// Number of iterations actually performed.
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
    // Warmup (excluded from measurement).
    for _ in 0..3 {
        f()?;
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f()?;
    }
    let elapsed = start.elapsed();
    let total_us = elapsed.as_micros() as u64;
    let avg_us = if iterations > 0 {
        total_us / iterations as u64
    } else {
        0
    };
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

// --- Typed algorithm tables (unknown names are errors, never silent defaults) ---

const KEM_NAMES: [&str; 3] = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
const DSA_NAMES: [&str; 3] = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
const HYBRID_NAMES: [&str; 3] = [
    "Hybrid-ML-KEM-512-X25519",
    "Hybrid-ML-KEM-768-X25519",
    "Hybrid-ML-KEM-1024-X25519",
];
const AEAD_NAMES: [&str; 3] = ["AES-256-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305"];
const HASH_NAMES: [&str; 5] = ["SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"];

fn resolve_kem(name: &str) -> Result<KemAlgorithm, String> {
    match name {
        "ML-KEM-512" => Ok(KemAlgorithm::MlKem512),
        "ML-KEM-768" => Ok(KemAlgorithm::MlKem768),
        "ML-KEM-1024" => Ok(KemAlgorithm::MlKem1024),
        _ => Err(format!("Unknown KEM algorithm: {name}")),
    }
}

fn resolve_dsa(name: &str) -> Result<DsaAlgorithm, String> {
    match name {
        "ML-DSA-44" => Ok(DsaAlgorithm::MlDsa44),
        "ML-DSA-65" => Ok(DsaAlgorithm::MlDsa65),
        "ML-DSA-87" => Ok(DsaAlgorithm::MlDsa87),
        _ => Err(format!("Unknown DSA algorithm: {name}")),
    }
}

fn resolve_slh_dsa(name: &str) -> Result<SlhDsaVariant, String> {
    match name {
        "SLH-DSA-SHA2-128f" => Ok(SlhDsaVariant::Sha2_128f),
        "SLH-DSA-SHA2-192f" => Ok(SlhDsaVariant::Sha2_192f),
        "SLH-DSA-SHA2-256f" => Ok(SlhDsaVariant::Sha2_256f),
        _ => Err(format!("Unknown SLH-DSA algorithm: {name}")),
    }
}

fn resolve_hybrid(name: &str) -> Result<HybridKemVariant, String> {
    match name {
        "Hybrid-ML-KEM-512-X25519" => Ok(HybridKemVariant::MlKem512X25519),
        "Hybrid-ML-KEM-768-X25519" => Ok(HybridKemVariant::MlKem768X25519),
        "Hybrid-ML-KEM-1024-X25519" => Ok(HybridKemVariant::MlKem1024X25519),
        _ => Err(format!("Unknown hybrid KEM variant: {name}")),
    }
}

fn resolve_aead(name: &str) -> Result<AeadAlgorithmVariant, String> {
    match name {
        "AES-256-GCM" => Ok(AeadAlgorithmVariant::Aes256Gcm),
        "ChaCha20-Poly1305" => Ok(AeadAlgorithmVariant::ChaCha20Poly1305),
        "XChaCha20-Poly1305" => Ok(AeadAlgorithmVariant::XChaCha20Poly1305),
        _ => Err(format!("Unknown AEAD algorithm: {name}")),
    }
}

fn resolve_hash(name: &str) -> Result<HashAlgorithm, String> {
    match name {
        "SHA-256" => Ok(HashAlgorithm::Sha256),
        "SHA-384" => Ok(HashAlgorithm::Sha384),
        "SHA-512" => Ok(HashAlgorithm::Sha512),
        "SHA3-256" => Ok(HashAlgorithm::Sha3_256),
        "SHA3-512" => Ok(HashAlgorithm::Sha3_512),
        _ => Err(format!("Unknown hash algorithm: {name}")),
    }
}

fn kem_strategy(name: &str) -> Result<Box<dyn KemStrategy>, String> {
    resolve_kem(name).map(KemFactory::create_strategy)
}

fn dsa_strategy(name: &str) -> Result<Box<dyn DsaStrategy>, String> {
    resolve_dsa(name).map(DsaFactory::create_strategy)
}

// --- Per-family benchmark sets ---

fn benchmark_kem_set(name: &str, iterations: u32) -> Result<Vec<BenchmarkResult>, String> {
    let mut out = Vec::with_capacity(3);
    out.push(bench("keygen", name, iterations, || {
        kem_strategy(name)?.generate_keypair()?;
        Ok(())
    })?);

    let kp = kem_strategy(name)?.generate_keypair()?;
    out.push(bench("encapsulate", name, iterations, || {
        kem_strategy(name)?.encapsulate(&kp.public_key)?;
        Ok(())
    })?);

    let enc = kem_strategy(name)?.encapsulate(&kp.public_key)?;
    out.push(bench("decapsulate", name, iterations, || {
        kem_strategy(name)?.decapsulate(&enc.ciphertext, &kp.secret_key.bytes)?;
        Ok(())
    })?);
    Ok(out)
}

fn benchmark_dsa_set(name: &str, iterations: u32) -> Result<Vec<BenchmarkResult>, String> {
    let mut out = Vec::with_capacity(3);
    out.push(bench("keygen", name, iterations, || {
        dsa_strategy(name)?.generate_keypair()?;
        Ok(())
    })?);

    let message = b"Benchmark test message for quantum_crypto library".to_vec();
    let kp = dsa_strategy(name)?.generate_keypair()?;
    out.push(bench("sign", name, iterations, || {
        dsa_strategy(name)?.sign(&message, &kp.secret_key.bytes)?;
        Ok(())
    })?);

    let sig = dsa_strategy(name)?.sign(&message, &kp.secret_key.bytes)?;
    out.push(bench("verify", name, iterations, || {
        dsa_strategy(name)?.verify(&message, &sig, &kp.public_key)?;
        Ok(())
    })?);
    Ok(out)
}

/// SLH-DSA signing is ~100× slower than ML-DSA, so sign iterations are
/// clamped to at most 5 to keep the suite practical.
fn benchmark_slh_dsa_set(name: &str, iterations: u32) -> Result<Vec<BenchmarkResult>, String> {
    use crate::core::slhdsa::SlhDsaStrategy;

    fn strategy(name: &str) -> Result<SlhDsaStrategy, String> {
        resolve_slh_dsa(name).map(SlhDsaStrategy::new)
    }

    let sign_iterations = iterations.clamp(1, 5);
    let mut out = Vec::with_capacity(3);
    out.push(bench("keygen", name, iterations, || {
        strategy(name)?.generate_keypair()?;
        Ok(())
    })?);

    let message = b"Benchmark test message for quantum_crypto library".to_vec();
    let kp = strategy(name)?.generate_keypair()?;
    out.push(bench("sign", name, sign_iterations, || {
        strategy(name)?.sign(&message, &kp.secret_key.bytes)?;
        Ok(())
    })?);

    let sig = strategy(name)?.sign(&message, &kp.secret_key.bytes)?;
    out.push(bench("verify", name, iterations, || {
        strategy(name)?.verify(&message, &sig, &kp.public_key)?;
        Ok(())
    })?);
    Ok(out)
}

fn benchmark_hybrid_set(name: &str, iterations: u32) -> Result<Vec<BenchmarkResult>, String> {
    fn engine(name: &str) -> Result<HybridKemEngine, String> {
        resolve_hybrid(name).map(HybridKemEngine::new)
    }

    let mut out = Vec::with_capacity(3);
    out.push(bench("keygen", name, iterations, || {
        engine(name)?.generate_keypair()?;
        Ok(())
    })?);

    let kp = engine(name)?.generate_keypair()?;
    out.push(bench("encapsulate", name, iterations, || {
        engine(name)?.encapsulate(&kp.mlkem_public_key, &kp.x25519_public_key)?;
        Ok(())
    })?);

    let enc = engine(name)?.encapsulate(&kp.mlkem_public_key, &kp.x25519_public_key)?;
    out.push(bench("decapsulate", name, iterations, || {
        engine(name)?.decapsulate(
            &enc.mlkem_ciphertext,
            &enc.x25519_ephemeral_pk,
            &kp.mlkem_secret_key,
            &kp.x25519_secret_key,
        )?;
        Ok(())
    })?);
    Ok(out)
}

fn benchmark_aead_set(
    name: &str,
    payload_sizes: &[usize],
    iterations: u32,
) -> Result<Vec<BenchmarkResult>, String> {
    fn engine(name: &str) -> Result<AeadEngine, String> {
        resolve_aead(name).map(AeadEngine::new)
    }

    let mut out = Vec::new();
    for size in payload_sizes {
        let key = vec![0x42u8; 32];
        let plaintext = vec![0xABu8; *size];
        let label = format!("{name} ({})", human_size(*size));

        out.push(bench(
            &format!("encrypt {}", human_size(*size)),
            &label,
            iterations,
            || {
                engine(name)?.encrypt(&key, &plaintext)?;
                Ok(())
            },
        )?);

        let ct = engine(name)?.encrypt(&key, &plaintext)?;
        out.push(bench(
            &format!("decrypt {}", human_size(*size)),
            &label,
            iterations,
            || {
                engine(name)?.decrypt(&key, &ct)?;
                Ok(())
            },
        )?);
    }
    Ok(out)
}

fn human_size(bytes: usize) -> &'static str {
    match bytes {
        64 => "64B",
        1024 => "1KB",
        65536 => "64KB",
        1048576 => "1MB",
        _ => "custom",
    }
}

fn benchmark_hash_set(name: &str, iterations: u32) -> Result<Vec<BenchmarkResult>, String> {
    let variant = resolve_hash(name)?;
    let input = vec![0xABu8; 1024];
    Ok(vec![bench("digest (1KB)", name, iterations, || {
        digest(variant, &input);
        Ok(())
    })?])
}

// --- Public entry points (FFI) ---

/// Run the full benchmark suite covering KEM, DSA, SLH-DSA, hybrid KEM,
/// AEAD, and hashing.
///
/// * `kem_iterations` — iterations for KEM / hybrid / hash benchmarks
/// * `dsa_iterations` — iterations for DSA benchmarks (SLH-DSA signing is
///   clamped internally, see [`benchmark_slh_dsa_set`])
/// * `aead_iterations` — iterations for AEAD benchmarks
pub fn run_benchmark_suite(
    kem_iterations: u32,
    dsa_iterations: u32,
    aead_iterations: u32,
) -> Result<BenchmarkSuiteResult, String> {
    let suite_start = Instant::now();
    let mut results = Vec::new();

    for name in KEM_NAMES {
        results.extend(benchmark_kem_set(name, kem_iterations)?);
    }
    for name in DSA_NAMES {
        results.extend(benchmark_dsa_set(name, dsa_iterations)?);
    }
    for name in [
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256f",
    ] {
        results.extend(benchmark_slh_dsa_set(name, dsa_iterations)?);
    }
    for name in HYBRID_NAMES {
        results.extend(benchmark_hybrid_set(name, kem_iterations)?);
    }

    let payload_sizes = [64, 1024, 65536, 1048576];
    for name in AEAD_NAMES {
        results.extend(benchmark_aead_set(name, &payload_sizes, aead_iterations)?);
    }
    for name in HASH_NAMES {
        results.extend(benchmark_hash_set(name, kem_iterations)?);
    }

    Ok(BenchmarkSuiteResult {
        results,
        platform: get_platform_info(),
        total_duration_ms: suite_start.elapsed().as_millis() as u64,
    })
}

/// Run a quick benchmark for a single KEM algorithm variant.
pub fn benchmark_kem_by_name(
    algorithm_name: String,
    iterations: u32,
) -> Result<Vec<BenchmarkResult>, String> {
    benchmark_kem_set(&algorithm_name, iterations)
}

/// Run a quick benchmark for a single ML-DSA algorithm variant.
pub fn benchmark_dsa_by_name(
    algorithm_name: String,
    iterations: u32,
) -> Result<Vec<BenchmarkResult>, String> {
    benchmark_dsa_set(&algorithm_name, iterations)
}

/// Run a quick benchmark for a single SLH-DSA parameter set
/// (signing iterations are clamped, see [`benchmark_slh_dsa_set`]).
pub fn benchmark_slh_dsa_by_name(
    algorithm_name: String,
    iterations: u32,
) -> Result<Vec<BenchmarkResult>, String> {
    benchmark_slh_dsa_set(&algorithm_name, iterations)
}

fn get_platform_info() -> String {
    format!(
        "{} {} ({})",
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::FAMILY
    )
}
