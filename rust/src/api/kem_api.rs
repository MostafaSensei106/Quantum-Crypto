//! ML-KEM (FIPS 203) key-encapsulation API — FFI boundary.
//!
//! All functions take owned values (`Vec<u8>`) because `flutter_rust_bridge`
//! codegen requires owned types at the boundary; borrowing happens inside the
//! core engine. Return values are moved, never cloned, out of the engine.

use crate::core::traits::{EncapsulationResult, KeyPair};
use crate::factory::kem_factory::{KemAlgorithm, KemFactory};

/// ML-KEM parameter set (FIPS 203).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKemAlgorithm {
    /// ML-KEM-512 — NIST security level 1.
    MlKem512,
    /// ML-KEM-768 — NIST security level 3 (recommended default).
    MlKem768,
    /// ML-KEM-1024 — NIST security level 5.
    MlKem1024,
}

/// FFI-safe key pair: raw public bytes + raw secret bytes.
pub struct KeyPairDto {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

/// FFI-safe encapsulation output.
pub struct EncapsulationDto {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl From<TargetKemAlgorithm> for KemAlgorithm {
    fn from(target: TargetKemAlgorithm) -> Self {
        match target {
            TargetKemAlgorithm::MlKem512 => Self::MlKem512,
            TargetKemAlgorithm::MlKem768 => Self::MlKem768,
            TargetKemAlgorithm::MlKem1024 => Self::MlKem1024,
        }
    }
}

impl From<KeyPair> for KeyPairDto {
    fn from(keypair: KeyPair) -> Self {
        Self {
            public_key: keypair.public_key,
            secret_key: keypair.secret_key.into_bytes(),
        }
    }
}

impl From<EncapsulationResult> for EncapsulationDto {
    fn from(
        EncapsulationResult {
            ciphertext,
            shared_secret,
        }: EncapsulationResult,
    ) -> Self {
        Self {
            ciphertext,
            shared_secret,
        }
    }
}

/// Generate an ML-KEM key pair for `algorithm`.
pub fn generate_kem_keypair(algorithm: TargetKemAlgorithm) -> Result<KeyPairDto, String> {
    KemFactory::create_strategy(algorithm.into())
        .generate_keypair()
        .map(KeyPairDto::from)
}

/// Encapsulate a fresh shared secret to `public_key`.
pub fn kem_encapsulate(
    algorithm: TargetKemAlgorithm,
    public_key: Vec<u8>,
) -> Result<EncapsulationDto, String> {
    KemFactory::create_strategy(algorithm.into())
        .encapsulate(&public_key)
        .map(EncapsulationDto::from)
}

/// Decapsulate `ciphertext` with `secret_key`, recovering the shared secret.
pub fn kem_decapsulate(
    algorithm: TargetKemAlgorithm,
    ciphertext: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    KemFactory::create_strategy(algorithm.into()).decapsulate(&ciphertext, &secret_key)
}
