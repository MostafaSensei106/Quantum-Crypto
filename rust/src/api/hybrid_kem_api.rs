//! Hybrid KEM (X25519 + ML-KEM) API — FFI boundary.
//!
//! Defense in depth: the shared secret is `HKDF-SHA256(ML-KEM-ss || X25519-ss)`,
//! so the exchange stays safe if *either* component is broken.

use crate::core::hybrid_kem::{
    HybridEncapsulationData, HybridKemEngine, HybridKemVariant, HybridKeyPairData,
};

/// Hybrid KEM variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetHybridKemAlgorithm {
    /// ML-KEM-512 + X25519 — NIST level 1 + classical.
    MlKem512X25519,
    /// ML-KEM-768 + X25519 — NIST level 3 + classical (recommended default).
    MlKem768X25519,
    /// ML-KEM-1024 + X25519 — NIST level 5 + classical.
    MlKem1024X25519,
}

/// FFI-safe hybrid key pair (both components, raw bytes).
pub struct HybridKeyPairDto {
    pub mlkem_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub mlkem_secret_key: Vec<u8>,
    pub x25519_secret_key: Vec<u8>,
}

/// FFI-safe hybrid encapsulation output.
pub struct HybridEncapsulationDto {
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl From<TargetHybridKemAlgorithm> for HybridKemVariant {
    fn from(target: TargetHybridKemAlgorithm) -> Self {
        match target {
            TargetHybridKemAlgorithm::MlKem512X25519 => Self::MlKem512X25519,
            TargetHybridKemAlgorithm::MlKem768X25519 => Self::MlKem768X25519,
            TargetHybridKemAlgorithm::MlKem1024X25519 => Self::MlKem1024X25519,
        }
    }
}

impl From<HybridKeyPairData> for HybridKeyPairDto {
    fn from(data: HybridKeyPairData) -> Self {
        let (mlkem_public_key, x25519_public_key, mlkem_secret_key, x25519_secret_key) =
            data.into_parts();
        Self {
            mlkem_public_key,
            x25519_public_key,
            mlkem_secret_key,
            x25519_secret_key,
        }
    }
}

impl From<HybridEncapsulationData> for HybridEncapsulationDto {
    fn from(
        HybridEncapsulationData {
            mlkem_ciphertext,
            x25519_ephemeral_pk,
            shared_secret,
        }: HybridEncapsulationData,
    ) -> Self {
        Self {
            mlkem_ciphertext,
            x25519_ephemeral_pk,
            shared_secret,
        }
    }
}

/// Generate a hybrid key pair for `algorithm`.
pub fn generate_hybrid_kem_keypair(
    algorithm: TargetHybridKemAlgorithm,
) -> Result<HybridKeyPairDto, String> {
    HybridKemEngine::new(algorithm.into())
        .generate_keypair()
        .map(HybridKeyPairDto::from)
}

/// Encapsulate a shared secret to the recipient's hybrid public keys.
pub fn hybrid_kem_encapsulate(
    algorithm: TargetHybridKemAlgorithm,
    mlkem_public_key: Vec<u8>,
    x25519_public_key: Vec<u8>,
) -> Result<HybridEncapsulationDto, String> {
    HybridKemEngine::new(algorithm.into())
        .encapsulate(&mlkem_public_key, &x25519_public_key)
        .map(HybridEncapsulationDto::from)
}

/// Decapsulate with the recipient's hybrid secret keys.
pub fn hybrid_kem_decapsulate(
    algorithm: TargetHybridKemAlgorithm,
    mlkem_ciphertext: Vec<u8>,
    x25519_ephemeral_pk: Vec<u8>,
    mlkem_secret_key: Vec<u8>,
    x25519_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    HybridKemEngine::new(algorithm.into()).decapsulate(
        &mlkem_ciphertext,
        &x25519_ephemeral_pk,
        &mlkem_secret_key,
        &x25519_secret_key,
    )
}
