//! ML-DSA (FIPS 204) digital-signature API — FFI boundary.
//!
//! Signatures here are **attached** (the returned bytes embed a copy of the
//! message, per the `pqcrypto` signed-message convention); pass the exact
//! bytes returned by [`dsa_sign`] to [`dsa_verify`]. For detached,
//! fixed-size-friendly signatures see the SLH-DSA API instead.

use crate::core::traits::DsaKeyPair;
use crate::factory::dsa_factory::{DsaAlgorithm, DsaFactory};

/// ML-DSA parameter set (FIPS 204).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetDsaAlgorithm {
    /// ML-DSA-44 — NIST security level 2.
    MlDsa44,
    /// ML-DSA-65 — NIST security level 3 (recommended default).
    MlDsa65,
    /// ML-DSA-87 — NIST security level 5.
    MlDsa87,
}

impl From<TargetDsaAlgorithm> for DsaAlgorithm {
    fn from(target: TargetDsaAlgorithm) -> Self {
        match target {
            TargetDsaAlgorithm::MlDsa44 => Self::MlDsa44,
            TargetDsaAlgorithm::MlDsa65 => Self::MlDsa65,
            TargetDsaAlgorithm::MlDsa87 => Self::MlDsa87,
        }
    }
}

/// FFI-safe signature key pair: raw public bytes + raw secret bytes.
pub struct DsaKeyPairDto {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl From<DsaKeyPair> for DsaKeyPairDto {
    fn from(keypair: DsaKeyPair) -> Self {
        Self {
            public_key: keypair.public_key,
            secret_key: keypair.secret_key.into_bytes(),
        }
    }
}

/// Generate an ML-DSA key pair for `algorithm`.
pub fn generate_dsa_keypair(algorithm: TargetDsaAlgorithm) -> Result<DsaKeyPairDto, String> {
    DsaFactory::create_strategy(algorithm.into())
        .generate_keypair()
        .map(DsaKeyPairDto::from)
}

/// Sign `message` with `secret_key`; returns attached signature bytes.
pub fn dsa_sign(
    algorithm: TargetDsaAlgorithm,
    message: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    DsaFactory::create_strategy(algorithm.into()).sign(&message, &secret_key)
}

/// Verify an attached `signature` over `message` with `public_key`.
/// Returns `Ok(false)` — not an error — when the signature is invalid.
pub fn dsa_verify(
    algorithm: TargetDsaAlgorithm,
    message: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<bool, String> {
    DsaFactory::create_strategy(algorithm.into()).verify(&message, &signature, &public_key)
}
