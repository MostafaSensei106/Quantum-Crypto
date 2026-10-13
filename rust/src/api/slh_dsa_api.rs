//! SLH-DSA (FIPS 205) stateless hash-based signatures — FFI boundary.
//!
//! Unlike ML-DSA, SLH-DSA signatures are **detached**: [`slh_dsa_sign`]
//! returns the raw signature bytes only, and [`slh_dsa_verify`] expects
//! exactly those bytes alongside the original message.
//!
//! Trade-off vs ML-DSA: larger signatures (17–49 KB) and slower signing,
//! but security rests solely on hash-function strength — no lattice
//! assumptions. Only the SHA-2 `f` (fast-signing) parameter sets are
//! exposed; see [`SlhDsaVariant`](crate::core::slhdsa::SlhDsaVariant).

use crate::core::slhdsa::{SlhDsaStrategy, SlhDsaVariant};
use crate::core::traits::{DsaKeyPair, DsaStrategy};

/// SLH-DSA parameter set (FIPS 205, SHA-2 fast-signing variants).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetSlhDsaAlgorithm {
    /// SLH-DSA-SHA2-128f — NIST security level 1.
    SlhDsaSha2_128f,
    /// SLH-DSA-SHA2-192f — NIST security level 3.
    SlhDsaSha2_192f,
    /// SLH-DSA-SHA2-256f — NIST security level 5.
    SlhDsaSha2_256f,
}

/// FFI-safe SLH-DSA key pair: raw public bytes + raw secret bytes.
pub struct SlhDsaKeyPairDto {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl From<TargetSlhDsaAlgorithm> for SlhDsaVariant {
    fn from(target: TargetSlhDsaAlgorithm) -> Self {
        match target {
            TargetSlhDsaAlgorithm::SlhDsaSha2_128f => Self::Sha2_128f,
            TargetSlhDsaAlgorithm::SlhDsaSha2_192f => Self::Sha2_192f,
            TargetSlhDsaAlgorithm::SlhDsaSha2_256f => Self::Sha2_256f,
        }
    }
}

impl From<DsaKeyPair> for SlhDsaKeyPairDto {
    fn from(keypair: DsaKeyPair) -> Self {
        Self {
            public_key: keypair.public_key,
            secret_key: keypair.secret_key.into_bytes(),
        }
    }
}

fn strategy(algorithm: TargetSlhDsaAlgorithm) -> SlhDsaStrategy {
    SlhDsaStrategy::new(algorithm.into())
}

/// Generate an SLH-DSA key pair for `algorithm`.
pub fn generate_slh_dsa_keypair(
    algorithm: TargetSlhDsaAlgorithm,
) -> Result<SlhDsaKeyPairDto, String> {
    strategy(algorithm)
        .generate_keypair()
        .map(SlhDsaKeyPairDto::from)
}

/// Sign `message`; returns detached signature bytes (message NOT included).
pub fn slh_dsa_sign(
    algorithm: TargetSlhDsaAlgorithm,
    message: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    strategy(algorithm).sign(&message, &secret_key)
}

/// Verify a detached `signature` over `message`.
/// Returns `Ok(false)` — not an error — when the signature is invalid.
pub fn slh_dsa_verify(
    algorithm: TargetSlhDsaAlgorithm,
    message: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<bool, String> {
    strategy(algorithm).verify(&message, &signature, &public_key)
}
