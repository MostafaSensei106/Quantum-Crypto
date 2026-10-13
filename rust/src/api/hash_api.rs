//! One-shot cryptographic hash API — FFI boundary.
//!
//! SHA-2 and SHA-3 digests for content addressing, key commitment, and
//! transcript hashing around the PQC primitives.

use crate::core::hash::{digest, HashAlgorithm};

/// Digest algorithm selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetHashAlgorithm {
    /// SHA-256 — 32-byte digest (default interop choice).
    Sha256,
    /// SHA-384 — 48-byte digest.
    Sha384,
    /// SHA-512 — 64-byte digest.
    Sha512,
    /// SHA3-256 — 32-byte digest (NIST FIPS 202).
    Sha3_256,
    /// SHA3-512 — 64-byte digest (NIST FIPS 202).
    Sha3_512,
}

impl From<TargetHashAlgorithm> for HashAlgorithm {
    fn from(target: TargetHashAlgorithm) -> Self {
        match target {
            TargetHashAlgorithm::Sha256 => Self::Sha256,
            TargetHashAlgorithm::Sha384 => Self::Sha384,
            TargetHashAlgorithm::Sha512 => Self::Sha512,
            TargetHashAlgorithm::Sha3_256 => Self::Sha3_256,
            TargetHashAlgorithm::Sha3_512 => Self::Sha3_512,
        }
    }
}

/// Compute the digest of `data` with `algorithm`.
pub fn hash_data(algorithm: TargetHashAlgorithm, data: Vec<u8>) -> Vec<u8> {
    digest(algorithm.into(), &data)
}
