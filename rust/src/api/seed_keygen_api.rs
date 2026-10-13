//! Deterministic seed-based key derivation — FFI boundary.
//!
//! One 32-byte master seed derives any number of domain-separated keys via
//! HKDF-SHA256 (`purpose || key_index`), enabling wallet-style backup and
//! recovery: back up the seed once, re-derive everything.

use crate::core::seed_keygen::SeedKeyDerivation;

/// Generate a cryptographically secure random 32-byte master seed.
pub fn generate_master_seed() -> Vec<u8> {
    SeedKeyDerivation::generate_seed()
}

/// Derive `output_len` bytes for (`purpose`, `key_index`) from `seed`.
pub fn derive_key_from_seed(
    seed: Vec<u8>,
    purpose: String,
    key_index: u32,
    output_len: u32,
) -> Result<Vec<u8>, String> {
    SeedKeyDerivation::derive(&seed, &purpose, key_index, output_len as usize)
}

/// Derive a 32-byte X25519 private key from (`seed`, `key_index`).
pub fn derive_x25519_from_seed(seed: Vec<u8>, key_index: u32) -> Result<Vec<u8>, String> {
    SeedKeyDerivation::derive_x25519_key(&seed, key_index)
}

/// Derive a 32-byte AEAD symmetric key from (`seed`, `key_index`).
pub fn derive_aead_key_from_seed(seed: Vec<u8>, key_index: u32) -> Result<Vec<u8>, String> {
    SeedKeyDerivation::derive_aead_key(&seed, key_index)
}
