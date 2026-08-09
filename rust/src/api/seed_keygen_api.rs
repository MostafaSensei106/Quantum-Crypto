use crate::core::seed_keygen::SeedKeyDerivation;

/// Generate a cryptographically secure random 32-byte master seed.
pub fn generate_master_seed() -> Vec<u8> {
    SeedKeyDerivation::generate_seed()
}

/// Derive key material from a master seed using HKDF-SHA256.
///
/// * `seed` - Master seed (>= 32 bytes)
/// * `purpose` - Domain separation string (e.g., "x25519-private-key")
/// * `key_index` - Index for deriving multiple keys of the same purpose
/// * `output_len` - Desired output length in bytes (1-8160)
pub fn derive_key_from_seed(
    seed: Vec<u8>,
    purpose: String,
    key_index: u32,
    output_len: u32,
) -> Result<Vec<u8>, String> {
    SeedKeyDerivation::derive(&seed, &purpose, key_index, output_len as usize)
}

/// Derive a 32-byte X25519 private key deterministically from seed.
pub fn derive_x25519_from_seed(seed: Vec<u8>, key_index: u32) -> Result<Vec<u8>, String> {
    SeedKeyDerivation::derive_x25519_key(&seed, key_index)
}

/// Derive a 32-byte AEAD symmetric key deterministically from seed.
pub fn derive_aead_key_from_seed(seed: Vec<u8>, key_index: u32) -> Result<Vec<u8>, String> {
    SeedKeyDerivation::derive_aead_key(&seed, key_index)
}
