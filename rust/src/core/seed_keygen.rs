use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

/// Deterministic key derivation from a master seed using HKDF-SHA256.
///
/// This module provides seed-based key derivation useful for wallets
/// and key recovery scenarios. A single master seed can deterministically
/// derive multiple keys for different purposes.
pub struct SeedKeyDerivation;

impl SeedKeyDerivation {
    /// Derive key material from a master seed.
    ///
    /// * `seed` - The master seed (must be >= 32 bytes)
    /// * `purpose` - Domain separation string (e.g., "x25519-private-key", "aead-key")
    /// * `key_index` - Index for deriving multiple keys of the same purpose
    /// * `output_len` - Desired output length in bytes (max 255 * 32 = 8160)
    pub fn derive(
        seed: &[u8],
        purpose: &str,
        key_index: u32,
        output_len: usize,
    ) -> Result<Vec<u8>, String> {
        if seed.len() < 32 {
            return Err(format!(
                "Seed must be at least 32 bytes, got {}",
                seed.len()
            ));
        }
        if output_len == 0 || output_len > 8160 {
            return Err("Output length must be between 1 and 8160 bytes".to_string());
        }

        let salt = b"quantum-crypto-seed-kdf-v1";
        let hkdf = Hkdf::<Sha256>::new(Some(salt), seed);

        // Build info: purpose || key_index (big-endian)
        let mut info = Vec::with_capacity(purpose.len() + 4);
        info.extend_from_slice(purpose.as_bytes());
        info.extend_from_slice(&key_index.to_be_bytes());

        let mut okm = vec![0u8; output_len];
        hkdf.expand(&info, &mut okm)
            .map_err(|_| "HKDF expansion failed".to_string())?;
        Ok(okm)
    }

    /// Derive a 32-byte X25519 private key from seed.
    pub fn derive_x25519_key(seed: &[u8], key_index: u32) -> Result<Vec<u8>, String> {
        Self::derive(seed, "x25519-private-key", key_index, 32)
    }

    /// Derive a 32-byte AEAD symmetric key from seed.
    pub fn derive_aead_key(seed: &[u8], key_index: u32) -> Result<Vec<u8>, String> {
        Self::derive(seed, "aead-symmetric-key", key_index, 32)
    }

    /// Generate a cryptographically secure random 32-byte master seed.
    pub fn generate_seed() -> Vec<u8> {
        let mut seed = vec![0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    }
}
