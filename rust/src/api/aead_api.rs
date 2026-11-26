//! AEAD symmetric-encryption API  FFI boundary.
//!
//! Output layout is `nonce || ciphertext+tag` (12-byte nonce, except
//! 24 bytes for [`TargetAeadAlgorithm::XChaCha20Poly1305`]).

use crate::core::aead::{AeadAlgorithmVariant, AeadEngine};

/// AEAD cipher selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetAeadAlgorithm {
    /// AES-256-GCM  fastest where AES hardware acceleration exists.
    Aes256Gcm,
    /// ChaCha20-Poly1305  fastest without AES hardware (mobile/ARM).
    ChaCha20Poly1305,
    /// XChaCha20-Poly1305  24-byte random nonce with a larger collision margin.
    XChaCha20Poly1305,
}

impl From<TargetAeadAlgorithm> for AeadAlgorithmVariant {
    fn from(target: TargetAeadAlgorithm) -> Self {
        match target {
            TargetAeadAlgorithm::Aes256Gcm => Self::Aes256Gcm,
            TargetAeadAlgorithm::ChaCha20Poly1305 => Self::ChaCha20Poly1305,
            TargetAeadAlgorithm::XChaCha20Poly1305 => Self::XChaCha20Poly1305,
        }
    }
}

/// Encrypt `plaintext` with a 32-byte `key`; returns `nonce || ciphertext+tag`.
pub fn aead_encrypt(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    aead_encrypt_with_aad(algorithm, key, plaintext, vec![])
}

/// Decrypt `ciphertext_with_nonce` (`nonce || ciphertext+tag`) with `key`.
pub fn aead_decrypt(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    ciphertext_with_nonce: Vec<u8>,
) -> Result<Vec<u8>, String> {
    aead_decrypt_with_aad(algorithm, key, ciphertext_with_nonce, vec![])
}

/// Encrypt with authenticated, unencrypted metadata.
pub fn aead_encrypt_with_aad(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let key = zeroize::Zeroizing::new(key);
    let plaintext = zeroize::Zeroizing::new(plaintext);
    crate::core::security::bounded(plaintext.len(), crate::core::security::MAX_PLAINTEXT)?;
    AeadEngine::new(algorithm.into()).encrypt_with_aad(&key, &plaintext, &associated_data)
}
/// Decrypt with the identical authenticated metadata.
pub fn aead_decrypt_with_aad(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    ciphertext_with_nonce: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let key = zeroize::Zeroizing::new(key);
    AeadEngine::new(algorithm.into()).decrypt_with_aad(
        &key,
        &ciphertext_with_nonce,
        &associated_data,
    )
}
