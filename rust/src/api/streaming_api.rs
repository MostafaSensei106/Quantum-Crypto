//! In-memory chunked AEAD v2. Requires the complete input and output buffers.
//! Uses authenticated STREAM segments and rejects legacy v1.

use crate::api::aead_api::TargetAeadAlgorithm;
use crate::core::aead::AeadAlgorithmVariant;
use crate::core::streaming;

/// Encrypt `plaintext` in chunks.
///
/// * `chunk_size`  chunk size in bytes; defaults to 64 KiB when `None`.
pub fn stream_aead_encrypt(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    chunk_size: Option<u32>,
) -> Result<Vec<u8>, String> {
    let key = zeroize::Zeroizing::new(key);
    let plaintext = zeroize::Zeroizing::new(plaintext);
    let variant: AeadAlgorithmVariant = algorithm.into();
    streaming::stream_encrypt(&key, &plaintext, variant, chunk_size.map(|s| s as usize))
}

/// Decrypt a stream produced by [`stream_aead_encrypt`].
pub fn stream_aead_decrypt(key: Vec<u8>, encrypted_data: Vec<u8>) -> Result<Vec<u8>, String> {
    let key = zeroize::Zeroizing::new(key);
    streaming::stream_decrypt(&key, &encrypted_data)
}
