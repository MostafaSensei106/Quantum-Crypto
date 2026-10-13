//! Chunked (streaming) AEAD encryption — FFI boundary.
//!
//! Large payloads are split into independently-encrypted chunks with
//! counter-based nonces, so encryption never holds the whole plaintext
//! plus ciphertext in memory at once. Output is self-describing
//! (header + chunks); [`stream_aead_decrypt`] reads the algorithm back
//! from the header, including streams written before XChaCha20-Poly1305
//! existed.

use crate::api::aead_api::TargetAeadAlgorithm;
use crate::core::aead::AeadAlgorithmVariant;
use crate::core::streaming;

/// Encrypt `plaintext` in chunks.
///
/// * `chunk_size` — chunk size in bytes; defaults to 64 KiB when `None`.
pub fn stream_aead_encrypt(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    chunk_size: Option<u32>,
) -> Result<Vec<u8>, String> {
    let variant: AeadAlgorithmVariant = algorithm.into();
    streaming::stream_encrypt(&key, &plaintext, variant, chunk_size.map(|s| s as usize))
}

/// Decrypt a stream produced by [`stream_aead_encrypt`].
pub fn stream_aead_decrypt(key: Vec<u8>, encrypted_data: Vec<u8>) -> Result<Vec<u8>, String> {
    streaming::stream_decrypt(&key, &encrypted_data)
}
