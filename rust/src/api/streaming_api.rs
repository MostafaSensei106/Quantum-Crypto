use crate::api::aead_api::TargetAeadAlgorithm;
use crate::core::aead::AeadAlgorithmVariant;
use crate::core::streaming;

/// Encrypt data using streaming/chunked AEAD encryption.
/// Suitable for large files. Data is split into chunks and each chunk
/// is encrypted independently with a counter-based nonce.
///
/// * `algorithm` - AEAD algorithm to use
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `chunk_size` - Optional chunk size in bytes (default: 65536 = 64KB)
pub fn stream_aead_encrypt(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    chunk_size: Option<u32>,
) -> Result<Vec<u8>, String> {
    let variant: AeadAlgorithmVariant = algorithm.into();
    streaming::stream_encrypt(
        &key,
        &plaintext,
        variant,
        chunk_size.map(|s| s as usize),
    )
}

/// Decrypt data that was encrypted with streaming/chunked AEAD encryption.
///
/// * `key` - 32-byte decryption key
/// * `encrypted_data` - The full encrypted stream (header + chunks)
pub fn stream_aead_decrypt(
    key: Vec<u8>,
    encrypted_data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    streaming::stream_decrypt(&key, &encrypted_data)
}
