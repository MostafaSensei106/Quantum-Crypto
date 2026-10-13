use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};

use crate::core::aead::AeadAlgorithmVariant;

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
const STREAM_VERSION: u8 = 1;

/// On-wire stream header: version (1B) || chunk_size (4B) || total_chunks (4B) || algorithm (1B).
pub struct StreamHeader {
    pub version: u8,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub algorithm: u8,
}

impl StreamHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::byte_len());
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chunk_size.to_be_bytes());
        bytes.extend_from_slice(&self.total_chunks.to_be_bytes());
        bytes.push(self.algorithm);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::byte_len() {
            return Err("Stream header too short".to_string());
        }
        let version = data[0];
        if version != STREAM_VERSION {
            return Err(format!("Unsupported stream version: {version}"));
        }
        let chunk_size = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let total_chunks = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
        let algorithm = data[9];
        Ok(Self {
            version,
            chunk_size,
            total_chunks,
            algorithm,
        })
    }

    pub fn byte_len() -> usize {
        10
    }
}

fn algorithm_to_byte(variant: AeadAlgorithmVariant) -> u8 {
    match variant {
        AeadAlgorithmVariant::Aes256Gcm => 0,
        AeadAlgorithmVariant::ChaCha20Poly1305 => 1,
        AeadAlgorithmVariant::XChaCha20Poly1305 => 2,
    }
}

fn byte_to_algorithm(byte: u8) -> Result<AeadAlgorithmVariant, String> {
    match byte {
        0 => Ok(AeadAlgorithmVariant::Aes256Gcm),
        1 => Ok(AeadAlgorithmVariant::ChaCha20Poly1305),
        2 => Ok(AeadAlgorithmVariant::XChaCha20Poly1305),
        _ => Err(format!("Unknown algorithm byte: {byte}")),
    }
}

/// Counter-based nonce for a chunk: zero-padded with the chunk index in the
/// last 4 bytes (big-endian). Length matches the cipher (12 or 24 bytes).
fn chunk_nonce(variant: AeadAlgorithmVariant, chunk_index: u32) -> Vec<u8> {
    let mut nonce = vec![0u8; variant.nonce_len()];
    let start = nonce.len() - 4;
    nonce[start..].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

fn encrypt_chunk(
    variant: AeadAlgorithmVariant,
    key: &[u8],
    nonce_bytes: &[u8],
    chunk: &[u8],
    chunk_index: usize,
) -> Result<Vec<u8>, String> {
    let map_err = |e: aes_gcm::Error| format!("Chunk {chunk_index} encryption failed: {e}");
    match variant {
        AeadAlgorithmVariant::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
            cipher
                .encrypt(Nonce::from_slice(nonce_bytes), chunk)
                .map_err(map_err)
        }
        AeadAlgorithmVariant::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
            cipher
                .encrypt(Nonce::from_slice(nonce_bytes), chunk)
                .map_err(map_err)
        }
        AeadAlgorithmVariant::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
            cipher
                .encrypt(XNonce::from_slice(nonce_bytes), chunk)
                .map_err(map_err)
        }
    }
}

fn decrypt_chunk(
    variant: AeadAlgorithmVariant,
    key: &[u8],
    nonce_bytes: &[u8],
    encrypted_chunk: &[u8],
    chunk_index: u32,
) -> Result<Vec<u8>, String> {
    let map_err = |e: aes_gcm::Error| format!("Chunk {chunk_index} decryption failed: {e}");
    match variant {
        AeadAlgorithmVariant::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
            cipher
                .decrypt(Nonce::from_slice(nonce_bytes), encrypted_chunk)
                .map_err(map_err)
        }
        AeadAlgorithmVariant::ChaCha20Poly1305 => {
            let cipher =
                ChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
            cipher
                .decrypt(Nonce::from_slice(nonce_bytes), encrypted_chunk)
                .map_err(map_err)
        }
        AeadAlgorithmVariant::XChaCha20Poly1305 => {
            let cipher =
                XChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("Invalid key: {e}"))?;
            cipher
                .decrypt(XNonce::from_slice(nonce_bytes), encrypted_chunk)
                .map_err(map_err)
        }
    }
}

fn check_key(key: &[u8]) -> Result<(), String> {
    if key.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", key.len()));
    }
    Ok(())
}

pub fn stream_encrypt(
    key: &[u8],
    plaintext: &[u8],
    variant: AeadAlgorithmVariant,
    chunk_size: Option<usize>,
) -> Result<Vec<u8>, String> {
    check_key(key)?;

    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 {
        return Err("Chunk size must be > 0".to_string());
    }

    let chunks: Vec<&[u8]> = plaintext.chunks(chunk_size).collect();
    let total_chunks = chunks.len() as u32;

    let header = StreamHeader {
        version: STREAM_VERSION,
        chunk_size: chunk_size as u32,
        total_chunks,
        algorithm: algorithm_to_byte(variant),
    };

    // Estimate output size: header + (nonce + chunk + tag) * num_chunks.
    let nonce_len = variant.nonce_len();
    let overhead_per_chunk = nonce_len + 16; // nonce + AEAD tag
    let estimated_size = StreamHeader::byte_len()
        + chunks
            .iter()
            .map(|c| overhead_per_chunk + c.len())
            .sum::<usize>();
    let mut output = Vec::with_capacity(estimated_size);
    output.extend_from_slice(&header.to_bytes());

    for (i, chunk) in chunks.iter().enumerate() {
        let nonce_bytes = chunk_nonce(variant, i as u32);
        let encrypted = encrypt_chunk(variant, key, &nonce_bytes, chunk, i)?;
        // Write nonce + encrypted data (which includes the tag).
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&encrypted);
    }

    Ok(output)
}

pub fn stream_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    check_key(key)?;
    if data.len() < StreamHeader::byte_len() {
        return Err("Data too short for stream header".to_string());
    }

    let header = StreamHeader::from_bytes(&data[..StreamHeader::byte_len()])?;
    let variant = byte_to_algorithm(header.algorithm)?;
    let nonce_len = variant.nonce_len();
    let mut offset = StreamHeader::byte_len();
    let mut plaintext = Vec::new();

    for i in 0..header.total_chunks {
        if offset + nonce_len > data.len() {
            return Err(format!("Unexpected end of data at chunk {i}"));
        }

        let nonce_bytes = &data[offset..offset + nonce_len];
        offset += nonce_len;

        // Determine encrypted chunk size: every chunk but the last carries a
        // full plaintext chunk plus the 16-byte AEAD tag.
        let encrypted_chunk_size = if i == header.total_chunks - 1 {
            data.len() - offset
        } else {
            header.chunk_size as usize + 16
        };

        if offset + encrypted_chunk_size > data.len() {
            return Err(format!("Chunk {i} extends beyond data"));
        }

        let encrypted_chunk = &data[offset..offset + encrypted_chunk_size];
        offset += encrypted_chunk_size;

        let decrypted = decrypt_chunk(variant, key, nonce_bytes, encrypted_chunk, i)?;
        plaintext.extend_from_slice(&decrypted);
    }

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_variants() {
        let key = vec![0x77u8; 32];
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        for variant in [
            AeadAlgorithmVariant::Aes256Gcm,
            AeadAlgorithmVariant::ChaCha20Poly1305,
            AeadAlgorithmVariant::XChaCha20Poly1305,
        ] {
            let enc = stream_encrypt(&key, &data, variant, Some(32_768)).unwrap();
            let dec = stream_decrypt(&key, &enc).unwrap();
            assert_eq!(dec, data);
        }
    }
}
