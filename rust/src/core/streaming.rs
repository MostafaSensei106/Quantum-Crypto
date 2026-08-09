use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use crate::core::aead::AeadAlgorithmVariant;

const DEFAULT_CHUNK_SIZE: usize = 64 * 1024; // 64 KB
const STREAM_VERSION: u8 = 1;

pub struct StreamHeader {
    pub version: u8,
    pub chunk_size: u32,
    pub total_chunks: u32,
    pub algorithm: u8,
}

impl StreamHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(10);
        bytes.push(self.version);
        bytes.extend_from_slice(&self.chunk_size.to_be_bytes());
        bytes.extend_from_slice(&self.total_chunks.to_be_bytes());
        bytes.push(self.algorithm);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 10 {
            return Err("Stream header too short".to_string());
        }
        let version = data[0];
        if version != STREAM_VERSION {
            return Err(format!("Unsupported stream version: {}", version));
        }
        let chunk_size = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let total_chunks = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
        let algorithm = data[9];
        Ok(Self { version, chunk_size, total_chunks, algorithm })
    }

    pub fn byte_len() -> usize { 10 }
}

fn algorithm_to_byte(variant: AeadAlgorithmVariant) -> u8 {
    match variant {
        AeadAlgorithmVariant::Aes256Gcm => 0,
        AeadAlgorithmVariant::ChaCha20Poly1305 => 1,
    }
}

fn byte_to_algorithm(byte: u8) -> Result<AeadAlgorithmVariant, String> {
    match byte {
        0 => Ok(AeadAlgorithmVariant::Aes256Gcm),
        1 => Ok(AeadAlgorithmVariant::ChaCha20Poly1305),
        _ => Err(format!("Unknown algorithm byte: {}", byte)),
    }
}

/// Generate a counter-based nonce for a given chunk index.
fn chunk_nonce(chunk_index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // Put chunk index in the last 4 bytes (big-endian)
    nonce[8..12].copy_from_slice(&chunk_index.to_be_bytes());
    nonce
}

pub fn stream_encrypt(
    key: &[u8],
    plaintext: &[u8],
    variant: AeadAlgorithmVariant,
    chunk_size: Option<usize>,
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }

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

    // Estimate output size: header + (nonce + chunk + tag) * num_chunks
    let overhead_per_chunk = 12 + 16; // nonce + AEAD tag
    let estimated_size = StreamHeader::byte_len()
        + chunks.iter().map(|c| overhead_per_chunk + c.len()).sum::<usize>();
    let mut output = Vec::with_capacity(estimated_size);
    output.extend_from_slice(&header.to_bytes());

    for (i, chunk) in chunks.iter().enumerate() {
        let nonce_bytes = chunk_nonce(i as u32);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let encrypted = match variant {
            AeadAlgorithmVariant::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| format!("Invalid key: {}", e))?;
                cipher.encrypt(nonce, *chunk)
                    .map_err(|e| format!("Chunk {} encryption failed: {}", i, e))?
            }
            AeadAlgorithmVariant::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key: {}", e))?;
                cipher.encrypt(nonce, *chunk)
                    .map_err(|e| format!("Chunk {} encryption failed: {}", i, e))?
            }
        };

        // Write nonce + encrypted data (which includes tag)
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&encrypted);
    }

    Ok(output)
}

pub fn stream_decrypt(
    key: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".to_string());
    }
    if data.len() < StreamHeader::byte_len() {
        return Err("Data too short for stream header".to_string());
    }

    let header = StreamHeader::from_bytes(&data[..StreamHeader::byte_len()])?;
    let variant = byte_to_algorithm(header.algorithm)?;
    let mut offset = StreamHeader::byte_len();
    let mut plaintext = Vec::new();

    for i in 0..header.total_chunks {
        if offset + 12 > data.len() {
            return Err(format!("Unexpected end of data at chunk {}", i));
        }

        let nonce_bytes = &data[offset..offset + 12];
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        offset += 12;

        // Determine encrypted chunk size
        let is_last = i == header.total_chunks - 1;
        let remaining_data = data.len() - offset;

        let encrypted_chunk_size = if is_last {
            remaining_data
        } else {
            // chunk_size + 16 (AEAD tag)
            header.chunk_size as usize + 16
        };

        if offset + encrypted_chunk_size > data.len() {
            return Err(format!("Chunk {} extends beyond data", i));
        }

        let encrypted_chunk = &data[offset..offset + encrypted_chunk_size];
        offset += encrypted_chunk_size;

        let decrypted = match variant {
            AeadAlgorithmVariant::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| format!("Invalid key: {}", e))?;
                cipher.decrypt(nonce, encrypted_chunk)
                    .map_err(|e| format!("Chunk {} decryption failed: {}", i, e))?
            }
            AeadAlgorithmVariant::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key: {}", e))?;
                cipher.decrypt(nonce, encrypted_chunk)
                    .map_err(|e| format!("Chunk {} decryption failed: {}", i, e))?
            }
        };

        plaintext.extend_from_slice(&decrypted);
    }

    Ok(plaintext)
}
