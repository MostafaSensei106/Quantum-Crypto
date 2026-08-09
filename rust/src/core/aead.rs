use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand_core::{OsRng, RngCore};

#[derive(Clone, Copy)]
pub enum AeadAlgorithmVariant {
    Aes256Gcm,
    ChaCha20Poly1305,
}

pub struct AeadEngine {
    variant: AeadAlgorithmVariant,
}

impl AeadEngine {
    pub fn new(variant: AeadAlgorithmVariant) -> Self {
        Self { variant }
    }

    pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key must be 32 bytes".to_string());
        }

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let ciphertext = match self.variant {
            AeadAlgorithmVariant::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {}", e))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| format!("Encryption failed: {}", e))?
            }
            AeadAlgorithmVariant::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {}", e))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| format!("Encryption failed: {}", e))?
            }
        };

        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, key: &[u8], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, String> {
        if key.len() != 32 {
            return Err("Key must be 32 bytes".to_string());
        }
        if ciphertext_with_nonce.len() < 28 {
            return Err("Ciphertext too short (must contain nonce and tag)".to_string());
        }

        let nonce_bytes = &ciphertext_with_nonce[..12];
        let ciphertext = &ciphertext_with_nonce[12..];
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        let plaintext = match self.variant {
            AeadAlgorithmVariant::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {}", e))?;
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| format!("Decryption failed: {}", e))?
            }
            AeadAlgorithmVariant::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {}", e))?;
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| format!("Decryption failed: {}", e))?
            }
        };

        Ok(plaintext)
    }
}
