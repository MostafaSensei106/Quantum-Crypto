use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};

/// AEAD cipher selection.
///
/// Wire format is `nonce || ciphertext+tag`, where the nonce is 12 bytes
/// for [`AeadAlgorithmVariant::Aes256Gcm`] and
/// [`AeadAlgorithmVariant::ChaCha20Poly1305`], and 24 bytes for
/// [`AeadAlgorithmVariant::XChaCha20Poly1305`]. The variant is always
/// explicit at both encrypt and decrypt time, so the layout is unambiguous.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlgorithmVariant {
    Aes256Gcm,
    ChaCha20Poly1305,
    /// Extended-nonce variant: safe to use with random nonces, no counter needed.
    XChaCha20Poly1305,
}

impl AeadAlgorithmVariant {
    /// Length of the random nonce prepended to every ciphertext.
    #[must_use]
    pub fn nonce_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }
}

pub struct AeadEngine {
    variant: AeadAlgorithmVariant,
}

impl AeadEngine {
    pub fn new(variant: AeadAlgorithmVariant) -> Self {
        Self { variant }
    }

    fn check_key(key: &[u8]) -> Result<(), String> {
        if key.len() != 32 {
            return Err(format!("Key must be 32 bytes, got {}", key.len()));
        }
        Ok(())
    }

    pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        Self::check_key(key)?;

        let nonce_len = self.variant.nonce_len();
        let mut nonce_bytes = vec![0u8; nonce_len];
        OsRng.fill_bytes(&mut nonce_bytes);

        let ciphertext = match self.variant {
            AeadAlgorithmVariant::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {e}"))?;
                cipher
                    .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
                    .map_err(|e| format!("Encryption failed: {e}"))?
            }
            AeadAlgorithmVariant::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {e}"))?;
                cipher
                    .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
                    .map_err(|e| format!("Encryption failed: {e}"))?
            }
            AeadAlgorithmVariant::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {e}"))?;
                cipher
                    .encrypt(XNonce::from_slice(&nonce_bytes), plaintext)
                    .map_err(|e| format!("Encryption failed: {e}"))?
            }
        };

        let mut result = Vec::with_capacity(nonce_len + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt(&self, key: &[u8], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>, String> {
        Self::check_key(key)?;

        // Ciphertext must hold at least nonce + 16-byte Poly1305/GMAC tag.
        let min_len = self.variant.nonce_len() + 16;
        if ciphertext_with_nonce.len() < min_len {
            return Err(format!(
                "Ciphertext too short: got {} bytes, need at least {min_len} (nonce + tag)",
                ciphertext_with_nonce.len()
            ));
        }

        let nonce_len = self.variant.nonce_len();
        let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(nonce_len);

        match self.variant {
            AeadAlgorithmVariant::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {e}"))?;
                cipher
                    .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
                    .map_err(|e| format!("Decryption failed: {e}"))
            }
            AeadAlgorithmVariant::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {e}"))?;
                cipher
                    .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
                    .map_err(|e| format!("Decryption failed: {e}"))
            }
            AeadAlgorithmVariant::XChaCha20Poly1305 => {
                let cipher = XChaCha20Poly1305::new_from_slice(key)
                    .map_err(|e| format!("Invalid key length: {e}"))?;
                cipher
                    .decrypt(XNonce::from_slice(nonce_bytes), ciphertext)
                    .map_err(|e| format!("Decryption failed: {e}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(variant: AeadAlgorithmVariant) {
        let engine = AeadEngine::new(variant);
        let key = vec![0x42u8; 32];
        let plaintext = b"quantum-safe payload";
        let ct = engine.encrypt(&key, plaintext).unwrap();
        assert_eq!(&ct[..variant.nonce_len()], &ct[..variant.nonce_len()]);
        let pt = engine.decrypt(&key, &ct).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn roundtrip_all_variants() {
        roundtrip(AeadAlgorithmVariant::Aes256Gcm);
        roundtrip(AeadAlgorithmVariant::ChaCha20Poly1305);
        roundtrip(AeadAlgorithmVariant::XChaCha20Poly1305);
    }

    #[test]
    fn rejects_short_key_and_truncated_ciphertext() {
        let engine = AeadEngine::new(AeadAlgorithmVariant::XChaCha20Poly1305);
        assert!(engine.encrypt(&[0u8; 16], b"x").is_err());
        assert!(engine.decrypt(&[0u8; 32], &[0u8; 20]).is_err());
    }
}
