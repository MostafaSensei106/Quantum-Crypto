use crate::core::aead::{AeadAlgorithmVariant, AeadEngine};

#[derive(Clone, Copy)]
pub enum TargetAeadAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl From<TargetAeadAlgorithm> for AeadAlgorithmVariant {
    fn from(target: TargetAeadAlgorithm) -> Self {
        match target {
            TargetAeadAlgorithm::Aes256Gcm => AeadAlgorithmVariant::Aes256Gcm,
            TargetAeadAlgorithm::ChaCha20Poly1305 => AeadAlgorithmVariant::ChaCha20Poly1305,
        }
    }
}

pub fn aead_encrypt(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let engine = AeadEngine::new(algorithm.into());
    engine.encrypt(&key, &plaintext)
}

pub fn aead_decrypt(
    algorithm: TargetAeadAlgorithm,
    key: Vec<u8>,
    ciphertext_with_nonce: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let engine = AeadEngine::new(algorithm.into());
    engine.decrypt(&key, &ciphertext_with_nonce)
}
