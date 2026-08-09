use crate::api::aead_api::TargetAeadAlgorithm;
use crate::api::dsa_api::TargetDsaAlgorithm;
use crate::api::hybrid_kem_api::TargetHybridKemAlgorithm;
use crate::core::aead::AeadEngine;
use crate::core::hybrid_kem::HybridKemEngine;
use crate::factory::dsa_factory::DsaFactory;

pub struct SecurePackageDto {
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub dsa_algorithm: TargetDsaAlgorithm,
    pub kem_algorithm: TargetHybridKemAlgorithm,
    pub aead_algorithm: TargetAeadAlgorithm,
}

pub fn sign_then_encrypt(
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    message: Vec<u8>,
    sender_dsa_secret_key: Vec<u8>,
    recipient_mlkem_public_key: Vec<u8>,
    recipient_x25519_public_key: Vec<u8>,
) -> Result<SecurePackageDto, String> {
    // 1. Sign
    let dsa_strategy = DsaFactory::create_strategy(dsa_algorithm.into());
    let signature = dsa_strategy.sign(&message, &sender_dsa_secret_key)?;

    // 2. Prepare payload
    let msg_len = message.len() as u32;
    let mut payload = Vec::with_capacity(4 + message.len() + signature.len());
    payload.extend_from_slice(&msg_len.to_be_bytes());
    payload.extend_from_slice(&message);
    payload.extend_from_slice(&signature);

    // 3. Encapsulate
    let kem_engine = HybridKemEngine::new(kem_algorithm.into());
    let enc_result =
        kem_engine.encapsulate(&recipient_mlkem_public_key, &recipient_x25519_public_key)?;

    // 4. Encrypt payload
    let aead_engine = AeadEngine::new(aead_algorithm.into());
    let encrypted_payload = aead_engine.encrypt(&enc_result.shared_secret, &payload)?;

    Ok(SecurePackageDto {
        mlkem_ciphertext: enc_result.mlkem_ciphertext,
        x25519_ephemeral_pk: enc_result.x25519_ephemeral_pk,
        encrypted_payload,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
    })
}

pub fn decrypt_then_verify(
    package_mlkem_ciphertext: Vec<u8>,
    package_x25519_ephemeral_pk: Vec<u8>,
    package_encrypted_payload: Vec<u8>,
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    recipient_mlkem_secret_key: Vec<u8>,
    recipient_x25519_secret_key: Vec<u8>,
    sender_dsa_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    // 1. Decapsulate
    let kem_engine = HybridKemEngine::new(kem_algorithm.into());
    let shared_secret = kem_engine.decapsulate(
        &package_mlkem_ciphertext,
        &package_x25519_ephemeral_pk,
        &recipient_mlkem_secret_key,
        &recipient_x25519_secret_key,
    )?;

    // 2. Decrypt
    let aead_engine = AeadEngine::new(aead_algorithm.into());
    let payload = aead_engine.decrypt(&shared_secret, &package_encrypted_payload)?;

    if payload.len() < 4 {
        return Err("Payload too short".to_string());
    }

    // 3. Extract length and split
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&payload[0..4]);
    let msg_len = u32::from_be_bytes(len_bytes) as usize;

    if payload.len() < 4 + msg_len {
        return Err("Invalid payload structure".to_string());
    }

    let message = &payload[4..4 + msg_len];
    let signature = &payload[4 + msg_len..];

    // 4. Verify
    let dsa_strategy = DsaFactory::create_strategy(dsa_algorithm.into());
    let is_valid = dsa_strategy.verify(message, signature, &sender_dsa_public_key)?;

    if is_valid {
        Ok(message.to_vec())
    } else {
        Err("Signature verification failed".to_string())
    }
}
