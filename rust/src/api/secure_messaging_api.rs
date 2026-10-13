//! Sign-then-encrypt / encrypt-then-sign messaging — FFI boundary.
//!
//! Two compositions over the same primitives (hybrid KEM + AEAD + ML-DSA):
//!
//! * **Sign-then-encrypt** ([`sign_then_encrypt`] / [`decrypt_then_verify`]):
//!   hides sender identity and the signature itself; needs the recipient key
//!   to even learn who signed.
//! * **Encrypt-then-sign** ([`encrypt_then_sign`] / [`verify_then_decrypt`]):
//!   lets anyone verify authenticity *before* decryption, at the cost of
//!   exposing the signature to observers.
//!
//! flutter_rust_bridge maps parameters 1:1 to Dart named args, so the
//! decrypt/verify entry points keep flat argument lists by design
//! (grouping them into a struct would break the generated bindings).

use crate::api::aead_api::TargetAeadAlgorithm;
use crate::api::dsa_api::TargetDsaAlgorithm;
use crate::api::hybrid_kem_api::TargetHybridKemAlgorithm;
use crate::core::aead::AeadEngine;
use crate::core::hybrid_kem::HybridKemEngine;
use crate::factory::dsa_factory::DsaFactory;

/// Length-prefix width (bytes) of the embedded message in sign-then-encrypt payloads.
const MSG_LEN_PREFIX: usize = 4;

/// Encrypted package produced by [`sign_then_encrypt`].
pub struct SecurePackageDto {
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub dsa_algorithm: TargetDsaAlgorithm,
    pub kem_algorithm: TargetHybridKemAlgorithm,
    pub aead_algorithm: TargetAeadAlgorithm,
}

/// Encrypted package produced by [`encrypt_then_sign`].
pub struct EncryptThenSignPackageDto {
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub dsa_algorithm: TargetDsaAlgorithm,
    pub kem_algorithm: TargetHybridKemAlgorithm,
    pub aead_algorithm: TargetAeadAlgorithm,
}

/// Pack `message || signature` with a 4-byte big-endian message length prefix.
fn encode_signed_payload(message: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(MSG_LEN_PREFIX + message.len() + signature.len());
    payload.extend_from_slice(&(message.len() as u32).to_be_bytes());
    payload.extend_from_slice(message);
    payload.extend_from_slice(signature);
    payload
}

/// Split a [`encode_signed_payload`] payload back into message + signature.
fn decode_signed_payload(payload: &[u8]) -> Result<(&[u8], &[u8]), String> {
    if payload.len() < MSG_LEN_PREFIX {
        return Err("Payload too short".to_string());
    }
    let mut len_bytes = [0u8; MSG_LEN_PREFIX];
    len_bytes.copy_from_slice(&payload[..MSG_LEN_PREFIX]);
    let msg_len = u32::from_be_bytes(len_bytes) as usize;
    if payload.len() < MSG_LEN_PREFIX + msg_len {
        return Err("Invalid payload structure".to_string());
    }
    Ok((
        &payload[MSG_LEN_PREFIX..MSG_LEN_PREFIX + msg_len],
        &payload[MSG_LEN_PREFIX + msg_len..],
    ))
}

/// The three outputs of a hybrid encapsulation: both ciphertext halves plus
/// the derived shared secret.
struct EncapsulationParts {
    mlkem_ciphertext: Vec<u8>,
    x25519_ephemeral_pk: Vec<u8>,
    shared_secret: Vec<u8>,
}

fn encapsulate_to(
    kem_algorithm: TargetHybridKemAlgorithm,
    mlkem_public_key: &[u8],
    x25519_public_key: &[u8],
) -> Result<EncapsulationParts, String> {
    let result = HybridKemEngine::new(kem_algorithm.into())
        .encapsulate(mlkem_public_key, x25519_public_key)?;
    Ok(EncapsulationParts {
        mlkem_ciphertext: result.mlkem_ciphertext,
        x25519_ephemeral_pk: result.x25519_ephemeral_pk,
        shared_secret: result.shared_secret,
    })
}

fn decapsulate_with(
    kem_algorithm: TargetHybridKemAlgorithm,
    mlkem_ciphertext: &[u8],
    x25519_ephemeral_pk: &[u8],
    mlkem_secret_key: &[u8],
    x25519_secret_key: &[u8],
) -> Result<Vec<u8>, String> {
    HybridKemEngine::new(kem_algorithm.into()).decapsulate(
        mlkem_ciphertext,
        x25519_ephemeral_pk,
        mlkem_secret_key,
        x25519_secret_key,
    )
}

/// Sign `message`, then encrypt (`message || signature`) to the recipient's
/// hybrid KEM public keys.
pub fn sign_then_encrypt(
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    message: Vec<u8>,
    sender_dsa_secret_key: Vec<u8>,
    recipient_mlkem_public_key: Vec<u8>,
    recipient_x25519_public_key: Vec<u8>,
) -> Result<SecurePackageDto, String> {
    let signature =
        DsaFactory::create_strategy(dsa_algorithm.into()).sign(&message, &sender_dsa_secret_key)?;
    let payload = encode_signed_payload(&message, &signature);

    let parts = encapsulate_to(
        kem_algorithm,
        &recipient_mlkem_public_key,
        &recipient_x25519_public_key,
    )?;
    let encrypted_payload =
        AeadEngine::new(aead_algorithm.into()).encrypt(&parts.shared_secret, &payload)?;

    Ok(SecurePackageDto {
        mlkem_ciphertext: parts.mlkem_ciphertext,
        x25519_ephemeral_pk: parts.x25519_ephemeral_pk,
        encrypted_payload,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
    })
}

// Flat args for Dart codegen compatibility (see module docs).
#[allow(clippy::too_many_arguments)]
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
    let shared_secret = decapsulate_with(
        kem_algorithm,
        &package_mlkem_ciphertext,
        &package_x25519_ephemeral_pk,
        &recipient_mlkem_secret_key,
        &recipient_x25519_secret_key,
    )?;
    let payload = AeadEngine::new(aead_algorithm.into())
        .decrypt(&shared_secret, &package_encrypted_payload)?;
    let (message, signature) = decode_signed_payload(&payload)?;

    let valid = DsaFactory::create_strategy(dsa_algorithm.into()).verify(
        message,
        signature,
        &sender_dsa_public_key,
    )?;
    if valid {
        Ok(message.to_vec())
    } else {
        Err("Signature verification failed".to_string())
    }
}

/// Encrypt `message` to the recipient, then sign the ciphertext so anyone
/// can verify authenticity before decryption.
pub fn encrypt_then_sign(
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    message: Vec<u8>,
    sender_dsa_secret_key: Vec<u8>,
    recipient_mlkem_public_key: Vec<u8>,
    recipient_x25519_public_key: Vec<u8>,
) -> Result<EncryptThenSignPackageDto, String> {
    let parts = encapsulate_to(
        kem_algorithm,
        &recipient_mlkem_public_key,
        &recipient_x25519_public_key,
    )?;
    let encrypted_payload =
        AeadEngine::new(aead_algorithm.into()).encrypt(&parts.shared_secret, &message)?;
    let signature = DsaFactory::create_strategy(dsa_algorithm.into())
        .sign(&encrypted_payload, &sender_dsa_secret_key)?;

    Ok(EncryptThenSignPackageDto {
        mlkem_ciphertext: parts.mlkem_ciphertext,
        x25519_ephemeral_pk: parts.x25519_ephemeral_pk,
        encrypted_payload,
        signature,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
    })
}

// Flat args for Dart codegen compatibility (see module docs).
#[allow(clippy::too_many_arguments)]
pub fn verify_then_decrypt(
    package_mlkem_ciphertext: Vec<u8>,
    package_x25519_ephemeral_pk: Vec<u8>,
    package_encrypted_payload: Vec<u8>,
    package_signature: Vec<u8>,
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    recipient_mlkem_secret_key: Vec<u8>,
    recipient_x25519_secret_key: Vec<u8>,
    sender_dsa_public_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let valid = DsaFactory::create_strategy(dsa_algorithm.into()).verify(
        &package_encrypted_payload,
        &package_signature,
        &sender_dsa_public_key,
    )?;
    if !valid {
        return Err("Signature verification failed".to_string());
    }

    let shared_secret = decapsulate_with(
        kem_algorithm,
        &package_mlkem_ciphertext,
        &package_x25519_ephemeral_pk,
        &recipient_mlkem_secret_key,
        &recipient_x25519_secret_key,
    )?;
    AeadEngine::new(aead_algorithm.into()).decrypt(&shared_secret, &package_encrypted_payload)
}
