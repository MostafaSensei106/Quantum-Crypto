//! Experimental v2 message protection. Identity, sessions and replay policy belong to the application.
//! Signatures authenticate a domain-separated SHA-256 transcript digest (not ML-DSA HashML-DSA).
use crate::api::{
    aead_api::TargetAeadAlgorithm, dsa_api::TargetDsaAlgorithm,
    hybrid_kem_api::TargetHybridKemAlgorithm,
};
use crate::core::{aead::AeadEngine, hybrid_kem::HybridKemEngine, security::*};
use crate::factory::dsa_factory::DsaFactory;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub struct SecurePackageDto {
    pub version: u8,
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub dsa_algorithm: TargetDsaAlgorithm,
    pub kem_algorithm: TargetHybridKemAlgorithm,
    pub aead_algorithm: TargetAeadAlgorithm,
}
pub struct EncryptThenSignPackageDto {
    pub version: u8,
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
    pub signature: Vec<u8>,
    pub dsa_algorithm: TargetDsaAlgorithm,
    pub kem_algorithm: TargetHybridKemAlgorithm,
    pub aead_algorithm: TargetAeadAlgorithm,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn context(
    mode: u8,
    dsa: TargetDsaAlgorithm,
    kem: TargetHybridKemAlgorithm,
    aead: TargetAeadAlgorithm,
    sender: &[u8],
    recipient_ml: &[u8],
    recipient_x: &[u8],
    ct: &[u8],
    ephemeral: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    bounded(aad.len(), MAX_AAD)?;
    let mut ctx = b"Quantum-Crypto/Message/v2".to_vec();
    ctx.extend_from_slice(&[
        2,
        mode,
        match dsa {
            TargetDsaAlgorithm::MlDsa44 => 0,
            TargetDsaAlgorithm::MlDsa65 => 1,
            TargetDsaAlgorithm::MlDsa87 => 2,
        },
        match kem {
            TargetHybridKemAlgorithm::MlKem512X25519 => 0,
            TargetHybridKemAlgorithm::MlKem768X25519 => 1,
            TargetHybridKemAlgorithm::MlKem1024X25519 => 2,
        },
        match aead {
            TargetAeadAlgorithm::Aes256Gcm => 0,
            TargetAeadAlgorithm::ChaCha20Poly1305 => 1,
            TargetAeadAlgorithm::XChaCha20Poly1305 => 2,
        },
    ]);
    for field in [sender, recipient_ml, recipient_x, ct, ephemeral, aad] {
        append_field(&mut ctx, field)?;
    }
    Ok(Sha256::digest(ctx).to_vec())
}
fn signed_digest(ctx: &[u8], body: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"Quantum-Crypto/Message/v2/signature");
    h.update(ctx);
    h.update((body.len() as u64).to_be_bytes());
    h.update(body);
    h.finalize().to_vec()
}
fn encode_signed_payload(message: &[u8], signature: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    bounded(message.len(), MAX_PLAINTEXT)?;
    let size = 4usize
        .checked_add(message.len())
        .and_then(|n| n.checked_add(signature.len()))
        .ok_or("Payload overflow")?;
    bounded(size, MAX_ENCODED)?;
    let mut p = Zeroizing::new(Vec::new());
    p.try_reserve_exact(size).map_err(|_| "Allocation failed")?;
    p.extend_from_slice(
        &u32::try_from(message.len())
            .map_err(|_| "Message too long")?
            .to_be_bytes(),
    );
    p.extend_from_slice(message);
    p.extend_from_slice(signature);
    Ok(p)
}
use crate::core::security::decode_signed_payload;

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub(crate) fn seal(
    mode: u8,
    dsa: TargetDsaAlgorithm,
    kem: TargetHybridKemAlgorithm,
    aead: TargetAeadAlgorithm,
    message: &[u8],
    sender_sk: &[u8],
    sender_pk: &[u8],
    recipient_ml: &[u8],
    recipient_x: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), String> {
    bounded(message.len(), MAX_PLAINTEXT)?;
    let parts = HybridKemEngine::new(kem.into()).encapsulate(recipient_ml, recipient_x)?;
    let shared = Zeroizing::new(parts.shared_secret);
    let ctx = context(
        mode,
        dsa,
        kem,
        aead,
        sender_pk,
        recipient_ml,
        recipient_x,
        &parts.mlkem_ciphertext,
        &parts.x25519_ephemeral_pk,
        aad,
    )?;
    let signer = DsaFactory::create_strategy(dsa.into());
    let (encrypted, signature) = if mode == 0 {
        let digest = signed_digest(&ctx, message);
        let sig = signer.sign(&digest, sender_sk)?;
        if !signer.verify(&digest, &sig, sender_pk)? {
            return Err("Sender key binding mismatch".into());
        }
        let payload = encode_signed_payload(message, &sig)?;
        (
            AeadEngine::new(aead.into()).encrypt_with_aad(&shared, &payload, &ctx)?,
            vec![],
        )
    } else {
        let encrypted = AeadEngine::new(aead.into()).encrypt_with_aad(&shared, message, &ctx)?;
        let digest = signed_digest(&ctx, &encrypted);
        let sig = signer.sign(&digest, sender_sk)?;
        if !signer.verify(&digest, &sig, sender_pk)? {
            return Err("Sender key binding mismatch".into());
        }
        (encrypted, sig)
    };
    Ok((
        parts.mlkem_ciphertext,
        parts.x25519_ephemeral_pk,
        encrypted,
        signature,
    ))
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn open(
    mode: u8,
    version: u8,
    dsa: TargetDsaAlgorithm,
    kem: TargetHybridKemAlgorithm,
    aead: TargetAeadAlgorithm,
    ct: &[u8],
    ephemeral: &[u8],
    encrypted: &[u8],
    signature: &[u8],
    recipient_ml_sk: &[u8],
    recipient_x_sk: &[u8],
    recipient_ml_pk: &[u8],
    recipient_x_pk: &[u8],
    sender_pk: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if version != 2 {
        return Err("Unsupported message version (v2 required)".into());
    }
    bounded(encrypted.len(), MAX_ENCODED + 40)?;
    bounded(signature.len(), 65536)?;
    let ctx = context(
        mode,
        dsa,
        kem,
        aead,
        sender_pk,
        recipient_ml_pk,
        recipient_x_pk,
        ct,
        ephemeral,
        aad,
    )?;
    let signer = DsaFactory::create_strategy(dsa.into());
    if mode == 1 && !signer.verify(&signed_digest(&ctx, encrypted), signature, sender_pk)? {
        return Err("Signature verification failed".into());
    }
    let shared = Zeroizing::new(HybridKemEngine::new(kem.into()).decapsulate(
        ct,
        ephemeral,
        recipient_ml_sk,
        recipient_x_sk,
        recipient_ml_pk,
        recipient_x_pk,
    )?);
    let mut payload =
        Zeroizing::new(AeadEngine::new(aead.into()).decrypt_with_aad(&shared, encrypted, &ctx)?);
    if mode == 1 {
        bounded(payload.len(), MAX_PLAINTEXT)?;
        return Ok(std::mem::take(&mut *payload));
    }
    let (msg, sig) = decode_signed_payload(&payload)?;
    if !signer.verify(&signed_digest(&ctx, msg), sig, sender_pk)? {
        return Err("Signature verification failed".into());
    }
    Ok(msg.to_vec())
}

#[allow(clippy::too_many_arguments)]
pub fn sign_then_encrypt(
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    message: Vec<u8>,
    sender_dsa_secret_key: Vec<u8>,
    sender_dsa_public_key: Vec<u8>,
    recipient_mlkem_public_key: Vec<u8>,
    recipient_x25519_public_key: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<SecurePackageDto, String> {
    let message = Zeroizing::new(message);
    let sender_dsa_secret_key = Zeroizing::new(sender_dsa_secret_key);
    let (mlkem_ciphertext, x25519_ephemeral_pk, encrypted_payload, signature) = seal(
        0,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
        &message,
        &sender_dsa_secret_key,
        &sender_dsa_public_key,
        &recipient_mlkem_public_key,
        &recipient_x25519_public_key,
        &associated_data,
    )?;
    let _ = signature;
    Ok(SecurePackageDto {
        version: 2,
        mlkem_ciphertext,
        x25519_ephemeral_pk,
        encrypted_payload,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_then_sign(
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    message: Vec<u8>,
    sender_dsa_secret_key: Vec<u8>,
    sender_dsa_public_key: Vec<u8>,
    recipient_mlkem_public_key: Vec<u8>,
    recipient_x25519_public_key: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<EncryptThenSignPackageDto, String> {
    let message = Zeroizing::new(message);
    let sender_dsa_secret_key = Zeroizing::new(sender_dsa_secret_key);
    let (mlkem_ciphertext, x25519_ephemeral_pk, encrypted_payload, signature) = seal(
        1,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
        &message,
        &sender_dsa_secret_key,
        &sender_dsa_public_key,
        &recipient_mlkem_public_key,
        &recipient_x25519_public_key,
        &associated_data,
    )?;
    Ok(EncryptThenSignPackageDto {
        version: 2,
        mlkem_ciphertext,
        x25519_ephemeral_pk,
        encrypted_payload,
        signature,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_then_verify(
    version: u8,
    package_mlkem_ciphertext: Vec<u8>,
    package_x25519_ephemeral_pk: Vec<u8>,
    package_encrypted_payload: Vec<u8>,
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    recipient_mlkem_secret_key: Vec<u8>,
    recipient_x25519_secret_key: Vec<u8>,
    recipient_mlkem_public_key: Vec<u8>,
    recipient_x25519_public_key: Vec<u8>,
    sender_dsa_public_key: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let recipient_mlkem_secret_key = Zeroizing::new(recipient_mlkem_secret_key);
    let recipient_x25519_secret_key = Zeroizing::new(recipient_x25519_secret_key);
    open(
        0,
        version,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
        &package_mlkem_ciphertext,
        &package_x25519_ephemeral_pk,
        &package_encrypted_payload,
        &[],
        &recipient_mlkem_secret_key,
        &recipient_x25519_secret_key,
        &recipient_mlkem_public_key,
        &recipient_x25519_public_key,
        &sender_dsa_public_key,
        &associated_data,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_then_decrypt(
    version: u8,
    package_mlkem_ciphertext: Vec<u8>,
    package_x25519_ephemeral_pk: Vec<u8>,
    package_encrypted_payload: Vec<u8>,
    package_signature: Vec<u8>,
    dsa_algorithm: TargetDsaAlgorithm,
    kem_algorithm: TargetHybridKemAlgorithm,
    aead_algorithm: TargetAeadAlgorithm,
    recipient_mlkem_secret_key: Vec<u8>,
    recipient_x25519_secret_key: Vec<u8>,
    recipient_mlkem_public_key: Vec<u8>,
    recipient_x25519_public_key: Vec<u8>,
    sender_dsa_public_key: Vec<u8>,
    associated_data: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let recipient_mlkem_secret_key = Zeroizing::new(recipient_mlkem_secret_key);
    let recipient_x25519_secret_key = Zeroizing::new(recipient_x25519_secret_key);
    open(
        1,
        version,
        dsa_algorithm,
        kem_algorithm,
        aead_algorithm,
        &package_mlkem_ciphertext,
        &package_x25519_ephemeral_pk,
        &package_encrypted_payload,
        &package_signature,
        &recipient_mlkem_secret_key,
        &recipient_x25519_secret_key,
        &recipient_mlkem_public_key,
        &recipient_x25519_public_key,
        &sender_dsa_public_key,
        &associated_data,
    )
}
