use crate::core::hybrid_kem::{HybridKemEngine, HybridKemVariant};

#[derive(Clone, Copy)]
pub enum TargetHybridKemAlgorithm {
    MlKem512X25519,
    MlKem768X25519,
    MlKem1024X25519,
}

pub struct HybridKeyPairDto {
    pub mlkem_public_key: Vec<u8>,
    pub x25519_public_key: Vec<u8>,
    pub mlkem_secret_key: Vec<u8>,
    pub x25519_secret_key: Vec<u8>,
}

pub struct HybridEncapsulationDto {
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl From<TargetHybridKemAlgorithm> for HybridKemVariant {
    fn from(target: TargetHybridKemAlgorithm) -> Self {
        match target {
            TargetHybridKemAlgorithm::MlKem512X25519 => HybridKemVariant::MlKem512X25519,
            TargetHybridKemAlgorithm::MlKem768X25519 => HybridKemVariant::MlKem768X25519,
            TargetHybridKemAlgorithm::MlKem1024X25519 => HybridKemVariant::MlKem1024X25519,
        }
    }
}

pub fn generate_hybrid_kem_keypair(
    algorithm: TargetHybridKemAlgorithm,
) -> Result<HybridKeyPairDto, String> {
    let engine = HybridKemEngine::new(algorithm.into());
    let data = engine.generate_keypair()?;
    Ok(HybridKeyPairDto {
        mlkem_public_key: data.mlkem_public_key.clone(),
        x25519_public_key: data.x25519_public_key.clone(),
        mlkem_secret_key: data.mlkem_secret_key.clone(),
        x25519_secret_key: data.x25519_secret_key.clone(),
    })
}

pub fn hybrid_kem_encapsulate(
    algorithm: TargetHybridKemAlgorithm,
    mlkem_public_key: Vec<u8>,
    x25519_public_key: Vec<u8>,
) -> Result<HybridEncapsulationDto, String> {
    let engine = HybridKemEngine::new(algorithm.into());
    let data = engine.encapsulate(&mlkem_public_key, &x25519_public_key)?;
    Ok(HybridEncapsulationDto {
        mlkem_ciphertext: data.mlkem_ciphertext,
        x25519_ephemeral_pk: data.x25519_ephemeral_pk,
        shared_secret: data.shared_secret,
    })
}

pub fn hybrid_kem_decapsulate(
    algorithm: TargetHybridKemAlgorithm,
    mlkem_ciphertext: Vec<u8>,
    x25519_ephemeral_pk: Vec<u8>,
    mlkem_secret_key: Vec<u8>,
    x25519_secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let engine = HybridKemEngine::new(algorithm.into());
    engine.decapsulate(
        &mlkem_ciphertext,
        &x25519_ephemeral_pk,
        &mlkem_secret_key,
        &x25519_secret_key,
    )
}
