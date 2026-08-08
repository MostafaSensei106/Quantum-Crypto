use crate::factory::kem_factory::{KemAlgorithm, KemFactory};

pub enum TargetKemAlgorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

pub struct KeyPairDto {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct EncapsulationDto {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl From<TargetKemAlgorithm> for KemAlgorithm {
    fn from(target: TargetKemAlgorithm) -> Self {
        match target {
            TargetKemAlgorithm::MlKem512 => KemAlgorithm::MlKem512,
            TargetKemAlgorithm::MlKem768 => KemAlgorithm::MlKem768,
            TargetKemAlgorithm::MlKem1024 => KemAlgorithm::MlKem1024,
        }
    }
}

pub fn generate_kem_keypair(algorithm: TargetKemAlgorithm) -> Result<KeyPairDto, String> {
    let strategy = KemFactory::create_strategy(algorithm.into());
    let keypair = strategy.generate_keypair()?;
    Ok(KeyPairDto {
        public_key: keypair.public_key,
        secret_key: keypair.secret_key.bytes.clone(),
    })
}

pub fn kem_encapsulate(
    algorithm: TargetKemAlgorithm,
    public_key: Vec<u8>,
) -> Result<EncapsulationDto, String> {
    let strategy = KemFactory::create_strategy(algorithm.into());
    let res = strategy.encapsulate(&public_key)?;
    Ok(EncapsulationDto {
        ciphertext: res.ciphertext,
        shared_secret: res.shared_secret,
    })
}

pub fn kem_decapsulate(
    algorithm: TargetKemAlgorithm,
    ciphertext: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let strategy = KemFactory::create_strategy(algorithm.into());
    strategy.decapsulate(&ciphertext, &secret_key)
}
