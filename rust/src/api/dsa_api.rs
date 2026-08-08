use crate::factory::dsa_factory::{DsaAlgorithm, DsaFactory};

pub enum TargetDsaAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl From<TargetDsaAlgorithm> for DsaAlgorithm {
    fn from(target: TargetDsaAlgorithm) -> Self {
        match target {
            TargetDsaAlgorithm::MlDsa44 => DsaAlgorithm::MlDsa44,
            TargetDsaAlgorithm::MlDsa65 => DsaAlgorithm::MlDsa65,
            TargetDsaAlgorithm::MlDsa87 => DsaAlgorithm::MlDsa87,
        }
    }
}

pub struct DsaKeyPairDto {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub fn generate_dsa_keypair(algorithm: TargetDsaAlgorithm) -> Result<DsaKeyPairDto, String> {
    let strategy = DsaFactory::create_strategy(algorithm.into());
    let keypair = strategy.generate_keypair()?;
    Ok(DsaKeyPairDto {
        public_key: keypair.public_key,
        secret_key: keypair.secret_key.bytes.clone(),
    })
}

pub fn dsa_sign(
    algorithm: TargetDsaAlgorithm,
    message: Vec<u8>,
    secret_key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let strategy = DsaFactory::create_strategy(algorithm.into());
    strategy.sign(&message, &secret_key)
}

pub fn dsa_verify(
    algorithm: TargetDsaAlgorithm,
    message: Vec<u8>,
    signature: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<bool, String> {
    let strategy = DsaFactory::create_strategy(algorithm.into());
    strategy.verify(&message, &signature, &public_key)
}
