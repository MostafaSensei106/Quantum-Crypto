use crate::core::traits::{EncapsulationResult, KemStrategy, KeyPair, SecretKeyContainer};
use pqcrypto_mlkem::{mlkem1024, mlkem512, mlkem768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

pub enum MlKemVariant {
    MlKem512,
    MlKem768,
    MlKem1024,
}

pub struct MlKemStrategy {
    variant: MlKemVariant,
}

impl MlKemStrategy {
    pub fn new(variant: MlKemVariant) -> Self {
        Self { variant }
    }
}

impl KemStrategy for MlKemStrategy {
    fn generate_keypair(&self) -> Result<KeyPair, String> {
        match self.variant {
            MlKemVariant::MlKem512 => {
                let (pk, sk) = mlkem512::keypair();
                Ok(KeyPair {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: SecretKeyContainer {
                        bytes: sk.as_bytes().to_vec(),
                    },
                })
            }
            MlKemVariant::MlKem768 => {
                let (pk, sk) = mlkem768::keypair();
                Ok(KeyPair {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: SecretKeyContainer {
                        bytes: sk.as_bytes().to_vec(),
                    },
                })
            }
            MlKemVariant::MlKem1024 => {
                let (pk, sk) = mlkem1024::keypair();
                Ok(KeyPair {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: SecretKeyContainer {
                        bytes: sk.as_bytes().to_vec(),
                    },
                })
            }
        }
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<EncapsulationResult, String> {
        match self.variant {
            MlKemVariant::MlKem512 => {
                let pk = mlkem512::PublicKey::from_bytes(public_key)
                    .map_err(|_| "Invalid public key for ML-KEM-512".to_string())?;
                let (ss, ct) = mlkem512::encapsulate(&pk);
                Ok(EncapsulationResult {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret: ss.as_bytes().to_vec(),
                })
            }
            MlKemVariant::MlKem768 => {
                let pk = mlkem768::PublicKey::from_bytes(public_key)
                    .map_err(|_| "Invalid public key for ML-KEM-768".to_string())?;
                let (ss, ct) = mlkem768::encapsulate(&pk);
                Ok(EncapsulationResult {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret: ss.as_bytes().to_vec(),
                })
            }
            MlKemVariant::MlKem1024 => {
                let pk = mlkem1024::PublicKey::from_bytes(public_key)
                    .map_err(|_| "Invalid public key for ML-KEM-1024".to_string())?;
                let (ss, ct) = mlkem1024::encapsulate(&pk);
                Ok(EncapsulationResult {
                    ciphertext: ct.as_bytes().to_vec(),
                    shared_secret: ss.as_bytes().to_vec(),
                })
            }
        }
    }

    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
        match self.variant {
            MlKemVariant::MlKem512 => {
                let ct = mlkem512::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| "Invalid ciphertext for ML-KEM-512".to_string())?;
                let sk = mlkem512::SecretKey::from_bytes(secret_key)
                    .map_err(|_| "Invalid secret key for ML-KEM-512".to_string())?;
                Ok(mlkem512::decapsulate(&ct, &sk).as_bytes().to_vec())
            }
            MlKemVariant::MlKem768 => {
                let ct = mlkem768::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| "Invalid ciphertext for ML-KEM-768".to_string())?;
                let sk = mlkem768::SecretKey::from_bytes(secret_key)
                    .map_err(|_| "Invalid secret key for ML-KEM-768".to_string())?;
                Ok(mlkem768::decapsulate(&ct, &sk).as_bytes().to_vec())
            }
            MlKemVariant::MlKem1024 => {
                let ct = mlkem1024::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| "Invalid ciphertext for ML-KEM-1024".to_string())?;
                let sk = mlkem1024::SecretKey::from_bytes(secret_key)
                    .map_err(|_| "Invalid secret key for ML-KEM-1024".to_string())?;
                Ok(mlkem1024::decapsulate(&ct, &sk).as_bytes().to_vec())
            }
        }
    }
}
