use crate::core::traits::{DsaKeyPair, DsaSecretKeyContainer, DsaStrategy};
use pqcrypto_mldsa::{mldsa44, mldsa65, mldsa87};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

pub struct MlDsaStrategy {
    variant: MlDsaVariant,
}

impl MlDsaStrategy {
    pub fn new(variant: MlDsaVariant) -> Self {
        Self { variant }
    }
}

impl DsaStrategy for MlDsaStrategy {
    fn generate_keypair(&self) -> Result<DsaKeyPair, String> {
        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let (pk, sk) = mldsa44::keypair();
                Ok(DsaKeyPair {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: DsaSecretKeyContainer {
                        bytes: sk.as_bytes().to_vec(),
                    },
                })
            }
            MlDsaVariant::MlDsa65 => {
                let (pk, sk) = mldsa65::keypair();
                Ok(DsaKeyPair {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: DsaSecretKeyContainer {
                        bytes: sk.as_bytes().to_vec(),
                    },
                })
            }
            MlDsaVariant::MlDsa87 => {
                let (pk, sk) = mldsa87::keypair();
                Ok(DsaKeyPair {
                    public_key: pk.as_bytes().to_vec(),
                    secret_key: DsaSecretKeyContainer {
                        bytes: sk.as_bytes().to_vec(),
                    },
                })
            }
        }
    }

    fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let sk = mldsa44::SecretKey::from_bytes(secret_key)
                    .map_err(|_| "Invalid secret key for ML-DSA-44".to_string())?;
                let signed = mldsa44::sign(message, &sk);
                Ok(signed.as_bytes().to_vec())
            }
            MlDsaVariant::MlDsa65 => {
                let sk = mldsa65::SecretKey::from_bytes(secret_key)
                    .map_err(|_| "Invalid secret key for ML-DSA-65".to_string())?;
                let signed = mldsa65::sign(message, &sk);
                Ok(signed.as_bytes().to_vec())
            }
            MlDsaVariant::MlDsa87 => {
                let sk = mldsa87::SecretKey::from_bytes(secret_key)
                    .map_err(|_| "Invalid secret key for ML-DSA-87".to_string())?;
                let signed = mldsa87::sign(message, &sk);
                Ok(signed.as_bytes().to_vec())
            }
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String> {
        match self.variant {
            MlDsaVariant::MlDsa44 => {
                let pk = mldsa44::PublicKey::from_bytes(public_key)
                    .map_err(|_| "Invalid public key for ML-DSA-44".to_string())?;
                let signed = mldsa44::SignedMessage::from_bytes(signature)
                    .map_err(|_| "Invalid signature format for ML-DSA-44".to_string())?;

                match mldsa44::open(&signed, &pk) {
                    Ok(opened_msg) => Ok(opened_msg == message),
                    Err(_) => Ok(false),
                }
            }
            MlDsaVariant::MlDsa65 => {
                let pk = mldsa65::PublicKey::from_bytes(public_key)
                    .map_err(|_| "Invalid public key for ML-DSA-65".to_string())?;
                let signed = mldsa65::SignedMessage::from_bytes(signature)
                    .map_err(|_| "Invalid signature format for ML-DSA-65".to_string())?;

                match mldsa65::open(&signed, &pk) {
                    Ok(opened_msg) => Ok(opened_msg == message),
                    Err(_) => Ok(false),
                }
            }
            MlDsaVariant::MlDsa87 => {
                let pk = mldsa87::PublicKey::from_bytes(public_key)
                    .map_err(|_| "Invalid public key for ML-DSA-87".to_string())?;
                let signed = mldsa87::SignedMessage::from_bytes(signature)
                    .map_err(|_| "Invalid signature format for ML-DSA-87".to_string())?;

                match mldsa87::open(&signed, &pk) {
                    Ok(opened_msg) => Ok(opened_msg == message),
                    Err(_) => Ok(false),
                }
            }
        }
    }
}
