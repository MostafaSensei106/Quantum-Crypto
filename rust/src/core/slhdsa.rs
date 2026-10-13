use crate::core::traits::{DsaKeyPair, DsaSecretKeyContainer, DsaStrategy};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

/// SLH-DSA (FIPS 205) parameter sets exposed by this library.
///
/// Only the SHA-2 `f` ("fast signing") variants are exposed: signing with
/// the `s` ("small signature") variants is orders of magnitude slower,
/// which makes them a poor default for interactive/mobile use. The three
/// levels mirror the ML-DSA story: L1 / L3 / L5.
///
/// Unlike ML-DSA, SLH-DSA signatures are **detached**: [`DsaStrategy::sign`]
/// returns the raw signature bytes only (no embedded message copy), and
/// [`DsaStrategy::verify`] expects those exact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlhDsaVariant {
    /// SLH-DSA-SHA2-128f — NIST security level 1, ~17 KB signatures.
    Sha2_128f,
    /// SLH-DSA-SHA2-192f — NIST security level 3, ~35 KB signatures.
    Sha2_192f,
    /// SLH-DSA-SHA2-256f — NIST security level 5, ~49 KB signatures.
    Sha2_256f,
}

pub struct SlhDsaStrategy {
    variant: SlhDsaVariant,
}

impl SlhDsaStrategy {
    pub fn new(variant: SlhDsaVariant) -> Self {
        Self { variant }
    }
}

impl DsaStrategy for SlhDsaStrategy {
    fn generate_keypair(&self) -> Result<DsaKeyPair, String> {
        let (public_key, secret_key) = match self.variant {
            SlhDsaVariant::Sha2_128f => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2128fsimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_192f => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2192fsimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            SlhDsaVariant::Sha2_256f => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2256fsimple::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };
        Ok(DsaKeyPair {
            public_key,
            secret_key: DsaSecretKeyContainer { bytes: secret_key },
        })
    }

    fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String> {
        let label = self.variant.fips_name();
        let signature = match self.variant {
            SlhDsaVariant::Sha2_128f => {
                use pqcrypto_sphincsplus::sphincssha2128fsimple as scheme;
                let sk = scheme::SecretKey::from_bytes(secret_key)
                    .map_err(|_| format!("Invalid secret key for {label}"))?;
                scheme::detached_sign(message, &sk).as_bytes().to_vec()
            }
            SlhDsaVariant::Sha2_192f => {
                use pqcrypto_sphincsplus::sphincssha2192fsimple as scheme;
                let sk = scheme::SecretKey::from_bytes(secret_key)
                    .map_err(|_| format!("Invalid secret key for {label}"))?;
                scheme::detached_sign(message, &sk).as_bytes().to_vec()
            }
            SlhDsaVariant::Sha2_256f => {
                use pqcrypto_sphincsplus::sphincssha2256fsimple as scheme;
                let sk = scheme::SecretKey::from_bytes(secret_key)
                    .map_err(|_| format!("Invalid secret key for {label}"))?;
                scheme::detached_sign(message, &sk).as_bytes().to_vec()
            }
        };
        Ok(signature)
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String> {
        let label = self.variant.fips_name();
        let valid = match self.variant {
            SlhDsaVariant::Sha2_128f => {
                use pqcrypto_sphincsplus::sphincssha2128fsimple as scheme;
                let pk = scheme::PublicKey::from_bytes(public_key)
                    .map_err(|_| format!("Invalid public key for {label}"))?;
                let sig = scheme::DetachedSignature::from_bytes(signature)
                    .map_err(|_| format!("Invalid signature format for {label}"))?;
                scheme::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            SlhDsaVariant::Sha2_192f => {
                use pqcrypto_sphincsplus::sphincssha2192fsimple as scheme;
                let pk = scheme::PublicKey::from_bytes(public_key)
                    .map_err(|_| format!("Invalid public key for {label}"))?;
                let sig = scheme::DetachedSignature::from_bytes(signature)
                    .map_err(|_| format!("Invalid signature format for {label}"))?;
                scheme::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            SlhDsaVariant::Sha2_256f => {
                use pqcrypto_sphincsplus::sphincssha2256fsimple as scheme;
                let pk = scheme::PublicKey::from_bytes(public_key)
                    .map_err(|_| format!("Invalid public key for {label}"))?;
                let sig = scheme::DetachedSignature::from_bytes(signature)
                    .map_err(|_| format!("Invalid signature format for {label}"))?;
                scheme::verify_detached_signature(&sig, message, &pk).is_ok()
            }
        };
        Ok(valid)
    }
}

impl SlhDsaVariant {
    /// Full FIPS 205 parameter-set name, used in error messages and benchmarks.
    #[must_use]
    pub fn fips_name(&self) -> &'static str {
        match self {
            Self::Sha2_128f => "SLH-DSA-SHA2-128f",
            Self::Sha2_192f => "SLH-DSA-SHA2-192f",
            Self::Sha2_256f => "SLH-DSA-SHA2-256f",
        }
    }
}
