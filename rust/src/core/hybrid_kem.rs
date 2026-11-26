use crate::core::security::append_field;
use hkdf::Hkdf;
use pqcrypto_mlkem::{mlkem1024, mlkem512, mlkem768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Copy)]
pub enum HybridKemVariant {
    MlKem512X25519,
    MlKem768X25519,
    MlKem1024X25519,
}

#[derive(ZeroizeOnDrop)]
pub struct HybridKeyPairData {
    #[zeroize(skip)]
    pub mlkem_public_key: Vec<u8>,
    #[zeroize(skip)]
    pub x25519_public_key: Vec<u8>,
    pub mlkem_secret_key: Vec<u8>,
    pub x25519_secret_key: Vec<u8>,
}

impl HybridKeyPairData {
    /// Consume the pair, moving all parts out without cloning.
    /// Secrets are taken (leaving empty buffers that drop cleans up).
    #[must_use]
    pub fn into_parts(mut self) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        (
            std::mem::take(&mut self.mlkem_public_key),
            std::mem::take(&mut self.x25519_public_key),
            std::mem::take(&mut self.mlkem_secret_key),
            std::mem::take(&mut self.x25519_secret_key),
        )
    }
}

pub struct HybridEncapsulationData {
    pub mlkem_ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

pub struct HybridKemEngine {
    pub variant: HybridKemVariant,
}

impl HybridKemEngine {
    pub fn new(variant: HybridKemVariant) -> Self {
        Self { variant }
    }

    fn kdf(
        &self,
        mlkem_ss: &[u8],
        x25519_ss: &[u8],
        mlkem_pk: &[u8],
        x25519_pk: &[u8],
        ct: &[u8],
        ephemeral: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(mlkem_ss);
        ikm.extend_from_slice(x25519_ss);
        let mut context = b"Quantum-Crypto/Hybrid-KEM/v2".to_vec();
        context.push(match self.variant {
            HybridKemVariant::MlKem512X25519 => 0,
            HybridKemVariant::MlKem768X25519 => 1,
            HybridKemVariant::MlKem1024X25519 => 2,
        });
        for field in [mlkem_pk, x25519_pk, ct, ephemeral] {
            append_field(&mut context, field)?;
        }
        let hkdf = Hkdf::<Sha256>::new(Some(b"Quantum-Crypto/Hybrid-KEM/v2/extract"), &ikm);
        let mut okm = Zeroizing::new(vec![0u8; 32]);
        hkdf.expand(&context, &mut okm)
            .map_err(|_| "HKDF expansion failed")?;
        Ok(std::mem::take(&mut *okm))
    }

    fn rank(&self) -> usize {
        match self.variant {
            HybridKemVariant::MlKem512X25519 => 2,
            HybridKemVariant::MlKem768X25519 => 3,
            HybridKemVariant::MlKem1024X25519 => 4,
        }
    }

    pub fn generate_keypair(&self) -> Result<HybridKeyPairData, String> {
        let x25519_sk = StaticSecret::random_from_rng(OsRng);
        let x25519_pk = X25519PublicKey::from(&x25519_sk);

        match self.variant {
            HybridKemVariant::MlKem512X25519 => {
                let (mlkem_pk, mlkem_sk) = mlkem512::keypair();
                Ok(HybridKeyPairData {
                    mlkem_public_key: mlkem_pk.as_bytes().to_vec(),
                    x25519_public_key: x25519_pk.to_bytes().to_vec(),
                    mlkem_secret_key: mlkem_sk.as_bytes().to_vec(),
                    x25519_secret_key: x25519_sk.to_bytes().to_vec(),
                })
            }
            HybridKemVariant::MlKem768X25519 => {
                let (mlkem_pk, mlkem_sk) = mlkem768::keypair();
                Ok(HybridKeyPairData {
                    mlkem_public_key: mlkem_pk.as_bytes().to_vec(),
                    x25519_public_key: x25519_pk.to_bytes().to_vec(),
                    mlkem_secret_key: mlkem_sk.as_bytes().to_vec(),
                    x25519_secret_key: x25519_sk.to_bytes().to_vec(),
                })
            }
            HybridKemVariant::MlKem1024X25519 => {
                let (mlkem_pk, mlkem_sk) = mlkem1024::keypair();
                Ok(HybridKeyPairData {
                    mlkem_public_key: mlkem_pk.as_bytes().to_vec(),
                    x25519_public_key: x25519_pk.to_bytes().to_vec(),
                    mlkem_secret_key: mlkem_sk.as_bytes().to_vec(),
                    x25519_secret_key: x25519_sk.to_bytes().to_vec(),
                })
            }
        }
    }

    pub fn encapsulate(
        &self,
        mlkem_pk: &[u8],
        x25519_pk_bytes: &[u8],
    ) -> Result<HybridEncapsulationData, String> {
        crate::core::mlkem_validation::validate_public_key(mlkem_pk, self.rank())?;
        let x25519_pk_array: [u8; 32] = x25519_pk_bytes
            .try_into()
            .map_err(|_| "Invalid X25519 public key length")?;
        let x25519_pk = X25519PublicKey::from(x25519_pk_array);
        let ephemeral_sk = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pk = X25519PublicKey::from(&ephemeral_sk);
        let x25519_ss = ephemeral_sk.diffie_hellman(&x25519_pk);
        if !x25519_ss.was_contributory() {
            return Err("Non-contributory X25519 public key".into());
        }

        match self.variant {
            HybridKemVariant::MlKem512X25519 => {
                let pk = mlkem512::PublicKey::from_bytes(mlkem_pk)
                    .map_err(|_| "Invalid ML-KEM public key")?;
                let (mlkem_ss, mlkem_ct) = mlkem512::encapsulate(&pk);
                let shared_secret = self.kdf(
                    mlkem_ss.as_bytes(),
                    x25519_ss.as_bytes(),
                    mlkem_pk,
                    x25519_pk_bytes,
                    mlkem_ct.as_bytes(),
                    ephemeral_pk.as_bytes(),
                )?;
                Ok(HybridEncapsulationData {
                    mlkem_ciphertext: [vec![2], mlkem_ct.as_bytes().to_vec()].concat(),
                    x25519_ephemeral_pk: ephemeral_pk.to_bytes().to_vec(),
                    shared_secret,
                })
            }
            HybridKemVariant::MlKem768X25519 => {
                let pk = mlkem768::PublicKey::from_bytes(mlkem_pk)
                    .map_err(|_| "Invalid ML-KEM public key")?;
                let (mlkem_ss, mlkem_ct) = mlkem768::encapsulate(&pk);
                let shared_secret = self.kdf(
                    mlkem_ss.as_bytes(),
                    x25519_ss.as_bytes(),
                    mlkem_pk,
                    x25519_pk_bytes,
                    mlkem_ct.as_bytes(),
                    ephemeral_pk.as_bytes(),
                )?;
                Ok(HybridEncapsulationData {
                    mlkem_ciphertext: [vec![2], mlkem_ct.as_bytes().to_vec()].concat(),
                    x25519_ephemeral_pk: ephemeral_pk.to_bytes().to_vec(),
                    shared_secret,
                })
            }
            HybridKemVariant::MlKem1024X25519 => {
                let pk = mlkem1024::PublicKey::from_bytes(mlkem_pk)
                    .map_err(|_| "Invalid ML-KEM public key")?;
                let (mlkem_ss, mlkem_ct) = mlkem1024::encapsulate(&pk);
                let shared_secret = self.kdf(
                    mlkem_ss.as_bytes(),
                    x25519_ss.as_bytes(),
                    mlkem_pk,
                    x25519_pk_bytes,
                    mlkem_ct.as_bytes(),
                    ephemeral_pk.as_bytes(),
                )?;
                Ok(HybridEncapsulationData {
                    mlkem_ciphertext: [vec![2], mlkem_ct.as_bytes().to_vec()].concat(),
                    x25519_ephemeral_pk: ephemeral_pk.to_bytes().to_vec(),
                    shared_secret,
                })
            }
        }
    }

    pub fn decapsulate(
        &self,
        mlkem_ct: &[u8],
        x25519_ephemeral_pk_bytes: &[u8],
        mlkem_sk: &[u8],
        x25519_sk_bytes: &[u8],
        mlkem_pk: &[u8],
        x25519_pk: &[u8],
    ) -> Result<Vec<u8>, String> {
        let embedded = crate::core::mlkem_validation::validate_secret_key(mlkem_sk, self.rank())?;
        if embedded != mlkem_pk {
            return Err("ML-KEM public key binding mismatch".into());
        }
        let (version, mlkem_ct) = mlkem_ct.split_first().ok_or("Missing hybrid version")?;
        if *version != 2 {
            return Err("Unsupported hybrid version (v2 required)".into());
        }
        let x25519_sk_array: [u8; 32] = x25519_sk_bytes
            .try_into()
            .map_err(|_| "Invalid X25519 secret key length")?;
        let x25519_sk_array = Zeroizing::new(x25519_sk_array);
        let x25519_sk = StaticSecret::from(*x25519_sk_array);
        if X25519PublicKey::from(&x25519_sk).as_bytes() != x25519_pk {
            return Err("X25519 key binding mismatch".into());
        }

        let x25519_ephemeral_pk_array: [u8; 32] = x25519_ephemeral_pk_bytes
            .try_into()
            .map_err(|_| "Invalid X25519 ephemeral public key length")?;
        let x25519_ephemeral_pk = X25519PublicKey::from(x25519_ephemeral_pk_array);

        let x25519_ss = x25519_sk.diffie_hellman(&x25519_ephemeral_pk);
        if !x25519_ss.was_contributory() {
            return Err("Non-contributory X25519 ephemeral key".into());
        }

        match self.variant {
            HybridKemVariant::MlKem512X25519 => {
                let ct = mlkem512::Ciphertext::from_bytes(mlkem_ct)
                    .map_err(|_| "Invalid ML-KEM ciphertext")?;
                let sk = mlkem512::SecretKey::from_bytes(mlkem_sk)
                    .map_err(|_| "Invalid ML-KEM secret key")?;
                let mlkem_ss = mlkem512::decapsulate(&ct, &sk);
                self.kdf(
                    mlkem_ss.as_bytes(),
                    x25519_ss.as_bytes(),
                    mlkem_pk,
                    x25519_pk,
                    mlkem_ct,
                    x25519_ephemeral_pk_bytes,
                )
            }
            HybridKemVariant::MlKem768X25519 => {
                let ct = mlkem768::Ciphertext::from_bytes(mlkem_ct)
                    .map_err(|_| "Invalid ML-KEM ciphertext")?;
                let sk = mlkem768::SecretKey::from_bytes(mlkem_sk)
                    .map_err(|_| "Invalid ML-KEM secret key")?;
                let mlkem_ss = mlkem768::decapsulate(&ct, &sk);
                self.kdf(
                    mlkem_ss.as_bytes(),
                    x25519_ss.as_bytes(),
                    mlkem_pk,
                    x25519_pk,
                    mlkem_ct,
                    x25519_ephemeral_pk_bytes,
                )
            }
            HybridKemVariant::MlKem1024X25519 => {
                let ct = mlkem1024::Ciphertext::from_bytes(mlkem_ct)
                    .map_err(|_| "Invalid ML-KEM ciphertext")?;
                let sk = mlkem1024::SecretKey::from_bytes(mlkem_sk)
                    .map_err(|_| "Invalid ML-KEM secret key")?;
                let mlkem_ss = mlkem1024::decapsulate(&ct, &sk);
                self.kdf(
                    mlkem_ss.as_bytes(),
                    x25519_ss.as_bytes(),
                    mlkem_pk,
                    x25519_pk,
                    mlkem_ct,
                    x25519_ephemeral_pk_bytes,
                )
            }
        }
    }
}
