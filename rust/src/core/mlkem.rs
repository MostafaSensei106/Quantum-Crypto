use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct MlKem768SecretWrapper {
    pub bytes: Vec<u8>,
}

pub struct MlKem768KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

pub struct MlKem768Encapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Key Generation
pub fn generate_keypair_768() -> MlKem768KeyPair {
    let (pk, sk) = mlkem768::keypair();
    return MlKem768KeyPair {
        public_key: pk.as_bytes().to_vec(),
        secret_key: sk.as_bytes().to_vec(),
    };
}

/// Encapsulation
pub fn encapsulate_768(public_key_bytes: &[u8]) -> Result<MlKem768Encapsulation, String> {
    let pk = mlkem768::PublicKey::from_bytes(public_key_bytes)
        .map_err(|_| "Failed to parse public key for ML-KEM-768".to_string())?;

    let (ss, ct) = mlkem768::encapsulate(&pk);

    Ok(MlKem768Encapsulation {
        ciphertext: ct.as_bytes().to_vec(),
        shared_secret: ss.as_bytes().to_vec(),
    })
}

/// Decapsulation
pub fn decapsulate_768(
    secret_key_bytes: &[u8],
    ciphertext_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let ct = mlkem768::Ciphertext::from_bytes(ciphertext_bytes)
        .map_err(|_| "Failed to parse ciphertext for ML-KEM-768".to_string())?;

    let sk = mlkem768::SecretKey::from_bytes(secret_key_bytes)
        .map_err(|_| "Failed to parse secret key for ML-KEM-768".to_string())?;

    let ss = mlkem768::decapsulate(&ct, &sk);

    Ok(ss.as_bytes().to_vec())
}
