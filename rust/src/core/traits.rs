use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SecretKeyContainer {
    pub bytes: Vec<u8>,
}

#[derive(ZeroizeOnDrop)]
pub struct DsaSecretKeyContainer {
    pub bytes: Vec<u8>,
}

pub struct DsaKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: DsaSecretKeyContainer,
}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: SecretKeyContainer,
}

pub struct EncapsulationResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

pub trait KemStrategy: Send + Sync {
    fn generate_keypair(&self) -> Result<KeyPair, String>;
    fn encapsulate(&self, public_key: &[u8]) -> Result<EncapsulationResult, String>;
    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String>;
}

pub trait DsaStrategy: Send + Sync {
    fn generate_keypair(&self) -> Result<DsaKeyPair, String>;
    fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool, String>;
}
