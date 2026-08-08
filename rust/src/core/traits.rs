use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct SecretKeyContainer {
    pub bytes: Vec<u8>,
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
