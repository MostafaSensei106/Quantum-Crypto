//! Opaque, process-local native secrets. Rust mutex ownership serializes use and close.
use crate::api::{
    aead_api::TargetAeadAlgorithm,
    dsa_api::TargetDsaAlgorithm,
    hybrid_kem_api::TargetHybridKemAlgorithm,
    kem_api::TargetKemAlgorithm,
    secure_messaging_api::{self as messaging, EncryptThenSignPackageDto, SecurePackageDto},
    slh_dsa_api::TargetSlhDsaAlgorithm,
};
use crate::core::{
    aead::AeadEngine, hybrid_kem::HybridKemEngine, security::*, slhdsa::SlhDsaStrategy, streaming,
    traits::DsaStrategy,
};
use crate::factory::{dsa_factory::DsaFactory, kem_factory::KemFactory};
use flutter_rust_bridge::frb;
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use std::sync::{Arc, Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeKeyAlgorithm {
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
    MlKem512X25519,
    MlKem768X25519,
    MlKem1024X25519,
    SphincsSha2_128f,
    SphincsSha2_192f,
    SphincsSha2_256f,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Seed,
    SharedSecret,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeKeyUsage {
    Sign,
    Decapsulate,
    Encrypt,
    Decrypt,
    Derive,
}

struct Material {
    primary: Zeroizing<Vec<u8>>,
    secondary: Zeroizing<Vec<u8>>,
    public: Vec<u8>,
    public_secondary: Vec<u8>,
}
#[frb(opaque)]
#[derive(Clone)]
pub struct NativeKey {
    algorithm: NativeKeyAlgorithm,
    exportable: bool,
    usage: Vec<NativeKeyUsage>,
    secret: Arc<Mutex<Option<Material>>>,
}
pub struct NativeExportDto {
    pub secret_key: Vec<u8>,
    pub secondary_secret_key: Vec<u8>,
}
pub struct NativeEncapsulationDto {
    pub ciphertext: Vec<u8>,
    pub x25519_ephemeral_pk: Vec<u8>,
    pub shared_secret: NativeKey,
}

impl NativeKeyAlgorithm {
    fn dsa(self) -> Result<TargetDsaAlgorithm, String> {
        match self {
            Self::MlDsa44 => Ok(TargetDsaAlgorithm::MlDsa44),
            Self::MlDsa65 => Ok(TargetDsaAlgorithm::MlDsa65),
            Self::MlDsa87 => Ok(TargetDsaAlgorithm::MlDsa87),
            _ => Err("Requires ML-DSA key".into()),
        }
    }
    fn kem(self) -> Result<TargetKemAlgorithm, String> {
        match self {
            Self::MlKem512 => Ok(TargetKemAlgorithm::MlKem512),
            Self::MlKem768 => Ok(TargetKemAlgorithm::MlKem768),
            Self::MlKem1024 => Ok(TargetKemAlgorithm::MlKem1024),
            _ => Err("Requires ML-KEM key".into()),
        }
    }
    fn hybrid(self) -> Result<TargetHybridKemAlgorithm, String> {
        match self {
            Self::MlKem512X25519 => Ok(TargetHybridKemAlgorithm::MlKem512X25519),
            Self::MlKem768X25519 => Ok(TargetHybridKemAlgorithm::MlKem768X25519),
            Self::MlKem1024X25519 => Ok(TargetHybridKemAlgorithm::MlKem1024X25519),
            _ => Err("Requires hybrid key".into()),
        }
    }
    fn slh(self) -> Result<TargetSlhDsaAlgorithm, String> {
        match self {
            Self::SphincsSha2_128f => Ok(TargetSlhDsaAlgorithm::SlhDsaSha2_128f),
            Self::SphincsSha2_192f => Ok(TargetSlhDsaAlgorithm::SlhDsaSha2_192f),
            Self::SphincsSha2_256f => Ok(TargetSlhDsaAlgorithm::SlhDsaSha2_256f),
            _ => Err("Requires SPHINCS+ key".into()),
        }
    }
    fn aead(self) -> Result<TargetAeadAlgorithm, String> {
        match self {
            Self::Aes256Gcm => Ok(TargetAeadAlgorithm::Aes256Gcm),
            Self::ChaCha20Poly1305 => Ok(TargetAeadAlgorithm::ChaCha20Poly1305),
            Self::XChaCha20Poly1305 => Ok(TargetAeadAlgorithm::XChaCha20Poly1305),
            _ => Err("Requires AEAD key".into()),
        }
    }
    fn allowed(self) -> Vec<NativeKeyUsage> {
        if self.dsa().is_ok() || self.slh().is_ok() {
            vec![NativeKeyUsage::Sign]
        } else if self.kem().is_ok() || self.hybrid().is_ok() {
            vec![NativeKeyUsage::Decapsulate]
        } else if self.aead().is_ok() {
            vec![NativeKeyUsage::Encrypt, NativeKeyUsage::Decrypt]
        } else {
            vec![NativeKeyUsage::Derive]
        }
    }
}
impl NativeKey {
    fn new(
        algorithm: NativeKeyAlgorithm,
        exportable: bool,
        usage: Option<Vec<NativeKeyUsage>>,
        material: Material,
    ) -> Result<Self, String> {
        let allowed = algorithm.allowed();
        let usage = usage.unwrap_or_else(|| allowed.clone());
        if usage.iter().any(|u| !allowed.contains(u)) {
            return Err("Usage incompatible with algorithm".into());
        }
        Ok(Self {
            algorithm,
            exportable,
            usage,
            secret: Arc::new(Mutex::new(Some(material))),
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, Option<Material>>, String> {
        let guard = self.secret.lock().map_err(|_| "Native key lock poisoned")?;
        if guard.is_none() {
            return Err("Native key disposed".into());
        }
        Ok(guard)
    }
    fn require(&self, usage: NativeKeyUsage) -> Result<(), String> {
        if self.usage.contains(&usage) {
            Ok(())
        } else {
            Err("Key usage not permitted".into())
        }
    }
    /// Idempotent: waits for any current operation and zeroizes owned secret storage.
    pub fn close(&self) -> Result<(), String> {
        // Even a poisoned operation must not prevent explicit secret disposal.
        let mut guard = self
            .secret
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        guard.take();
        Ok(())
    }
    pub fn public_key(&self) -> Result<Vec<u8>, String> {
        let g = self.lock()?;
        Ok(g.as_ref().ok_or("Disposed")?.public.clone())
    }
    pub fn secondary_public_key(&self) -> Result<Vec<u8>, String> {
        let g = self.lock()?;
        Ok(g.as_ref().ok_or("Disposed")?.public_secondary.clone())
    }
    pub fn export_secret(&self) -> Result<NativeExportDto, String> {
        let g = self.lock()?;
        if !self.exportable {
            return Err("Key is not exportable".into());
        }
        let m = g.as_ref().ok_or("Disposed")?;
        Ok(NativeExportDto {
            secret_key: m.primary.to_vec(),
            secondary_secret_key: m.secondary.to_vec(),
        })
    }
    pub fn sign(&self, message: Vec<u8>) -> Result<Vec<u8>, String> {
        let message = Zeroizing::new(message);
        bounded(message.len(), MAX_PLAINTEXT)?;
        self.require(NativeKeyUsage::Sign)?;
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        if let Ok(d) = self.algorithm.dsa() {
            DsaFactory::create_strategy(d.into()).sign(&message, &m.primary)
        } else {
            SlhDsaStrategy::new(self.algorithm.slh()?.into()).sign(&message, &m.primary)
        }
    }
    pub fn encrypt(&self, plaintext: Vec<u8>, associated_data: Vec<u8>) -> Result<Vec<u8>, String> {
        let plaintext = Zeroizing::new(plaintext);
        bounded(plaintext.len(), MAX_PLAINTEXT)?;
        self.require(NativeKeyUsage::Encrypt)?;
        let g = self.lock()?;
        AeadEngine::new(self.algorithm.aead()?.into()).encrypt_with_aad(
            &g.as_ref().ok_or("Disposed")?.primary,
            &plaintext,
            &associated_data,
        )
    }
    pub fn decrypt(
        &self,
        ciphertext: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.require(NativeKeyUsage::Decrypt)?;
        bounded(
            ciphertext.len(),
            MAX_PLAINTEXT
                + crate::core::aead::AeadAlgorithmVariant::from(self.algorithm.aead()?).nonce_len()
                + 16,
        )?;
        let g = self.lock()?;
        AeadEngine::new(self.algorithm.aead()?.into()).decrypt_with_aad(
            &g.as_ref().ok_or("Disposed")?.primary,
            &ciphertext,
            &associated_data,
        )
    }
    pub fn stream_encrypt(
        &self,
        plaintext: Vec<u8>,
        chunk_size: Option<u32>,
    ) -> Result<Vec<u8>, String> {
        let plaintext = Zeroizing::new(plaintext);
        self.require(NativeKeyUsage::Encrypt)?;
        let g = self.lock()?;
        streaming::stream_encrypt(
            &g.as_ref().ok_or("Disposed")?.primary,
            &plaintext,
            self.algorithm.aead()?.into(),
            chunk_size.map(|v| v as usize),
        )
    }
    pub fn stream_decrypt(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>, String> {
        self.require(NativeKeyUsage::Decrypt)?;
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        // Stream algorithm is authenticated, but also enforce this handle's algorithm policy.
        let expected = match self.algorithm.aead()? {
            TargetAeadAlgorithm::Aes256Gcm => 0,
            TargetAeadAlgorithm::ChaCha20Poly1305 => 1,
            TargetAeadAlgorithm::XChaCha20Poly1305 => 2,
        };
        if ciphertext.get(1) != Some(&expected) {
            return Err("Stream algorithm does not match key".into());
        }
        streaming::stream_decrypt(&m.primary, &ciphertext)
    }
    /// Child output cannot be exported if the parent was non-exportable.
    pub fn derive_aead(
        &self,
        algorithm: TargetNativeAead,
        context: Vec<u8>,
        key_index: u32,
        exportable: bool,
    ) -> Result<NativeKey, String> {
        self.require(NativeKeyUsage::Derive)?;
        bounded(context.len(), MAX_AAD)?;
        if context.is_empty() {
            return Err("Derivation context must not be empty".into());
        }
        if exportable && !self.exportable {
            return Err("Non-exportable parent cannot derive exportable key".into());
        }
        let target = match algorithm {
            TargetNativeAead::Aes256Gcm => NativeKeyAlgorithm::Aes256Gcm,
            TargetNativeAead::ChaCha20Poly1305 => NativeKeyAlgorithm::ChaCha20Poly1305,
            TargetNativeAead::XChaCha20Poly1305 => NativeKeyAlgorithm::XChaCha20Poly1305,
        };
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        let mut info = b"Quantum-Crypto/NativeKey/AEAD/v2".to_vec();
        info.push(match algorithm {
            TargetNativeAead::Aes256Gcm => 0,
            TargetNativeAead::ChaCha20Poly1305 => 1,
            TargetNativeAead::XChaCha20Poly1305 => 2,
        });
        append_field(&mut info, &context)?;
        info.extend_from_slice(&key_index.to_be_bytes());
        let mut out = Zeroizing::new(vec![0; 32]);
        Hkdf::<Sha256>::new(Some(b"Quantum-Crypto/NativeKey/v2"), &m.primary)
            .expand(&info, &mut out)
            .map_err(|_| "KDF failed")?;
        Self::new(
            target,
            exportable,
            None,
            Material {
                primary: out,
                secondary: Zeroizing::new(vec![]),
                public: vec![],
                public_secondary: vec![],
            },
        )
    }
    pub fn decapsulate(
        &self,
        ciphertext: Vec<u8>,
        x25519_ephemeral_pk: Vec<u8>,
    ) -> Result<NativeKey, String> {
        self.require(NativeKeyUsage::Decapsulate)?;
        bounded(ciphertext.len(), 4096)?;
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        let shared = if let Ok(k) = self.algorithm.kem() {
            if !x25519_ephemeral_pk.is_empty() {
                return Err("Unexpected X25519 key".into());
            }
            KemFactory::create_strategy(k.into()).decapsulate(&ciphertext, &m.primary)?
        } else {
            HybridKemEngine::new(self.algorithm.hybrid()?.into()).decapsulate(
                &ciphertext,
                &x25519_ephemeral_pk,
                &m.primary,
                &m.secondary,
                &m.public,
                &m.public_secondary,
            )?
        };
        shared_key(shared, self.exportable)
    }
    pub fn sign_and_encrypt(
        &self,
        message: Vec<u8>,
        recipient_algorithm: TargetHybridKemAlgorithm,
        recipient_mlkem_public_key: Vec<u8>,
        recipient_x25519_public_key: Vec<u8>,
        aead_algorithm: TargetAeadAlgorithm,
        associated_data: Vec<u8>,
    ) -> Result<SecurePackageDto, String> {
        let message = Zeroizing::new(message);
        self.require(NativeKeyUsage::Sign)?;
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        let dsa = self.algorithm.dsa()?;
        let (ct, ephemeral, payload, _) = messaging::seal(
            0,
            dsa,
            recipient_algorithm,
            aead_algorithm,
            &message,
            &m.primary,
            &m.public,
            &recipient_mlkem_public_key,
            &recipient_x25519_public_key,
            &associated_data,
        )?;
        Ok(SecurePackageDto {
            version: 2,
            mlkem_ciphertext: ct,
            x25519_ephemeral_pk: ephemeral,
            encrypted_payload: payload,
            dsa_algorithm: dsa,
            kem_algorithm: recipient_algorithm,
            aead_algorithm,
        })
    }
    pub fn encrypt_and_sign(
        &self,
        message: Vec<u8>,
        recipient_algorithm: TargetHybridKemAlgorithm,
        recipient_mlkem_public_key: Vec<u8>,
        recipient_x25519_public_key: Vec<u8>,
        aead_algorithm: TargetAeadAlgorithm,
        associated_data: Vec<u8>,
    ) -> Result<EncryptThenSignPackageDto, String> {
        let message = Zeroizing::new(message);
        self.require(NativeKeyUsage::Sign)?;
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        let dsa = self.algorithm.dsa()?;
        let (ct, ephemeral, payload, signature) = messaging::seal(
            1,
            dsa,
            recipient_algorithm,
            aead_algorithm,
            &message,
            &m.primary,
            &m.public,
            &recipient_mlkem_public_key,
            &recipient_x25519_public_key,
            &associated_data,
        )?;
        Ok(EncryptThenSignPackageDto {
            version: 2,
            mlkem_ciphertext: ct,
            x25519_ephemeral_pk: ephemeral,
            encrypted_payload: payload,
            signature,
            dsa_algorithm: dsa,
            kem_algorithm: recipient_algorithm,
            aead_algorithm,
        })
    }
    pub fn decrypt_and_verify(
        &self,
        package: SecurePackageDto,
        sender_dsa_public_key: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.require(NativeKeyUsage::Decapsulate)?;
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        if self.algorithm.hybrid()? != package.kem_algorithm {
            return Err("Package key algorithm mismatch".into());
        }
        messaging::open(
            0,
            package.version,
            package.dsa_algorithm,
            package.kem_algorithm,
            package.aead_algorithm,
            &package.mlkem_ciphertext,
            &package.x25519_ephemeral_pk,
            &package.encrypted_payload,
            &[],
            &m.primary,
            &m.secondary,
            &m.public,
            &m.public_secondary,
            &sender_dsa_public_key,
            &associated_data,
        )
    }
    pub fn verify_and_decrypt(
        &self,
        package: EncryptThenSignPackageDto,
        sender_dsa_public_key: Vec<u8>,
        associated_data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.require(NativeKeyUsage::Decapsulate)?;
        let g = self.lock()?;
        let m = g.as_ref().ok_or("Disposed")?;
        if self.algorithm.hybrid()? != package.kem_algorithm {
            return Err("Package key algorithm mismatch".into());
        }
        messaging::open(
            1,
            package.version,
            package.dsa_algorithm,
            package.kem_algorithm,
            package.aead_algorithm,
            &package.mlkem_ciphertext,
            &package.x25519_ephemeral_pk,
            &package.encrypted_payload,
            &package.signature,
            &m.primary,
            &m.secondary,
            &m.public,
            &m.public_secondary,
            &sender_dsa_public_key,
            &associated_data,
        )
    }
}
#[derive(Clone, Copy)]
pub enum TargetNativeAead {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}
fn shared_key(bytes: Vec<u8>, exportable: bool) -> Result<NativeKey, String> {
    NativeKey::new(
        NativeKeyAlgorithm::SharedSecret,
        exportable,
        None,
        Material {
            primary: Zeroizing::new(bytes),
            secondary: Zeroizing::new(vec![]),
            public: vec![],
            public_secondary: vec![],
        },
    )
}

pub fn generate_native_key(
    algorithm: NativeKeyAlgorithm,
    exportable: bool,
    usage: Option<Vec<NativeKeyUsage>>,
) -> Result<NativeKey, String> {
    if usage.as_ref().is_some_and(|v| v.len() > 5) {
        return Err("Too many key usages".into());
    }
    let material = if let Ok(d) = algorithm.dsa() {
        let p = DsaFactory::create_strategy(d.into()).generate_keypair()?;
        Material {
            primary: Zeroizing::new(p.secret_key.into_bytes()),
            secondary: Zeroizing::new(vec![]),
            public: p.public_key,
            public_secondary: vec![],
        }
    } else if let Ok(s) = algorithm.slh() {
        let p = SlhDsaStrategy::new(s.into()).generate_keypair()?;
        Material {
            primary: Zeroizing::new(p.secret_key.into_bytes()),
            secondary: Zeroizing::new(vec![]),
            public: p.public_key,
            public_secondary: vec![],
        }
    } else if let Ok(k) = algorithm.kem() {
        let p = KemFactory::create_strategy(k.into()).generate_keypair()?;
        Material {
            primary: Zeroizing::new(p.secret_key.into_bytes()),
            secondary: Zeroizing::new(vec![]),
            public: p.public_key,
            public_secondary: vec![],
        }
    } else if let Ok(h) = algorithm.hybrid() {
        let p = HybridKemEngine::new(h.into()).generate_keypair()?;
        let (pk, xpk, sk, xsk) = p.into_parts();
        Material {
            primary: Zeroizing::new(sk),
            secondary: Zeroizing::new(xsk),
            public: pk,
            public_secondary: xpk,
        }
    } else if algorithm == NativeKeyAlgorithm::SharedSecret {
        return Err("Shared secrets must be encapsulated or imported".into());
    } else {
        let mut bytes = Zeroizing::new(vec![0; 32]);
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| "OS randomness unavailable")?;
        Material {
            primary: bytes,
            secondary: Zeroizing::new(vec![]),
            public: vec![],
            public_secondary: vec![],
        }
    };
    NativeKey::new(algorithm, exportable, usage, material)
}
/// Import explicitly crosses the Dart/native secret boundary. Validates key pairing.
pub fn import_native_key(
    algorithm: NativeKeyAlgorithm,
    secret_key: Vec<u8>,
    secondary_secret_key: Vec<u8>,
    public_key: Vec<u8>,
    secondary_public_key: Vec<u8>,
    exportable: bool,
    usage: Option<Vec<NativeKeyUsage>>,
) -> Result<NativeKey, String> {
    let primary = Zeroizing::new(secret_key);
    let secondary = Zeroizing::new(secondary_secret_key);
    bounded(primary.len(), 65536)?;
    bounded(public_key.len(), 65536)?;
    bounded(secondary.len(), 32)?;
    bounded(secondary_public_key.len(), 32)?;
    let challenge = b"Quantum-Crypto/native-import/key-binding/v2";
    if let Ok(d) = algorithm.dsa() {
        let signer = DsaFactory::create_strategy(d.into());
        let sig = signer.sign(challenge, &primary)?;
        if !signer.verify(challenge, &sig, &public_key)? {
            return Err("Key binding mismatch".into());
        }
    } else if let Ok(s) = algorithm.slh() {
        let signer = SlhDsaStrategy::new(s.into());
        let sig = signer.sign(challenge, &primary)?;
        if !signer.verify(challenge, &sig, &public_key)? {
            return Err("Key binding mismatch".into());
        }
    } else if let Ok(k) = algorithm.kem() {
        let kem = KemFactory::create_strategy(k.into());
        let enc = kem.encapsulate(&public_key)?;
        let ss = Zeroizing::new(enc.shared_secret);
        let recovered = Zeroizing::new(kem.decapsulate(&enc.ciphertext, &primary)?);
        if !bool::from(ss.as_slice().ct_eq(recovered.as_slice())) {
            return Err("Key binding mismatch".into());
        }
    } else if let Ok(h) = algorithm.hybrid() {
        let kem = HybridKemEngine::new(h.into());
        let enc = kem.encapsulate(&public_key, &secondary_public_key)?;
        let ss = Zeroizing::new(enc.shared_secret);
        let recovered = Zeroizing::new(kem.decapsulate(
            &enc.mlkem_ciphertext,
            &enc.x25519_ephemeral_pk,
            &primary,
            &secondary,
            &public_key,
            &secondary_public_key,
        )?);
        if !bool::from(ss.as_slice().ct_eq(recovered.as_slice())) {
            return Err("Key binding mismatch".into());
        }
    } else if primary.len() != 32 || !public_key.is_empty() {
        return Err("Symmetric secrets and seeds must be 32 bytes with no public key".into());
    }
    if algorithm.hybrid().is_err() && (!secondary.is_empty() || !secondary_public_key.is_empty()) {
        return Err("Unexpected secondary key".into());
    }
    NativeKey::new(
        algorithm,
        exportable,
        usage,
        Material {
            primary,
            secondary,
            public: public_key,
            public_secondary: secondary_public_key,
        },
    )
}
pub fn native_encapsulate(
    algorithm: NativeKeyAlgorithm,
    public_key: Vec<u8>,
    secondary_public_key: Vec<u8>,
    exportable: bool,
) -> Result<NativeEncapsulationDto, String> {
    if let Ok(k) = algorithm.kem() {
        if !secondary_public_key.is_empty() {
            return Err("Unexpected secondary key".into());
        }
        let e = KemFactory::create_strategy(k.into()).encapsulate(&public_key)?;
        Ok(NativeEncapsulationDto {
            ciphertext: e.ciphertext,
            x25519_ephemeral_pk: vec![],
            shared_secret: shared_key(e.shared_secret, exportable)?,
        })
    } else {
        let e = HybridKemEngine::new(algorithm.hybrid()?.into())
            .encapsulate(&public_key, &secondary_public_key)?;
        Ok(NativeEncapsulationDto {
            ciphertext: e.mlkem_ciphertext,
            x25519_ephemeral_pk: e.x25519_ephemeral_pk,
            shared_secret: shared_key(e.shared_secret, exportable)?,
        })
    }
}
