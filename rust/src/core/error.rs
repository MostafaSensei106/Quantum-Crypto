use std::fmt;

/// Categorized error types for the quantum_crypto library.
/// Each variant maps to a specific failure domain, making it easier
/// for consumers to handle errors programmatically.
#[derive(Debug, Clone)]
pub enum CryptoError {
    /// The provided key has an invalid length or format.
    InvalidKeyLength { expected: usize, actual: usize },
    /// The provided key data is malformed or corrupted.
    InvalidKeyFormat { algorithm: String, detail: String },
    /// The ciphertext is too short or malformed.
    InvalidCiphertext { detail: String },
    /// Signature verification failed.
    SignatureVerificationFailed,
    /// Signature data is malformed.
    InvalidSignatureFormat { detail: String },
    /// AEAD encryption or decryption failed.
    AeadError { operation: String, detail: String },
    /// KEM encapsulation or decapsulation failed.
    KemError { operation: String, detail: String },
    /// HKDF key derivation failed.
    KdfError { detail: String },
    /// The input seed is too short.
    InvalidSeedLength { minimum: usize, actual: usize },
    /// Streaming encryption/decryption format error.
    StreamFormatError { detail: String },
    /// Generic/unexpected error.
    InternalError { detail: String },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidKeyLength { expected, actual } => {
                write!(f, "Invalid key length: expected {} bytes, got {}", expected, actual)
            }
            CryptoError::InvalidKeyFormat { algorithm, detail } => {
                write!(f, "Invalid key format for {}: {}", algorithm, detail)
            }
            CryptoError::InvalidCiphertext { detail } => {
                write!(f, "Invalid ciphertext: {}", detail)
            }
            CryptoError::SignatureVerificationFailed => {
                write!(f, "Signature verification failed")
            }
            CryptoError::InvalidSignatureFormat { detail } => {
                write!(f, "Invalid signature format: {}", detail)
            }
            CryptoError::AeadError { operation, detail } => {
                write!(f, "AEAD {} failed: {}", operation, detail)
            }
            CryptoError::KemError { operation, detail } => {
                write!(f, "KEM {} failed: {}", operation, detail)
            }
            CryptoError::KdfError { detail } => {
                write!(f, "Key derivation failed: {}", detail)
            }
            CryptoError::InvalidSeedLength { minimum, actual } => {
                write!(f, "Seed too short: minimum {} bytes, got {}", minimum, actual)
            }
            CryptoError::StreamFormatError { detail } => {
                write!(f, "Stream format error: {}", detail)
            }
            CryptoError::InternalError { detail } => {
                write!(f, "Internal error: {}", detail)
            }
        }
    }
}

impl std::error::Error for CryptoError {}

/// Convert CryptoError to String for FRB compatibility.
/// All API functions use Result<T, String>, so we convert at the API boundary.
impl From<CryptoError> for String {
    fn from(err: CryptoError) -> String {
        err.to_string()
    }
}
