/// One-shot cryptographic hash functions (SHA-2 and SHA-3 families).
///
/// These are the classical building blocks used alongside the PQC schemes:
/// content addressing, key commitment, and transcript hashing.
/// Digest algorithm selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_512,
}

impl HashAlgorithm {
    /// Digest length in bytes.
    #[must_use]
    pub fn digest_len(&self) -> usize {
        match self {
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }
}

/// Compute the digest of `data` with the selected algorithm.
pub fn digest(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => {
            use sha2::Digest as _;
            sha2::Sha256::digest(data).to_vec()
        }
        HashAlgorithm::Sha384 => {
            use sha2::Digest as _;
            sha2::Sha384::digest(data).to_vec()
        }
        HashAlgorithm::Sha512 => {
            use sha2::Digest as _;
            sha2::Sha512::digest(data).to_vec()
        }
        HashAlgorithm::Sha3_256 => {
            use sha3::Digest as _;
            sha3::Sha3_256::digest(data).to_vec()
        }
        HashAlgorithm::Sha3_512 => {
            use sha3::Digest as _;
            sha3::Sha3_512::digest(data).to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_sha256_empty() {
        let hex: String = digest(HashAlgorithm::Sha256, b"")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn digest_lengths_match() {
        for algo in [
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sha3_256,
            HashAlgorithm::Sha3_512,
        ] {
            assert_eq!(digest(algo, b"abc").len(), algo.digest_len());
        }
    }
}
