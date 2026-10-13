//! HKDF key-derivation API — FFI boundary.
//!
//! [`hkdf_derive`] / [`hkdf_derive_multi`] are the historical SHA-256 entry
//! points (kept for backward compatibility). New code should prefer the
//! `*_with_hash` variants to select the digest explicitly.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

/// Digest used inside HKDF-Extract/Expand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetHkdfHash {
    /// HKDF-SHA-256 (default, 32-byte native output).
    Sha256,
    /// HKDF-SHA-384 (48-byte native output).
    Sha384,
    /// HKDF-SHA-512 (64-byte native output).
    Sha512,
}

/// HKDF-SHA256 ceiling: 255 × 32-byte blocks.
const MAX_OUTPUT_LEN: u32 = 8160;

fn validate_ikm(shared_secret: &[u8]) -> Result<(), String> {
    if shared_secret.is_empty() {
        return Err("Shared secret must not be empty".to_string());
    }
    Ok(())
}

fn validate_output_len(output_len: u32) -> Result<(), String> {
    if output_len == 0 || output_len > MAX_OUTPUT_LEN {
        return Err(format!(
            "Output length must be between 1 and {MAX_OUTPUT_LEN} bytes"
        ));
    }
    Ok(())
}

fn salt_or_none(salt: &[u8]) -> Option<&[u8]> {
    if salt.is_empty() {
        None
    } else {
        Some(salt)
    }
}

fn expand(
    hash: TargetHkdfHash,
    shared_secret: &[u8],
    salt: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), String> {
    let expand_err = |info: &[u8]| {
        format!(
            "HKDF expansion failed for info '{}'",
            String::from_utf8_lossy(info)
        )
    };
    match hash {
        TargetHkdfHash::Sha256 => {
            let hkdf = Hkdf::<Sha256>::new(salt_or_none(salt), shared_secret);
            hkdf.expand(info, okm).map_err(|_| expand_err(info))?;
        }
        TargetHkdfHash::Sha384 => {
            let hkdf = Hkdf::<Sha384>::new(salt_or_none(salt), shared_secret);
            hkdf.expand(info, okm).map_err(|_| expand_err(info))?;
        }
        TargetHkdfHash::Sha512 => {
            let hkdf = Hkdf::<Sha512>::new(salt_or_none(salt), shared_secret);
            hkdf.expand(info, okm).map_err(|_| expand_err(info))?;
        }
    }
    Ok(())
}

/// Derive `output_len` bytes from `shared_secret` with an explicit digest.
///
/// * `salt` — optional salt; empty means "no salt" (not a zeroed salt).
/// * `info` — context/application-specific separation string.
/// * `output_len` — 1..=8160.
pub fn hkdf_derive_with_hash(
    shared_secret: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    output_len: u32,
    hash: TargetHkdfHash,
) -> Result<Vec<u8>, String> {
    validate_ikm(&shared_secret)?;
    validate_output_len(output_len)?;

    let mut okm = vec![0u8; output_len as usize];
    expand(hash, &shared_secret, &salt, &info, &mut okm)?;
    Ok(okm)
}

/// Derive one `key_length`-byte key per entry in `info_strings`, same digest.
pub fn hkdf_derive_multi_with_hash(
    shared_secret: Vec<u8>,
    salt: Vec<u8>,
    info_strings: Vec<String>,
    key_length: u32,
    hash: TargetHkdfHash,
) -> Result<Vec<Vec<u8>>, String> {
    validate_ikm(&shared_secret)?;
    validate_output_len(key_length)?;
    if info_strings.is_empty() {
        return Err("At least one info string is required".to_string());
    }

    info_strings
        .iter()
        .map(|info| {
            let mut okm = vec![0u8; key_length as usize];
            expand(hash, &shared_secret, &salt, info.as_bytes(), &mut okm)?;
            Ok(okm)
        })
        .collect()
}

/// Derive key material with HKDF-SHA256 (legacy default; see [`hkdf_derive_with_hash`]).
pub fn hkdf_derive(
    shared_secret: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    output_len: u32,
) -> Result<Vec<u8>, String> {
    hkdf_derive_with_hash(
        shared_secret,
        salt,
        info,
        output_len,
        TargetHkdfHash::Sha256,
    )
}

/// Derive multiple keys with HKDF-SHA256 (legacy default; see [`hkdf_derive_multi_with_hash`]).
pub fn hkdf_derive_multi(
    shared_secret: Vec<u8>,
    salt: Vec<u8>,
    info_strings: Vec<String>,
    key_length: u32,
) -> Result<Vec<Vec<u8>>, String> {
    hkdf_derive_multi_with_hash(
        shared_secret,
        salt,
        info_strings,
        key_length,
        TargetHkdfHash::Sha256,
    )
}
