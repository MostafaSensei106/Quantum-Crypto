use hkdf::Hkdf;
use sha2::Sha256;

/// Derive key material from a shared secret using HKDF-SHA256.
///
/// * `shared_secret` - Input keying material (e.g., from KEM encapsulation)
/// * `salt` - Optional salt (if empty, a default salt is used)
/// * `info` - Context/application-specific info string
/// * `output_len` - Desired output length in bytes (1-8160)
pub fn hkdf_derive(
    shared_secret: Vec<u8>,
    salt: Vec<u8>,
    info: Vec<u8>,
    output_len: u32,
) -> Result<Vec<u8>, String> {
    if shared_secret.is_empty() {
        return Err("Shared secret must not be empty".to_string());
    }
    if output_len == 0 || output_len > 8160 {
        return Err("Output length must be between 1 and 8160 bytes".to_string());
    }

    let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };
    let hkdf = Hkdf::<Sha256>::new(salt_ref, &shared_secret);
    let mut okm = vec![0u8; output_len as usize];
    hkdf.expand(&info, &mut okm)
        .map_err(|_| "HKDF expansion failed: output length may be too large".to_string())?;
    Ok(okm)
}

/// Derive multiple keys from a shared secret in one call.
/// Returns a vector of derived keys, one for each entry in `info_strings`.
///
/// * `shared_secret` - Input keying material
/// * `salt` - Optional salt
/// * `info_strings` - Vector of context strings, one per desired key
/// * `key_length` - Length of each derived key in bytes
pub fn hkdf_derive_multi(
    shared_secret: Vec<u8>,
    salt: Vec<u8>,
    info_strings: Vec<String>,
    key_length: u32,
) -> Result<Vec<Vec<u8>>, String> {
    if shared_secret.is_empty() {
        return Err("Shared secret must not be empty".to_string());
    }
    if key_length == 0 || key_length > 8160 {
        return Err("Key length must be between 1 and 8160 bytes".to_string());
    }
    if info_strings.is_empty() {
        return Err("At least one info string is required".to_string());
    }

    let salt_ref = if salt.is_empty() { None } else { Some(salt.as_slice()) };
    let hkdf = Hkdf::<Sha256>::new(salt_ref, &shared_secret);

    let mut keys = Vec::with_capacity(info_strings.len());
    for info in &info_strings {
        let mut okm = vec![0u8; key_length as usize];
        hkdf.expand(info.as_bytes(), &mut okm)
            .map_err(|_| format!("HKDF expansion failed for info '{}'", info))?;
        keys.push(okm);
    }
    Ok(keys)
}
