//! Key encoding utilities (hex / base64)  FFI boundary.
//!
//! Pure functions: no key validation is performed here, encoding only.

use base64::{engine::general_purpose, Engine as _};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Encode bytes as lowercase hex (two chars per byte, no prefix).
pub fn bytes_to_hex(data: Vec<u8>) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in &data {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Decode lowercase/uppercase hex (no `0x` prefix) into bytes.
pub fn hex_to_bytes(hex: String) -> Result<Vec<u8>, String> {
    let hex = hex.strip_prefix("0x").unwrap_or(&hex);
    if !hex.len().is_multiple_of(2) {
        return Err("Hex string has odd length".to_string());
    }
    crate::core::security::bounded(hex.len(), crate::core::security::MAX_ENCODED)?;
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .enumerate()
        .map(|(i, pair)| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            match (digit(pair[0]), digit(pair[1])) {
                (Some(a), Some(b)) => Ok((a << 4) | b),
                _ => Err(format!("Invalid hex character at byte position {i}")),
            }
        })
        .collect()
}

/// Encode bytes as standard Base64 (padded).
pub fn bytes_to_base64(data: Vec<u8>) -> String {
    general_purpose::STANDARD.encode(&data)
}

/// Decode standard Base64 into bytes.
pub fn base64_to_bytes(encoded: String) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("Failed to decode base64: {e}"))
}

/// Encode bytes as URL-safe Base64 (padded).
pub fn bytes_to_base64_url_safe(data: Vec<u8>) -> String {
    general_purpose::URL_SAFE.encode(&data)
}

/// Decode URL-safe Base64 into bytes.
pub fn base64_url_safe_to_bytes(encoded: String) -> Result<Vec<u8>, String> {
    general_purpose::URL_SAFE
        .decode(encoded.trim())
        .map_err(|e| format!("Failed to decode base64: {e}"))
}
