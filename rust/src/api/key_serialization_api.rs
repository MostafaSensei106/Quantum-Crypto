//! Key encoding utilities (hex / base64) — FFI boundary.
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
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex character at byte position {}", i / 2))
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
