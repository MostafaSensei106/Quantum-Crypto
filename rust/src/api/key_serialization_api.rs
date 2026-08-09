use base64::{engine::general_purpose, Engine as _};

pub fn bytes_to_hex(data: Vec<u8>) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: String) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16)
            .map_err(|e| format!("Failed to parse hex: {}", e))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub fn bytes_to_base64(data: Vec<u8>) -> String {
    general_purpose::STANDARD.encode(&data)
}

pub fn base64_to_bytes(encoded: String) -> Result<Vec<u8>, String> {
    general_purpose::STANDARD
        .decode(&encoded)
        .map_err(|e| format!("Failed to decode base64: {}", e))
}

pub fn bytes_to_base64_url_safe(data: Vec<u8>) -> String {
    general_purpose::URL_SAFE.encode(&data)
}

pub fn base64_url_safe_to_bytes(encoded: String) -> Result<Vec<u8>, String> {
    general_purpose::URL_SAFE
        .decode(&encoded)
        .map_err(|e| format!("Failed to decode base64: {}", e))
}
