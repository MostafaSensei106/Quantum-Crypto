//! Shared bounds and unambiguous protocol encodings.
pub const MAX_PLAINTEXT: usize = 64 * 1024 * 1024;
pub const MAX_AAD: usize = 1024 * 1024;
pub const MAX_CHUNK: usize = 1024 * 1024;
pub const MAX_ENCODED: usize = MAX_PLAINTEXT + 2 * 1024 * 1024;

pub fn bounded(len: usize, max: usize) -> Result<(), String> {
    if len > max {
        Err(format!("Input exceeds {max}-byte limit"))
    } else {
        Ok(())
    }
}
pub fn append_field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let n = u32::try_from(bytes.len()).map_err(|_| "Field exceeds u32 length")?;
    let size = out
        .len()
        .checked_add(4)
        .and_then(|v| v.checked_add(bytes.len()))
        .ok_or("Length overflow")?;
    bounded(size, MAX_ENCODED)?;
    out.try_reserve(4 + bytes.len())
        .map_err(|_| "Allocation failed")?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Strict length-prefixed signed-message payload parser.
pub fn decode_signed_payload(payload: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let prefix = payload.get(..4).ok_or("Truncated signed payload")?;
    let n = u32::from_be_bytes(prefix.try_into().map_err(|_| "Invalid prefix")?) as usize;
    bounded(n, MAX_PLAINTEXT)?;
    let end = 4usize.checked_add(n).ok_or("Payload overflow")?;
    if end >= payload.len() {
        return Err("Missing signature or truncated message".into());
    }
    Ok((&payload[4..end], &payload[end..]))
}
