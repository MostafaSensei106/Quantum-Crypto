//! Version 2 in-memory chunked AEAD using RustCrypto STREAM-BE32.
//! Header: version:u8 || algorithm:u8 || chunk_size:u32be || plaintext_len:u32be
//! || salt:[u8;32] || STREAM nonce prefix (AEAD nonce length minus five).
//! The entire header is AAD for every segment. Empty input has a final tag.
use crate::core::{aead::AeadAlgorithmVariant, security::*};
use aead::{
    stream::{DecryptorBE32, EncryptorBE32},
    KeyInit, Payload,
};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

const VERSION: u8 = 2;
const FIXED_HEADER: usize = 42;

fn id(v: AeadAlgorithmVariant) -> u8 {
    match v {
        AeadAlgorithmVariant::Aes256Gcm => 0,
        AeadAlgorithmVariant::ChaCha20Poly1305 => 1,
        AeadAlgorithmVariant::XChaCha20Poly1305 => 2,
    }
}
fn variant(n: u8) -> Result<AeadAlgorithmVariant, String> {
    match n {
        0 => Ok(AeadAlgorithmVariant::Aes256Gcm),
        1 => Ok(AeadAlgorithmVariant::ChaCha20Poly1305),
        2 => Ok(AeadAlgorithmVariant::XChaCha20Poly1305),
        _ => Err("Unknown stream algorithm".into()),
    }
}
fn derive(key: &[u8], salt: &[u8], algorithm: u8) -> Result<Zeroizing<[u8; 32]>, String> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes".into());
    }
    let mut out = Zeroizing::new([0; 32]);
    let mut info = b"Quantum-Crypto/STREAM-BE32/v2/".to_vec();
    info.push(algorithm);
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(&info, out.as_mut())
        .map_err(|_| "Stream KDF failed")?;
    Ok(out)
}
fn sizes(chunk: usize, len: usize, prefix: usize) -> Result<(usize, usize), String> {
    if chunk == 0 || chunk > MAX_CHUNK {
        return Err("Chunk size must be 1..1048576".into());
    }
    bounded(len, MAX_PLAINTEXT)?;
    let count = len.div_ceil(chunk).max(1);
    let size = count
        .checked_mul(16)
        .and_then(|v| v.checked_add(len))
        .and_then(|v| v.checked_add(FIXED_HEADER + prefix))
        .ok_or("Stream size overflow")?;
    bounded(size, MAX_ENCODED)?;
    Ok((count, size))
}

pub fn stream_encrypt(
    key: &[u8],
    plaintext: &[u8],
    algorithm: AeadAlgorithmVariant,
    chunk_size: Option<usize>,
) -> Result<Vec<u8>, String> {
    let chunk = chunk_size.unwrap_or(64 * 1024);
    let prefix_len = algorithm.nonce_len() - 5;
    let (count, size) = sizes(chunk, plaintext.len(), prefix_len)?;
    let mut header = vec![VERSION, id(algorithm)];
    header.extend_from_slice(
        &u32::try_from(chunk)
            .map_err(|_| "Chunk too large")?
            .to_be_bytes(),
    );
    header.extend_from_slice(
        &u32::try_from(plaintext.len())
            .map_err(|_| "Stream too large")?
            .to_be_bytes(),
    );
    let mut randomness = vec![0; 32 + prefix_len];
    OsRng
        .try_fill_bytes(&mut randomness)
        .map_err(|_| "OS randomness unavailable")?;
    header.extend_from_slice(&randomness);
    let derived = derive(key, &header[10..42], id(algorithm))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(size)
        .map_err(|_| "Allocation failed")?;
    output.extend_from_slice(&header);
    macro_rules! encrypt {
        ($cipher:ty) => {{
            let cipher = <$cipher>::new_from_slice(derived.as_ref()).map_err(|_| "Invalid key")?;
            let mut stream = EncryptorBE32::from_aead(cipher, header[FIXED_HEADER..].into());
            for i in 0..count - 1 {
                output.extend_from_slice(
                    &stream
                        .encrypt_next(Payload {
                            msg: &plaintext[i * chunk..(i + 1) * chunk],
                            aad: &header,
                        })
                        .map_err(|_| "Stream encryption failed")?,
                );
            }
            output.extend_from_slice(
                &stream
                    .encrypt_last(Payload {
                        msg: &plaintext[(count - 1) * chunk..],
                        aad: &header,
                    })
                    .map_err(|_| "Stream encryption failed")?,
            );
        }};
    }
    match algorithm {
        AeadAlgorithmVariant::Aes256Gcm => encrypt!(Aes256Gcm),
        AeadAlgorithmVariant::ChaCha20Poly1305 => encrypt!(ChaCha20Poly1305),
        AeadAlgorithmVariant::XChaCha20Poly1305 => encrypt!(XChaCha20Poly1305),
    }
    Ok(output)
}

pub fn stream_decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    bounded(data.len(), MAX_ENCODED)?;
    if data.len() < FIXED_HEADER || data[0] != VERSION {
        return Err("Unsupported or truncated stream (v2 required)".into());
    }
    let algorithm = variant(data[1])?;
    let chunk = u32::from_be_bytes(data[2..6].try_into().map_err(|_| "Invalid header")?) as usize;
    let len = u32::from_be_bytes(data[6..10].try_into().map_err(|_| "Invalid header")?) as usize;
    let prefix_len = algorithm.nonce_len() - 5;
    let (count, size) = sizes(chunk, len, prefix_len)?;
    if data.len() != size {
        return Err("Truncated stream or trailing data".into());
    }
    let header = &data[..FIXED_HEADER + prefix_len];
    let derived = derive(key, &header[10..42], data[1])?;
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(len)
        .map_err(|_| "Allocation failed")?;
    macro_rules! decrypt {
        ($cipher:ty) => {{
            let cipher = <$cipher>::new_from_slice(derived.as_ref()).map_err(|_| "Invalid key")?;
            let mut stream = DecryptorBE32::from_aead(cipher, header[FIXED_HEADER..].into());
            let mut offset = header.len();
            for _ in 0..count - 1 {
                let end = offset + chunk + 16;
                let block = Zeroizing::new(
                    stream
                        .decrypt_next(Payload {
                            msg: &data[offset..end],
                            aad: header,
                        })
                        .map_err(|_| "Stream authentication failed")?,
                );
                plaintext.extend_from_slice(&block);
                offset = end;
            }
            let block = Zeroizing::new(
                stream
                    .decrypt_last(Payload {
                        msg: &data[offset..],
                        aad: header,
                    })
                    .map_err(|_| "Stream authentication failed")?,
            );
            plaintext.extend_from_slice(&block);
        }};
    }
    match algorithm {
        AeadAlgorithmVariant::Aes256Gcm => decrypt!(Aes256Gcm),
        AeadAlgorithmVariant::ChaCha20Poly1305 => decrypt!(ChaCha20Poly1305),
        AeadAlgorithmVariant::XChaCha20Poly1305 => decrypt!(XChaCha20Poly1305),
    }
    Ok(std::mem::take(&mut *plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stream_security() {
        for v in [
            AeadAlgorithmVariant::Aes256Gcm,
            AeadAlgorithmVariant::ChaCha20Poly1305,
            AeadAlgorithmVariant::XChaCha20Poly1305,
        ] {
            for data in [vec![], vec![1], vec![2; 64], vec![3; 65], vec![4; 200]] {
                let key = [7; 32];
                let ct = stream_encrypt(&key, &data, v, Some(64)).unwrap();
                assert_eq!(stream_decrypt(&key, &ct).unwrap(), data);
                assert_ne!(ct, stream_encrypt(&key, &data, v, Some(64)).unwrap());
                assert!(stream_decrypt(&[8; 32], &ct).is_err());
                for i in 0..ct.len() {
                    let mut bad = ct.clone();
                    bad[i] ^= 1;
                    assert!(stream_decrypt(&key, &bad).is_err(), "byte {i}");
                }
                for n in 0..ct.len() {
                    assert!(stream_decrypt(&key, &ct[..n]).is_err());
                }
                let mut extra = ct.clone();
                extra.push(0);
                assert!(stream_decrypt(&key, &extra).is_err());
                if data.len() > 128 {
                    let h = FIXED_HEADER + v.nonce_len() - 5;
                    let mut swapped = ct.clone();
                    for i in 0..80 {
                        swapped.swap(h + i, h + 80 + i);
                    }
                    assert!(stream_decrypt(&key, &swapped).is_err());
                }
            }
        }
    }
    #[test]
    fn bounds_and_legacy() {
        assert!(stream_decrypt(&[0; 32], &[1; 100]).is_err());
        for chunk in [0, MAX_CHUNK + 1, usize::MAX] {
            assert!(
                stream_encrypt(&[0; 32], b"", AeadAlgorithmVariant::Aes256Gcm, Some(chunk))
                    .is_err()
            );
        }
    }
}
