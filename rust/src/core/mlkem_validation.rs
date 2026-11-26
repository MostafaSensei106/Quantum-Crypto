//! FIPS 203 sections 7.2/7.3 input checks missing from pqcrypto-mlkem.
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

pub fn validate_public_key(pk: &[u8], k: usize) -> Result<(), String> {
    if !(2..=4).contains(&k) {
        return Err("Invalid ML-KEM rank".into());
    }
    let expected = 384 * k + 32;
    if pk.len() != expected {
        return Err("Invalid ML-KEM public key length".into());
    }
    // ByteDecode_12: each three bytes encode two coefficients; both must be < q.
    for block in pk[..384 * k].as_chunks::<3>().0.iter() {
        let a = u16::from(block[0]) | (u16::from(block[1] & 15) << 8);
        let b = u16::from(block[1] >> 4) | (u16::from(block[2]) << 4);
        if a >= 3329 || b >= 3329 {
            return Err("Non-canonical ML-KEM public key coefficient".into());
        }
    }
    Ok(())
}
pub fn validate_secret_key(sk: &[u8], k: usize) -> Result<&[u8], String> {
    if !(2..=4).contains(&k) {
        return Err("Invalid ML-KEM rank".into());
    }
    // dkPKE || ek || H(ek) || z, FIPS 203 Algorithm 21.
    if sk.len() != 768 * k + 96 {
        return Err("Invalid ML-KEM secret key length".into());
    }
    let pk = &sk[384 * k..768 * k + 32];
    validate_public_key(pk, k)?;
    let digest = Sha3_256::digest(pk);
    if !bool::from(digest.as_slice().ct_eq(&sk[768 * k + 32..768 * k + 64])) {
        return Err("ML-KEM secret key hash mismatch".into());
    }
    Ok(pk)
}
