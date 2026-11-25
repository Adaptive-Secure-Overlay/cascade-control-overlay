#![forbid(unsafe_code)]
//! HKDF-SHA256, SHA-256 digests, constant-time comparisons, and canonical hex codecs.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::aead::{Key128, Key256};
use crate::error::CryptoError;

/// Derives `length` bytes using HKDF-SHA256 (`RFC 5869`), matching Python's `cryptography` HKDF.
pub fn hkdf_sha256_vec(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if length == 0 {
        return Err(CryptoError::KdfExpandFailed);
    }
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut okm = Zeroizing::new(vec![0u8; length]);
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfExpandFailed)?;
    Ok(okm)
}

/// Derives a 256-bit key using HKDF-SHA256.
pub fn hkdf_sha256_key256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Key256, CryptoError> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| CryptoError::KdfExpandFailed)?;
    Ok(Key256::from_bytes(*okm))
}

/// Derives a 128-bit key using HKDF-SHA256.
pub fn hkdf_sha256_key128(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Key128, CryptoError> {
    let salt_opt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt_opt, ikm);
    let mut okm = Zeroizing::new([0u8; 16]);
    hk.expand(info, okm.as_mut())
        .map_err(|_| CryptoError::KdfExpandFailed)?;
    Ok(Key128::from_bytes(*okm))
}

/// Computes a raw 32-byte SHA-256 digest.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Computes a lowercase hex-encoded SHA-256 digest.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Constant-time byte-slice comparison.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Decodes a canonical lowercase hex string into a fixed-size byte array.
///
/// Rejects uppercase hex characters, whitespace, or incorrect length.
pub fn decode_canonical_hex<const N: usize>(value: &str) -> Result<[u8; N], CryptoError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CryptoError::InvalidHex);
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(value, &mut out).map_err(|_| CryptoError::InvalidHex)?;
    Ok(out)
}

/// Decodes a variable-length canonical lowercase hex string with an upper byte bound.
pub fn decode_canonical_hex_vec(value: &str, max_bytes: usize) -> Result<Vec<u8>, CryptoError> {
    if value.len() % 2 != 0
        || value.len() / 2 > max_bytes
        || !value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CryptoError::InvalidHex);
    }
    hex::decode(value).map_err(|_| CryptoError::InvalidHex)
}
