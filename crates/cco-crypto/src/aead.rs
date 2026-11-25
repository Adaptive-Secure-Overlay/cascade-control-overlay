#![forbid(unsafe_code)]
//! Symmetric AEAD encryption (AES-256-GCM and AES-128-GCM) with automatic zeroization.

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;

/// Standard 96-bit AES-GCM nonce.
pub type Nonce12 = [u8; 12];

/// AES-GCM authentication tag size in bytes.
pub const AES_GCM_TAG_LEN: usize = 16;

/// Zeroizing 256-bit symmetric key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key256([u8; 32]);

impl Key256 {
    /// Creates a 256-bit key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a 256-bit key from a slice, validating length.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 32] = slice
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }

    /// Generates a fresh random 256-bit key using `OsRng`.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Borrows the raw 32-byte key material.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality comparison against another `Key256`.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for Key256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key256([REDACTED])")
    }
}

/// Zeroizing 128-bit symmetric key material (used in Section 4.3.1 AES-128-GCM benchmarks).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key128([u8; 16]);

impl Key128 {
    /// Creates a 128-bit key from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Creates a 128-bit key from a slice, validating length.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 16] = slice
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }

    /// Generates a fresh random 128-bit key using `OsRng`.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Borrows the raw 16-byte key material.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Constant-time equality comparison against another `Key128`.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for Key128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key128([REDACTED])")
    }
}

/// Generates `N` cryptographically secure random bytes using `OsRng`.
#[must_use]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Generates a fresh 12-byte AES-GCM nonce using `OsRng`.
#[must_use]
pub fn random_nonce12() -> Nonce12 {
    random_bytes::<12>()
}

/// Encrypts `plaintext` with AES-256-GCM using a fresh random 12-byte nonce.
///
/// Returns `(nonce, ciphertext_with_tag)`.
pub fn aes256_gcm_encrypt(
    key: &Key256,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Nonce12, Vec<u8>), CryptoError> {
    let nonce = random_nonce12();
    let ct = aes256_gcm_encrypt_with_nonce(key, &nonce, plaintext, aad)?;
    Ok((nonce, ct))
}

/// Encrypts `plaintext` with AES-256-GCM using an explicit 12-byte nonce.
///
/// Primarily intended for deterministic golden-vector verification; production callers
/// should prefer [`aes256_gcm_encrypt`].
pub fn aes256_gcm_encrypt_with_nonce(
    key: &Key256,
    nonce: &Nonce12,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts `ciphertext_with_tag` with AES-256-GCM, authenticating `aad`.
pub fn aes256_gcm_decrypt(
    key: &Key256,
    nonce: &Nonce12,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < AES_GCM_TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}

/// Encrypts `plaintext` with AES-128-GCM using a fresh random 12-byte nonce.
pub fn aes128_gcm_encrypt(
    key: &Key128,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Nonce12, Vec<u8>), CryptoError> {
    let nonce = random_nonce12();
    let ct = aes128_gcm_encrypt_with_nonce(key, &nonce, plaintext, aad)?;
    Ok((nonce, ct))
}

/// Encrypts `plaintext` with AES-128-GCM using an explicit 12-byte nonce.
pub fn aes128_gcm_encrypt_with_nonce(
    key: &Key128,
    nonce: &Nonce12,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes128Gcm::new(key.as_bytes().into());
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)
}

/// Decrypts `ciphertext_with_tag` with AES-128-GCM, authenticating `aad`.
pub fn aes128_gcm_decrypt(
    key: &Key128,
    nonce: &Nonce12,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < AES_GCM_TAG_LEN {
        return Err(CryptoError::AuthenticationFailed);
    }
    let cipher = Aes128Gcm::new(key.as_bytes().into());
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)
}
