#![forbid(unsafe_code)]
//! Ed25519 signing and strict verification (`verify_strict`) with automatic zeroization.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::kdf::{decode_canonical_hex, sha256_hex};

/// Zeroizing 32-byte Ed25519 signing key seed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ed25519SecretKey([u8; 32]);

/// Validated 32-byte Ed25519 verifying (public) key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ed25519PublicKey([u8; 32]);

/// Raw 64-byte Ed25519 signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519SecretKey {
    /// Generates a new random Ed25519 signing key using `OsRng`.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self(seed)
    }

    /// Constructs a signing key from a 32-byte seed.
    #[must_use]
    pub const fn from_bytes(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    /// Parses a canonical 64-char lowercase hex Ed25519 signing seed.
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        let seed = decode_canonical_hex::<32>(value)?;
        Ok(Self(seed))
    }

    /// Returns a zeroizing copy of the raw 32-byte seed.
    #[must_use]
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }

    /// Returns a zeroizing lowercase hex encoding of the 32-byte seed.
    #[must_use]
    pub fn to_hex_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0))
    }

    /// Derives the corresponding Ed25519 verifying key.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        let signing = SigningKey::from_bytes(&self.0);
        Ed25519PublicKey(signing.verifying_key().to_bytes())
    }

    /// Computes a deterministic Ed25519 signature over `message`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let signing = SigningKey::from_bytes(&self.0);
        let sig = signing.sign(message);
        Ed25519Signature(sig.to_bytes())
    }

    /// Constant-time comparison of the raw seed bytes.
    #[must_use]
    pub fn ct_eq_bytes(&self, other: &[u8; 32]) -> bool {
        bool::from(self.0.ct_eq(other))
    }
}

impl fmt::Debug for Ed25519SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ed25519SecretKey([REDACTED])")
    }
}

impl Ed25519PublicKey {
    /// Validates and constructs an Ed25519 verifying key from 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidVerifyingKey)?;
        Ok(Self(bytes))
    }

    /// Validates and constructs an Ed25519 verifying key from a byte slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 32] = slice
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Self::from_bytes(bytes)
    }

    /// Parses and validates a canonical 64-char lowercase hex Ed25519 verifying key.
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        let bytes = decode_canonical_hex::<32>(value)?;
        Self::from_bytes(bytes)
    }

    /// Borrows the raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes the verifying key as canonical lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Computes the Trust Registry v2 `key_id` (`sha256(raw_public_key)` lowercase hex).
    #[must_use]
    pub fn key_id(&self) -> String {
        sha256_hex(&self.0)
    }

    /// Verifies `signature` over `message` using `ed25519-dalek::VerifyingKey::verify_strict`.
    pub fn verify_strict(
        &self,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), CryptoError> {
        let verifying =
            VerifyingKey::from_bytes(&self.0).map_err(|_| CryptoError::InvalidVerifyingKey)?;
        let sig = Signature::from_bytes(&signature.0);
        verifying
            .verify_strict(message, &sig)
            .map_err(|_| CryptoError::BadSignature)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({}..)", &self.to_hex()[..8])
    }
}

impl Ed25519Signature {
    /// Constructs a signature from raw 64 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Constructs a signature from a byte slice, verifying 64-byte length.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 64] = slice
            .try_into()
            .map_err(|_| CryptoError::InvalidSignatureLength)?;
        Ok(Self(bytes))
    }

    /// Parses a canonical 128-char lowercase hex signature.
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        let bytes = decode_canonical_hex::<64>(value)?;
        Ok(Self(bytes))
    }

    /// Borrows the raw 64 signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Encodes the signature as canonical lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Signature({}..)", &self.to_hex()[..8])
    }
}
