#![forbid(unsafe_code)]
//! X25519 key agreement with strict contributory check and automatic zeroization.

use std::fmt;

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::CryptoError;
use crate::kdf::decode_canonical_hex;

/// Zeroizing 32-byte X25519 private scalar seed.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SecretKey([u8; 32]);

/// Raw 32-byte X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct X25519PublicKey([u8; 32]);

/// Zeroizing 32-byte X25519 Diffie-Hellman shared secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519SharedSecret([u8; 32]);

impl X25519SecretKey {
    /// Generates a new random X25519 private key from `OsRng`.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Constructs a private key from raw 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses a canonical 64-char lowercase hex X25519 private key.
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        let bytes = decode_canonical_hex::<32>(value)?;
        Ok(Self(bytes))
    }

    /// Returns a zeroizing copy of the raw 32-byte private key.
    #[must_use]
    pub fn to_bytes_zeroizing(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0)
    }

    /// Returns a zeroizing lowercase hex encoding of the private key.
    #[must_use]
    pub fn to_hex_zeroizing(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0))
    }

    /// Derives the corresponding X25519 public key.
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        let secret = StaticSecret::from(self.0);
        let public = DalekPublicKey::from(&secret);
        X25519PublicKey(public.to_bytes())
    }

    /// Performs X25519 Diffie-Hellman key agreement, rejecting non-contributory points.
    pub fn diffie_hellman(
        &self,
        peer: &X25519PublicKey,
    ) -> Result<X25519SharedSecret, CryptoError> {
        let secret = StaticSecret::from(self.0);
        let peer_pub = DalekPublicKey::from(peer.0);
        let shared = secret.diffie_hellman(&peer_pub);
        if !shared.was_contributory() {
            return Err(CryptoError::KeyAgreementFailed);
        }
        Ok(X25519SharedSecret(*shared.as_bytes()))
    }

    /// Constant-time equality comparison against raw 32-byte secret material.
    #[must_use]
    pub fn ct_eq_bytes(&self, other: &[u8; 32]) -> bool {
        bool::from(self.0.ct_eq(other))
    }
}

impl fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519SecretKey([REDACTED])")
    }
}

impl X25519PublicKey {
    /// Constructs a public key from raw 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Constructs a public key from a slice, verifying 32-byte length.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 32] = slice
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self(bytes))
    }

    /// Parses a canonical 64-char lowercase hex X25519 public key.
    pub fn from_hex(value: &str) -> Result<Self, CryptoError> {
        let bytes = decode_canonical_hex::<32>(value)?;
        Ok(Self(bytes))
    }

    /// Borrows the raw 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encodes the public key as canonical lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for X25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "X25519PublicKey({}..)", &self.to_hex()[..8])
    }
}

impl X25519SharedSecret {
    /// Borrows the raw 32-byte shared secret.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519SharedSecret([REDACTED])")
    }
}
