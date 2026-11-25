#![forbid(unsafe_code)]
//! Fail-closed error types for cryptographic operations.
//!
//! Error messages never include secret keys, ciphertexts, plaintexts,
//! or attacker-controlled byte slices.

use thiserror::Error;

/// Stable fail-closed cryptographic error.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Key length does not match expected primitive requirement.
    #[error("invalid_key_length")]
    InvalidKeyLength,

    /// AEAD nonce length is not 12 bytes.
    #[error("invalid_nonce_length")]
    InvalidNonceLength,

    /// Ed25519 signature length is not 64 bytes.
    #[error("invalid_signature_length")]
    InvalidSignatureLength,

    /// Hex string is malformed or not canonical lowercase.
    #[error("invalid_hex")]
    InvalidHex,

    /// Ed25519 public key bytes do not represent a valid curve point.
    #[error("invalid_verifying_key")]
    InvalidVerifyingKey,

    /// X25519 key agreement yielded a non-contributory (all-zero) shared secret.
    #[error("key_agreement_failed")]
    KeyAgreementFailed,

    /// HKDF expansion exceeded SHA-256 output bounds or requested zero length.
    #[error("kdf_expand_failed")]
    KdfExpandFailed,

    /// AEAD encryption failed.
    #[error("encryption_failed")]
    EncryptionFailed,

    /// AEAD authentication tag verification failed.
    #[error("authentication_failed")]
    AuthenticationFailed,

    /// Strict Ed25519 signature verification failed.
    #[error("bad_signature")]
    BadSignature,

    /// Invalid cryptographic domain or purpose label.
    #[error("invalid_context")]
    InvalidContext,
}

impl CryptoError {
    /// Returns a stable, log-safe failure code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidKeyLength => "invalid_key_length",
            Self::InvalidNonceLength => "invalid_nonce_length",
            Self::InvalidSignatureLength => "invalid_signature_length",
            Self::InvalidHex => "invalid_hex",
            Self::InvalidVerifyingKey => "invalid_verifying_key",
            Self::KeyAgreementFailed => "key_agreement_failed",
            Self::KdfExpandFailed => "kdf_expand_failed",
            Self::EncryptionFailed => "encryption_failed",
            Self::AuthenticationFailed => "authentication_failed",
            Self::BadSignature => "bad_signature",
            Self::InvalidContext => "invalid_context",
        }
    }
}
