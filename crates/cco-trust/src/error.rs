#![forbid(unsafe_code)]
//! Fail-closed error codes for Trust Registry v2.

use thiserror::Error;

/// Stable fail-closed error returned by Trust Registry v2 operations.
///
/// Never includes raw private keys, signatures, or untrusted payload bytes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}: {message}")]
pub struct TrustRegistryError {
    /// Machine-readable, stable failure code matching the Python v2 specification.
    pub code: &'static str,
    /// Short human-readable diagnostic message without secret material.
    pub message: String,
}

impl TrustRegistryError {
    /// Creates a new fail-closed registry error with a stable code.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns the stable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
