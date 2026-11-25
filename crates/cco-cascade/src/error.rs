#![forbid(unsafe_code)]
//! Fail-closed error codes for `cco-cascade` state machines.

use thiserror::Error;

/// Stable fail-closed security or protocol error without secret material.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{code}")]
pub struct CascadeError {
    /// Machine-readable stable reason code (matching Python `MccSecurityError.code`).
    pub code: &'static str,
}

impl CascadeError {
    /// Constructs a new fail-closed error with a stable log-safe code.
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self { code }
    }

    /// Returns the stable reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
}
