#![forbid(unsafe_code)]
//! Pure Sans-I/O state machines for Cascade Control Overlay.
//!
//! - [`mcc`]: Multiple Start Connections (MCC) with Ed25519 authentication,
//!   X25519 recipient capsules, opaque continuation handles, move-only delivery proofs,
//!   and durable SQLite at-most-once anti-replay ledger.

pub mod error;
pub mod mcc;

pub use error::CascadeError;
