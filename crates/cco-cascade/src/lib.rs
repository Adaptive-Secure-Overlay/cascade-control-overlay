#![forbid(unsafe_code)]
//! Pure Sans-I/O state machines for Cascade Control Overlay.
//!
//! - [`mcc`]: Multiple Start Connections (MCC) with Ed25519 authentication,
//!   X25519 recipient capsules, opaque continuation handles, move-only delivery proofs,
//!   and durable SQLite at-most-once anti-replay ledger.
//! - [`universal`]: Universal H-hop Privacy Cascade (`H >= 2`) with hop-local handles
//!   and automatic reject/abort route recovery.

pub mod error;
pub mod mcc;
pub mod universal;

pub use error::CascadeError;
