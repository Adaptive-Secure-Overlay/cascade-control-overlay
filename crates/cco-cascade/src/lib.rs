#![forbid(unsafe_code)]
//! Pure Sans-I/O state machines for Cascade Control Overlay.
//!
//! - [`mcc`]: Multiple Start Connections (MCC) with Ed25519 authentication,
//!   X25519 recipient capsules, opaque continuation handles, move-only delivery proofs,
//!   and durable SQLite at-most-once anti-replay ledger.
//! - [`universal`]: Universal H-hop Privacy Cascade (`H >= 2`) with hop-local handles
//!   and automatic reject/abort route recovery.
//! - [`wireguard`]: WireGuard Handshake Overlay (types 1/2/3 via overlay, type 4 direct bypass)
//!   and the canonical 27-scenario verification matrix.

pub mod error;
pub mod mcc;
pub mod universal;
pub mod wireguard;

pub use error::CascadeError;
