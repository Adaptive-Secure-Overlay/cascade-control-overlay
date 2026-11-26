#![forbid(unsafe_code)]
//! Multiple Start Connections (MCC) authenticated state machine, privacy opaque handles,
//! move-only delivery proofs, and SQLite at-most-once anti-replay ledger.

pub mod machine;
pub mod proof;
pub mod security;
pub mod selection;

pub use machine::{
    MAX_ACTIVE, MAX_ATTEMPTS, MAX_IKE, MAX_PLAINTEXT, MAX_REQUESTS, MccAction, MccFanout,
    MccNodeConfig, MccNodeMachine, ROUTE_TTL_MS, WG_OVERLAY_CONTROL_PORT,
};
pub use proof::{DeliveredIkeMeta, DeliveryReceipt, IkeInjectionOutcome, LocalDeliveryProof};
pub use security::{
    AdmitStatus, CLOCK_SKEW, CapsuleV1, CapsuleV2, EndpointSecurity, MAX_BODY_BYTES, MAX_COPIES,
    MAX_DELIVERY_ATTEMPTS, MAX_EXCHANGES, MAX_LEDGER_BYTES, MAX_LIFETIME, MAX_SEAL_PLAINTEXT,
    MAX_WIRE_CIPHERTEXT, MCC_VERSION, VerifiedMessage, decode_canonical_base64_ct,
    encode_canonical_base64_ct,
};
pub use selection::{SelectionMode, SelectionPolicy};
