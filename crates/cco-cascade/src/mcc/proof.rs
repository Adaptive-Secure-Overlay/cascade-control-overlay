#![forbid(unsafe_code)]
//! Move-only single-use delivery proof and strict injection outcome enum.
//!
//! Rust's ownership system enforces at compile time what `mcc_auth.py::_LocalDeliveryProof`
//! checked dynamically at runtime: a proof can only be minted after Ed25519 verification
//! and ledger reservation, cannot be cloned or copied, and is consumed exactly once.

use serde_json::Value;

/// Local UDP/charon injection result (`ike_proxy.py::IkeInjectionOutcome`).
///
/// - `Sent`: local syscall completed; mark the ledger reservation as `delivered`.
/// - `Rejected`: confirmed pre-injection refusal; caller may release the reservation
///   and try another verified MCC candidate.
/// - `Unknown`: injection may have reached the kernel/daemon; retrying is FORBIDDEN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeInjectionOutcome {
    Sent,
    Rejected,
    Unknown,
}

/// Verified IKE metadata carried alongside an authenticated payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredIkeMeta {
    pub src: String,
    pub dst: String,
    pub x1: String,
    pub x2: String,
    pub conn_id: String,
    pub context: String,
    pub direction: String,
    pub ike_src_ip: String,
    pub ike_src_port: u16,
    pub ike_dst_ip: String,
    pub ike_dst_port: u16,
    pub udp_port: u16,
    pub opaque_token: String,
    pub expected_copies: usize,
    pub copy_id: usize,
    pub message_key: String,
}

impl DeliveredIkeMeta {
    /// Converts metadata to a JSON object for adapter/logging consumers.
    #[must_use]
    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "kind": "ike",
            "privacy": true,
            "inline": true,
            "phase": "REAL_IKE_MCC_AUTH",
            "src": self.src,
            "dst": self.dst,
            "x1": self.x1,
            "x2": self.x2,
            "conn_id": self.conn_id,
            "ab_context": self.context,
            "mcc_session_id": self.context,
            "dir": self.direction,
            "ike_src_ip": self.ike_src_ip,
            "ike_src_port": self.ike_src_port,
            "ike_dst_ip": self.ike_dst_ip,
            "ike_dst_port": self.ike_dst_port,
            "udp_port": self.udp_port,
            "opaque_token": self.opaque_token,
            "mcc_fanout": self.expected_copies,
        })
    }
}

/// Single-use, non-Clone, non-Copy local delivery proof.
///
/// Constructed exclusively by `MccNodeMachine` after Ed25519 signature verification,
/// semantic validation, and durable SQLite `claim_delivery` reservation.
#[derive(Debug)]
pub struct LocalDeliveryProof {
    payload: Vec<u8>,
    meta: DeliveredIkeMeta,
    message_key: String,
    copy_id: usize,
}

impl LocalDeliveryProof {
    pub(crate) fn mint(
        payload: Vec<u8>,
        meta: DeliveredIkeMeta,
        message_key: String,
        copy_id: usize,
    ) -> Self {
        Self {
            payload,
            meta,
            message_key,
            copy_id,
        }
    }

    /// Borrows the verified IKE payload bytes before consumption.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Borrows the verified delivery metadata before consumption.
    #[must_use]
    pub fn meta(&self) -> &DeliveredIkeMeta {
        &self.meta
    }

    /// Consumes the proof once, yielding `(payload, meta, DeliveryReceipt)` for the IKE sink.
    #[must_use]
    pub fn consume(self) -> (Vec<u8>, DeliveredIkeMeta, DeliveryReceipt) {
        let receipt = DeliveryReceipt {
            message_key: self.message_key,
            copy_id: self.copy_id,
        };
        (self.payload, self.meta, receipt)
    }
}

/// Opaque receipt returned by [`LocalDeliveryProof::consume`] to report the local
/// injection outcome back to the state machine (`complete_delivery`).
#[derive(Debug)]
pub struct DeliveryReceipt {
    pub(crate) message_key: String,
    pub(crate) copy_id: usize,
}
