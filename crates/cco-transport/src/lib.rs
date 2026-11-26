#![forbid(unsafe_code)]
//! Asynchronous Tokio UDP transport, 4-step MGMT hop handshake, and non-blocking session worker.

pub mod config;
pub mod error;
pub mod mgmt;
pub mod node;

pub use config::{
    CascadeTransportConfig, NodeTransportConfig, PeerEndpoint, RouteMode, SocketProtector,
};
pub use error::TransportError;
pub use mgmt::{
    InitiatorHandshake, MgmtSession, PendingResponderHandshake, decrypt_link_envelope,
    encrypt_link_envelope, responder_handle_auth, responder_handle_init,
};
pub use node::{IkeSink, OverlayNode, OverlayNodeHandle, RelayOnlySink, TransportCounters};
