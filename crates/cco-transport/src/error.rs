#![forbid(unsafe_code)]
//! Fail-closed error types for the asynchronous UDP overlay transport.

use thiserror::Error;

/// Transport-layer error with stable log-safe codes.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Underlying UDP socket I/O error.
    #[error("socket_io_error: {0}")]
    Io(#[from] std::io::Error),

    /// Referenced peer is unknown or equals the local node.
    #[error("unknown_peer")]
    UnknownPeer,

    /// 4-step MGMT handshake timed out or failed authentication.
    #[error("mgmt_handshake_failed")]
    MgmtHandshakeFailed,

    /// No established MGMT session with peer.
    #[error("no_session")]
    NoSession,

    /// Wire framing, encryption, or protocol decoding error.
    #[error("protocol_error: {0}")]
    Protocol(&'static str),

    /// Cascade state machine error.
    #[error("cascade_error: {0}")]
    Cascade(&'static str),

    /// Node actor channel closed (daemon stopped).
    #[error("node_stopped")]
    NodeStopped,
}
