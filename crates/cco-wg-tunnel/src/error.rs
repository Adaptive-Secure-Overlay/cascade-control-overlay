#![forbid(unsafe_code)]
//! Fail-closed error codes for `cco-wg-tunnel`.

use thiserror::Error;

/// Stable, log-safe errors emitted by [`crate::SplitWireGuardTunnel`].
#[derive(Debug, Error)]
pub enum WgTunnelError {
    #[error("invalid_wg_key")]
    InvalidWgKey,

    #[error("invalid_peer")]
    InvalidPeer,

    #[error("invalid_config: {0}")]
    InvalidConfig(&'static str),

    #[error("overlay_error: {0}")]
    Overlay(String),

    #[error("socket_io_error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tunnel_stopped")]
    Stopped,
}

impl WgTunnelError {
    /// Returns a stable machine-readable error code (never contains secrets or raw payloads).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidWgKey => "invalid_wg_key",
            Self::InvalidPeer => "invalid_peer",
            Self::InvalidConfig(c) => c,
            Self::Overlay(_) => "overlay_error",
            Self::Io(_) => "socket_io_error",
            Self::Stopped => "tunnel_stopped",
        }
    }
}
