#![forbid(unsafe_code)]
//! Userspace WireGuard (`boringtun`) tunnel with strict control-plane / data-plane separation:
//! - WireGuard control handshakes (`type 1/2/3`) traverse ONLY the authenticated MCC overlay
//!   (`A -> X1 -> X2 -> B`) backed by Trust Registry v2 and SQLite anti-replay.
//! - WireGuard transport data (`type 4`) traverses ONLY the direct UDP socket (`A <-> B`).

pub mod engine;
pub mod error;
pub mod stats;
pub mod tun;

pub use engine::{SplitTunnelHandle, SplitWireGuardTunnel, WgTunnelConfig};
pub use error::WgTunnelError;
pub use stats::{SanitizedEvent, TunnelState, TunnelStats};
pub use tun::{ChannelTun, ChannelTunPeer, TunDevice, TunFuture};

#[cfg(unix)]
pub use tun::UnixFdTun;
