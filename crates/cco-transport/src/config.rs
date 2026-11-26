#![forbid(unsafe_code)]
//! Configuration structs for the overlay transport node.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cco_cascade::mcc::{MccFanout, SelectionPolicy};
use serde::{Deserialize, Serialize};

/// Optional platform callback protecting outbound UDP sockets from VPN routing loops
/// (e.g., Android `VpnService.protect(fd)`).
pub type SocketProtector = Arc<dyn Fn(i32) -> bool + Send + Sync>;

/// Network addressing for one overlay mesh participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEndpoint {
    /// Logical node identifier (must match Trust Registry v2).
    pub name: String,
    /// Overlay UDP address (`ip:port`) used for hop-to-hop traffic.
    pub overlay_addr: SocketAddr,
    /// Underlay IPv4 identity used in IKEv2 / IPsec endpoints.
    pub underlay_ip: Ipv4Addr,
}

/// Runtime configuration for one [`crate::OverlayNode`].
#[derive(Clone)]
pub struct NodeTransportConfig {
    /// Local node name (must exist in `peers` and Trust Registry v2).
    pub name: String,
    /// Local UDP socket bind address.
    pub bind_addr: SocketAddr,
    /// Complete peer directory keyed by node name.
    pub peers: BTreeMap<String, PeerEndpoint>,
    /// MCC fanout budget when initiating new IKEv2 or WireGuard control routes.
    pub fanout: MccFanout,
    /// MCC receiver-side selection policy.
    pub policy: SelectionPolicy,
    /// Per-attempt timeout for 4-step MGMT handshake steps in milliseconds.
    pub udp_timeout_ms: u64,
    /// Number of MGMT handshake retry attempts.
    pub retries: usize,
    /// Whether to proactively establish hop MGMT sessions to peers at startup.
    pub preconnect: bool,
    /// Optional deterministic seed for reproducible E2E tests.
    pub deterministic_seed: Option<u64>,
    /// Optional socket protector callback (e.g., Android `VpnService.protect`).
    pub socket_protector: Option<SocketProtector>,
}

impl fmt::Debug for NodeTransportConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeTransportConfig")
            .field("name", &self.name)
            .field("bind_addr", &self.bind_addr)
            .field("peers_count", &self.peers.len())
            .field("fanout", &self.fanout)
            .field("policy", &self.policy)
            .field("udp_timeout_ms", &self.udp_timeout_ms)
            .field("retries", &self.retries)
            .field("preconnect", &self.preconnect)
            .field("has_socket_protector", &self.socket_protector.is_some())
            .finish()
    }
}

impl NodeTransportConfig {
    /// Creates a standard transport configuration with safe defaults.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        bind_addr: SocketAddr,
        peers: BTreeMap<String, PeerEndpoint>,
    ) -> Self {
        Self {
            name: name.into(),
            bind_addr,
            peers,
            fanout: MccFanout::default(),
            policy: SelectionPolicy::default(),
            udp_timeout_ms: 1200,
            retries: 4,
            preconnect: true,
            deterministic_seed: None,
            socket_protector: None,
        }
    }
}
