#![forbid(unsafe_code)]
//! Configuration structs for the overlay transport node.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};

use cco_cascade::mcc::{MccFanout, SelectionPolicy};
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone)]
pub struct NodeTransportConfig {
    /// Local node name (must exist in `peers` and Trust Registry v2).
    pub name: String,
    /// Local UDP socket bind address.
    pub bind_addr: SocketAddr,
    /// Complete peer directory keyed by node name.
    pub peers: BTreeMap<String, PeerEndpoint>,
    /// MCC fanout budget when initiating new IKEv2 routes.
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
        }
    }
}
