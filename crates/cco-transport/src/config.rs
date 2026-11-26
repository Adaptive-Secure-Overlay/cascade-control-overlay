#![forbid(unsafe_code)]
//! Configuration structs for the overlay transport node.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use cco_cascade::mcc::{MccFanout, SelectionPolicy};
use cco_cascade::universal::{DEFAULT_MAX_HOPS, DEFAULT_PARALLEL_CHAINS, HopSelectionModel};
use serde::{Deserialize, Serialize};

/// Optional platform callback protecting outbound UDP sockets from VPN routing loops
/// (e.g., Android `VpnService.protect(fd)`).
pub type SocketProtector = Arc<dyn Fn(i32) -> bool + Send + Sync>;

/// Active control-plane routing architecture used when initiating local IKEv2 / WireGuard exchanges.
///
/// Note: every node's UDP receiver simultaneously handles both `MCC_*` and `CASCADE_*` frames so
/// intermediate relays remain 100% backward-compatible with existing 2-hop `mcc2` containers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum RouteMode {
    /// Classic 2-hop MCC (`A -> X1 -> X2 -> B`).
    #[serde(rename = "mcc2")]
    #[default]
    Mcc2,
    /// Universal H-hop Privacy Cascade (`A -> X1 -> ... -> Xm -> B`, `m = 2..max_hops`).
    #[serde(rename = "cascade")]
    Cascade,
}

impl RouteMode {
    /// Canonical lowercase identifier (`"mcc2"` or `"cascade"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mcc2 => "mcc2",
            Self::Cascade => "cascade",
        }
    }
}

/// Configuration for Universal H-hop Privacy Cascade (`RouteMode::Cascade`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CascadeTransportConfig {
    /// Desired number of intermediate relays `m` (`2..=max_hops`).
    pub hops: usize,
    /// Upper bound on hop count enforced by both endpoints and intermediate relays.
    pub max_hops: usize,
    /// Next-hop selection model (`F3NoRep` without repeats or `F4WithRep` with non-adjacent repeats).
    pub hop_model: HopSelectionModel,
    /// Number of parallel independent chains `K` launched on initiation (`O(K * m)` packet budget).
    pub parallel_chains: usize,
    /// Route lifetime in seconds.
    pub route_ttl_secs: f64,
}

impl Default for CascadeTransportConfig {
    fn default() -> Self {
        Self {
            hops: 3,
            max_hops: DEFAULT_MAX_HOPS,
            hop_model: HopSelectionModel::F4WithRep,
            parallel_chains: DEFAULT_PARALLEL_CHAINS,
            route_ttl_secs: 120.0,
        }
    }
}

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
    /// Routing engine selected for outbound local control-plane packets (`mcc2` or `cascade`).
    pub route_mode: RouteMode,
    /// Universal H-hop Cascade parameters (`hops`, `max_hops`, `hop_model`, `parallel_chains`).
    pub cascade: CascadeTransportConfig,
    /// MCC fanout budget when initiating new IKEv2 or WireGuard control routes in `mcc2` mode.
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
            .field("route_mode", &self.route_mode)
            .field("cascade", &self.cascade)
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
    /// Creates a standard transport configuration with safe defaults (`RouteMode::Mcc2`).
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
            route_mode: RouteMode::Mcc2,
            cascade: CascadeTransportConfig::default(),
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
