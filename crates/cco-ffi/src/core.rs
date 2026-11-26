#![forbid(unsafe_code)]
//! Pure safe FFI core logic backing the C-ABI (Windows/macOS) and Android JNI facades.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use cco_analytics::{
    RouteModel, compromise_metrics, f_i2p, simulate_compromise_monte_carlo, threshold_n50,
    uniform_entropy,
};
use cco_cascade::mcc::{EndpointSecurity, MccFanout, SelectionMode, SelectionPolicy};
use cco_cascade::universal::{DEFAULT_MAX_HOPS, DEFAULT_PARALLEL_CHAINS, HopSelectionModel};
use cco_crypto::{Ed25519SecretKey, X25519SecretKey, decode_canonical_hex};
use cco_transport::{
    CascadeTransportConfig, NodeTransportConfig, PeerEndpoint, RouteMode, SocketProtector,
};
use cco_trust::{
    NodeKeyRecord, RegistryStatus, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use cco_wg_tunnel::{
    ChannelTun, ChannelTunPeer, SanitizedEvent, SplitTunnelHandle, SplitWireGuardTunnel,
    TunnelStats, WgTunnelConfig,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Complete JSON configuration passed from GUI clients (Android/Windows/macOS) to start a tunnel.
#[derive(Debug, Clone, Deserialize)]
pub struct FfiTunnelConfig {
    pub node_name: String,
    pub peer_name: String,
    pub peers: Vec<PeerEndpoint>,
    pub trust_registry_json: String,
    pub trust_root_json: String,
    pub signing_key_hex: String,
    pub encryption_key_hex: String,
    pub wg_private_key_hex: String,
    pub peer_wg_public_key_hex: String,
    pub direct_bind_addr: SocketAddr,
    pub peer_direct_addr: SocketAddr,
    pub replay_db_path: PathBuf,
    #[serde(default = "default_mcc_mode")]
    pub mcc_mode: String,
    /// Control-plane routing architecture: `"mcc2"` (default) or `"cascade"` (Universal H-hop).
    #[serde(default = "default_route_mode")]
    pub route_mode: String,
    /// Number of intermediate cascade hops `m` (`2..=max_hops`) when `route_mode == "cascade"`.
    #[serde(default = "default_cascade_hops", alias = "hops")]
    pub cascade_hops: usize,
    /// Maximum permitted cascade hop count (`>= 2`).
    #[serde(default = "default_max_hops")]
    pub max_hops: usize,
    /// Next-hop selection model for `cascade`: `"f3"` (no repeats) or `"f4"` (with repeats).
    #[serde(default = "default_hop_model")]
    pub hop_model: String,
    /// Linear parallel independent chains `K` (`O(K * m)` budget) when `route_mode == "cascade"`.
    #[serde(default = "default_parallel_chains")]
    pub parallel_chains: usize,
    #[serde(default = "default_fanout")]
    pub x1_fanout: usize,
    #[serde(default = "default_fanout")]
    pub x2_fanout: usize,
    #[serde(default = "default_ike_fanout")]
    pub ike_fanout: usize,
    #[serde(default)]
    pub window_ms: u64,
    #[serde(default = "default_quiet_ms")]
    pub quiet_ms: u64,
    #[serde(default = "default_min_copies")]
    pub min_copies: usize,
    #[serde(default = "default_deadline_ms")]
    pub deadline_ms: u64,
    #[serde(default = "default_true")]
    pub preconnect: bool,
    #[serde(default)]
    pub initiate_handshake: bool,
    /// Set to `true` for macOS `utun` 4-byte AF header; `false` for Android `VpnService` & Linux.
    #[serde(default)]
    pub has_pi_header: bool,
}

fn default_mcc_mode() -> String {
    "adaptive".to_owned()
}
fn default_route_mode() -> String {
    "mcc2".to_owned()
}
const fn default_cascade_hops() -> usize {
    3
}
const fn default_max_hops() -> usize {
    DEFAULT_MAX_HOPS
}
fn default_hop_model() -> String {
    "f4".to_owned()
}
const fn default_parallel_chains() -> usize {
    DEFAULT_PARALLEL_CHAINS
}
const fn default_fanout() -> usize {
    2
}
const fn default_ike_fanout() -> usize {
    1
}
const fn default_quiet_ms() -> u64 {
    150
}
const fn default_min_copies() -> usize {
    3
}
const fn default_deadline_ms() -> u64 {
    12_000
}
const fn default_true() -> bool {
    true
}

/// Summary returned to GUI clients for the Chapter 3 Research Analytics tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FfiAnalyticsSummary {
    pub n: usize,
    pub m: usize,
    pub j: usize,
    pub i2p_routes: String,
    pub f1_routes: String,
    pub f3_routes: String,
    pub f4_routes: String,
    pub f1_entropy_bits: f64,
    pub f3_entropy_bits: f64,
    pub f4_entropy_bits: f64,
    pub f1_compromise_pct: f64,
    pub f3_compromise_pct: f64,
    pub f4_compromise_pct: f64,
    pub f1_n50: Option<usize>,
    pub f3_n50: Option<usize>,
    pub f4_n50: Option<usize>,
    pub f4_monte_carlo_pct: Option<f64>,
    pub f4_monte_carlo_abs_error: Option<f64>,
    pub f4_monte_carlo_ms: Option<f64>,
}

/// Verifies a signed Trust Registry v2 JSON payload against a pinned Trust Root v1 JSON payload.
pub fn verify_trust_bundle(
    registry_json: &str,
    root_json: &str,
    required_nodes: &[String],
) -> Result<RegistryStatus, String> {
    if required_nodes.is_empty() {
        return Err("empty_required_nodes".to_owned());
    }
    let dir = tempfile::TempDir::new().map_err(|_| "io_error".to_owned())?;
    let root_path = dir.path().join("root.json");
    std::fs::write(&root_path, root_json.as_bytes()).map_err(|_| "io_error".to_owned())?;
    let verified = verify_registry_bytes(
        registry_json.as_bytes(),
        &root_path,
        required_nodes.iter().map(String::as_str),
        VerifyConstraints::default(),
    )
    .map_err(|e| e.code().to_owned())?;
    Ok(verified.status())
}

/// Computes exact Chapter 3 combinatorics, compromise risk, `n50`, and a fast `rayon` Monte Carlo check.
pub fn run_analytics_summary(n: usize, m: usize, j: usize) -> Result<FfiAnalyticsSummary, String> {
    if n < 3 || j == 0 || j > 16 || m + 2 > n {
        return Err("invalid_analytics_parameters".to_owned());
    }
    let f1_u = uniform_entropy(RouteModel::F1Tor, n, j);
    let f3_u = uniform_entropy(RouteModel::F3NoRep, n, j);
    let f4_u = uniform_entropy(RouteModel::F4WithRep, n, j);
    let f1_c = compromise_metrics(RouteModel::F1Tor, n, m, j);
    let f3_c = compromise_metrics(RouteModel::F3NoRep, n, m, j);
    let f4_c = compromise_metrics(RouteModel::F4WithRep, n, m, j);
    let mc = simulate_compromise_monte_carlo(RouteModel::F4WithRep, n, m, j, 100_000, 42);

    Ok(FfiAnalyticsSummary {
        n,
        m,
        j,
        i2p_routes: f_i2p(n, j).to_string(),
        f1_routes: f1_u.total_routes,
        f3_routes: f3_u.total_routes,
        f4_routes: f4_u.total_routes,
        f1_entropy_bits: f1_u.h_uniform_bits.unwrap_or(0.0),
        f3_entropy_bits: f3_u.h_uniform_bits.unwrap_or(0.0),
        f4_entropy_bits: f4_u.h_uniform_bits.unwrap_or(0.0),
        f1_compromise_pct: f1_c.compromise_prob.unwrap_or(0.0) * 100.0,
        f3_compromise_pct: f3_c.compromise_prob.unwrap_or(0.0) * 100.0,
        f4_compromise_pct: f4_c.compromise_prob.unwrap_or(0.0) * 100.0,
        f1_n50: threshold_n50(RouteModel::F1Tor, m, j, 500),
        f3_n50: threshold_n50(RouteModel::F3NoRep, m, j, 500),
        f4_n50: threshold_n50(RouteModel::F4WithRep, m, j, 500),
        f4_monte_carlo_pct: mc.as_ref().map(|r| r.empirical_prob * 100.0),
        f4_monte_carlo_abs_error: mc.as_ref().map(|r| r.abs_error),
        f4_monte_carlo_ms: mc.as_ref().map(|r| r.elapsed_ms),
    })
}

/// Generates an ephemeral RFC 5737 4-node demo profile for GUI quick-start and diagnostics.
pub fn generate_local_demo_bundle(local_node: &str, peer_node: &str) -> Result<String, String> {
    if local_node.is_empty() || peer_node.is_empty() || local_node == peer_node {
        return Err("invalid_demo_nodes".to_owned());
    }
    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("demo-root".to_owned(), root_sk.public_key());
    let root_bytes = build_trust_root_bytes(&signers).map_err(|e| e.code().to_owned())?;
    let root_json = String::from_utf8(root_bytes).map_err(|_| "utf8_error".to_owned())?;

    let names = [local_node, "X1", "X2", peer_node];
    let mut records = BTreeMap::new();
    let mut peers = Vec::new();
    let mut local_signing = String::new();
    let mut local_encryption = String::new();

    for (idx, &name) in names.iter().enumerate() {
        let esk = Ed25519SecretKey::generate();
        let xsk = X25519SecretKey::generate();
        if name == local_node {
            local_signing = (*esk.to_hex_zeroizing()).clone();
            local_encryption = (*xsk.to_hex_zeroizing()).clone();
        }
        records.insert(
            name.to_owned(),
            NodeKeyRecord {
                encryption: xsk.public_key(),
                verification: esk.public_key(),
                key_id: esk.public_key().key_id(),
                revoked: false,
            },
        );
        let ip = Ipv4Addr::new(192, 0, 2, (10 + idx) as u8);
        peers.push(PeerEndpoint {
            name: name.to_owned(),
            overlay_addr: SocketAddr::from((ip, 9000)),
            underlay_ip: ip,
        });
    }

    let reg_bytes =
        sign_registry_v2(1, &records, "demo-root", &root_sk).map_err(|e| e.code().to_owned())?;
    let reg_json = String::from_utf8(reg_bytes).map_err(|_| "utf8_error".to_owned())?;

    let wg_local = X25519SecretKey::generate();
    let wg_peer = X25519SecretKey::generate();

    let out = serde_json::json!({
        "node_name": local_node,
        "peer_name": peer_node,
        "peers": peers,
        "trust_root_json": root_json,
        "trust_registry_json": reg_json,
        "signing_key_hex": local_signing,
        "encryption_key_hex": local_encryption,
        "wg_private_key_hex": *wg_local.to_hex_zeroizing(),
        "peer_wg_public_key_hex": wg_peer.public_key().to_hex(),
        "direct_bind_addr": "192.0.2.10:51820",
        "peer_direct_addr": "192.0.2.13:51820",
        "mcc_mode": "adaptive",
        "x1_fanout": 2,
        "x2_fanout": 2,
        "ike_fanout": 1,
    });
    serde_json::to_string_pretty(&out).map_err(|_| "json_error".to_owned())
}

/// Thread-safe handle owned by Android/Windows/macOS host applications.
pub struct CcoTunnelHandle {
    rt: tokio::runtime::Runtime,
    tunnel: SplitTunnelHandle,
    channel_peer: Option<ChannelTunPeer>,
}

impl CcoTunnelHandle {
    /// Starts a split tunnel backed by a safe in-memory IP packet channel (for Windows Wintun & tests).
    pub fn start_with_channel(config_json: &str) -> Result<Self, String> {
        let (cfg, security, initiate) = parse_and_verify_config(config_json, None)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| "runtime_init_failed".to_owned())?;

        let (tun, peer) = ChannelTun::pair(256);
        let tunnel = rt.block_on(async move {
            let h = SplitWireGuardTunnel::start(cfg, security, tun)
                .await
                .map_err(|e| e.code().to_owned())?;
            if initiate {
                let _ = h.initiate_handshake().await;
            }
            Ok::<_, String>(h)
        })?;

        Ok(Self {
            rt,
            tunnel,
            channel_peer: Some(peer),
        })
    }

    /// Starts a split tunnel attached to a Unix TUN `OwnedFd` (Android `VpnService`, Linux, macOS `utun`).
    #[cfg(unix)]
    pub fn start_with_fd(
        config_json: &str,
        tun_fd: std::os::fd::OwnedFd,
        socket_protector: Option<SocketProtector>,
    ) -> Result<Self, String> {
        let parsed_raw: FfiTunnelConfig =
            serde_json::from_str(config_json).map_err(|_| "invalid_config_json".to_owned())?;
        let has_pi_header = parsed_raw.has_pi_header;
        let (cfg, security, initiate) = parse_and_verify_config(config_json, socket_protector)?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| "runtime_init_failed".to_owned())?;

        let tun = cco_wg_tunnel::UnixFdTun::from_owned_fd(tun_fd, has_pi_header)
            .map_err(|_| "tun_fd_init_failed".to_owned())?;

        let tunnel = rt.block_on(async move {
            let h = SplitWireGuardTunnel::start(cfg, security, tun)
                .await
                .map_err(|e| e.code().to_owned())?;
            if initiate {
                let _ = h.initiate_handshake().await;
            }
            Ok::<_, String>(h)
        })?;

        Ok(Self {
            rt,
            tunnel,
            channel_peer: None,
        })
    }

    /// Proactively triggers a WireGuard Type 1 handshake through the MCC overlay.
    pub fn initiate_handshake(&self) -> Result<(), String> {
        self.rt
            .block_on(self.tunnel.initiate_handshake())
            .map_err(|e| e.code().to_owned())
    }

    /// Pushes one outbound L3 IP packet (Windows Wintun bridge). Returns `Ok(true)` if queued,
    /// `Ok(false)` if channel full.
    pub fn push_outbound_ip(&self, ip_packet: &[u8]) -> Result<bool, String> {
        let Some(ref peer) = self.channel_peer else {
            return Err("not_channel_tun".to_owned());
        };
        match peer.try_send_outbound_ip(ip_packet.to_vec()) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(_) => Err("tun_channel_closed".to_owned()),
        }
    }

    /// Non-blocking pop of one decrypted inbound L3 IP packet (Windows Wintun bridge).
    #[must_use]
    pub fn pop_inbound_ip(&self) -> Option<Vec<u8>> {
        self.channel_peer
            .as_ref()
            .and_then(ChannelTunPeer::try_recv_inbound_ip)
    }

    /// Returns live [`TunnelStats`] snapshot.
    #[must_use]
    pub fn stats(&self) -> TunnelStats {
        self.tunnel.stats()
    }

    /// Drains sanitized telemetry events.
    #[must_use]
    pub fn drain_events(&self) -> Vec<SanitizedEvent> {
        self.tunnel.drain_events()
    }

    /// Returns bound local overlay UDP address.
    #[must_use]
    pub fn overlay_local_addr(&self) -> SocketAddr {
        self.tunnel.overlay_local_addr()
    }

    /// Returns bound local direct UDP address.
    #[must_use]
    pub fn direct_local_addr(&self) -> SocketAddr {
        self.tunnel.direct_local_addr()
    }

    /// Cleanly stops the tunnel and shuts down background tasks.
    pub fn stop(self) {
        self.rt.block_on(self.tunnel.shutdown());
        drop(self.channel_peer);
        self.rt.shutdown_timeout(std::time::Duration::from_secs(2));
    }
}

fn parse_and_verify_config(
    config_json: &str,
    socket_protector: Option<SocketProtector>,
) -> Result<(WgTunnelConfig, EndpointSecurity, bool), String> {
    let raw: FfiTunnelConfig =
        serde_json::from_str(config_json).map_err(|_| "invalid_config_json".to_owned())?;

    let mut peers = BTreeMap::new();
    for p in raw.peers {
        peers.insert(p.name.clone(), p);
    }
    let self_peer = peers
        .get(&raw.node_name)
        .ok_or_else(|| "unknown_local_node".to_owned())?;
    let bind_addr = self_peer.overlay_addr;

    // Fail-closed Trust Registry v2 verification BEFORE opening any socket!
    let tmp_root = tempfile::TempDir::new().map_err(|_| "io_error".to_owned())?;
    let root_path = tmp_root.path().join("root.json");
    std::fs::write(&root_path, raw.trust_root_json.as_bytes())
        .map_err(|_| "io_error".to_owned())?;
    let required: Vec<&str> = peers.keys().map(String::as_str).collect();
    let verified = verify_registry_bytes(
        raw.trust_registry_json.as_bytes(),
        &root_path,
        required,
        VerifyConstraints::default(),
    )
    .map_err(|e| e.code().to_owned())?;
    let reg_status = verified.status();

    let signing_bytes = Zeroizing::new(
        decode_canonical_hex::<32>(&raw.signing_key_hex)
            .map_err(|_| "invalid_signing_key".to_owned())?,
    );
    let enc_bytes = Zeroizing::new(
        decode_canonical_hex::<32>(&raw.encryption_key_hex)
            .map_err(|_| "invalid_encryption_key".to_owned())?,
    );
    let wg_sk_bytes = Zeroizing::new(
        decode_canonical_hex::<32>(&raw.wg_private_key_hex)
            .map_err(|_| "invalid_wg_private_key".to_owned())?,
    );
    let peer_wg_pk = decode_canonical_hex::<32>(&raw.peer_wg_public_key_hex)
        .map_err(|_| "invalid_peer_wg_public_key".to_owned())?;

    let signing = Ed25519SecretKey::from_bytes(*signing_bytes);
    let encryption = X25519SecretKey::from_bytes(*enc_bytes);

    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let security = EndpointSecurity::new(
        &raw.node_name,
        verified,
        signing,
        encryption,
        &raw.replay_db_path,
        now_s,
    )
    .map_err(|e| e.code().to_owned())?;

    let mode = match raw.mcc_mode.as_str() {
        "first" => SelectionMode::First,
        "window" => SelectionMode::Window,
        "adaptive" => SelectionMode::Adaptive,
        "wait-all" | "wait_all" => SelectionMode::WaitAll,
        _ => return Err("unsupported_selection_mode".to_owned()),
    };
    let policy = SelectionPolicy {
        mode,
        window_ms: raw.window_ms,
        deadline_ms: raw.deadline_ms,
        min_copies: raw.min_copies,
        quiet_ms: raw.quiet_ms,
    };
    policy.validate().map_err(|e| e.code().to_owned())?;

    let route_mode = match raw.route_mode.as_str() {
        "mcc2" => RouteMode::Mcc2,
        "cascade" => RouteMode::Cascade,
        _ => return Err("unsupported_route_mode".to_owned()),
    };
    let hop_model = match raw.hop_model.as_str() {
        "f3" | "F3" => HopSelectionModel::F3NoRep,
        "f4" | "F4" => HopSelectionModel::F4WithRep,
        _ => return Err("unsupported_hop_model".to_owned()),
    };
    if route_mode == RouteMode::Cascade && (raw.cascade_hops < 2 || raw.cascade_hops > raw.max_hops)
    {
        return Err("invalid_hop_count".to_owned());
    }

    let mut overlay = NodeTransportConfig::new(&raw.node_name, bind_addr, peers);
    overlay.route_mode = route_mode;
    overlay.cascade = CascadeTransportConfig {
        hops: raw.cascade_hops,
        max_hops: raw.max_hops.max(raw.cascade_hops).max(2),
        hop_model,
        parallel_chains: raw.parallel_chains,
        route_ttl_secs: 120.0,
    };
    overlay.fanout = MccFanout {
        x1: raw.x1_fanout,
        x2: raw.x2_fanout,
        ike: raw.ike_fanout,
    };
    overlay.policy = policy;
    overlay.preconnect = raw.preconnect;
    overlay.socket_protector = socket_protector;

    let wg_cfg = WgTunnelConfig {
        peer_name: raw.peer_name,
        wg_private_key: wg_sk_bytes,
        peer_wg_public_key: peer_wg_pk,
        wg_preshared_key: None,
        direct_bind_addr: raw.direct_bind_addr,
        peer_direct_addr: raw.peer_direct_addr,
        persistent_keepalive_secs: Some(25),
        overlay,
        trust_registry_version: reg_status.version,
        trust_registry_sha256: reg_status.sha256,
    };

    Ok((wg_cfg, security, raw.initiate_handshake))
}
