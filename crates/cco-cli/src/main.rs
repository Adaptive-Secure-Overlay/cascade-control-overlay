#![forbid(unsafe_code)]
//! Unified `cco` command-line interface for Cascade Control Overlay.
//!
//! Subcommands:
//! - `node`: run an authenticated overlay mesh node (`cco-transport` + `cco-cascade`).
//! - `trust-admin`: offline Trust Registry v2 provisioning (`init-root`, `keygen`, `sign-registry`, `verify`, `install-update`).
//! - `wg-sim`: execute the canonical 27-scenario WireGuard handshake overlay matrix.
//! - `analytics`: exact Chapter 3 combinatorics, `n50` thresholds, and `rayon` Monte Carlo simulation.
//! - `bench`: cryptographic (X25519 vs RSA-3072) and Monte Carlo benchmarks.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use cco_analytics::{
    DEFAULT_MONTE_CARLO_TRIALS, RouteModel, compromise_metrics, f_i2p, run_crypto_benchmark,
    simulate_compromise_monte_carlo, threshold_n50, uniform_entropy,
};
use cco_cascade::mcc::{EndpointSecurity, MccFanout, SelectionMode, SelectionPolicy};
use cco_cascade::wireguard::{
    format_scenarios_csv, run_canonical_27_eve_results, run_canonical_27_scenarios,
};
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_linux_proxy::{
    DEFAULT_CAPTURE_BASE_500, DEFAULT_CAPTURE_BASE_4500, DEFAULT_SOCKET_MARK, IkeProxyConfig,
    LinuxIkeProxy, render_nftables_rules, render_xfrm_bypass_script,
};
use cco_transport::{IkeSink, NodeTransportConfig, OverlayNode, PeerEndpoint, RelayOnlySink};
use cco_trust::{
    TrustRegistryStore, VerifyConstraints, build_trust_root_bytes, generate_node_identity,
    read_ed25519_key_file, read_x25519_key_file, sign_registry_files, verify_registry_bytes,
};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "cco",
    version,
    about = "Cascade Control Overlay — MCC, Universal H-hop Cascade, WireGuard Overlay, and Chapter 3 Analytics"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run an authenticated overlay node daemon (fail-closed Trust Registry v2 gate).
    Node(NodeArgs),

    /// Offline Trust Registry v2 provisioning and verification tool.
    TrustAdmin {
        #[command(subcommand)]
        action: TrustAdminCmd,
    },

    /// Execute the canonical 27-scenario WireGuard handshake overlay verification matrix.
    WgSim {
        /// Output format: json, csv, or eve-json (schemas/eve-result.schema.json).
        #[arg(long, value_enum, default_value_t = WgSimFormat::Json)]
        format: WgSimFormat,
    },

    /// Generate a WireGuard X25519 keypair (private key written 0600 if --key-out is set).
    WgKeygen {
        #[arg(long)]
        key_out: Option<PathBuf>,
    },

    /// Run a live userspace WireGuard tunnel splitting control handshakes via MCC and data directly.
    WgTunnel(WgTunnelArgs),

    /// Chapter 3 route combinatorics, compromise probability, n50, and Monte Carlo simulator.
    Analytics {
        #[command(subcommand)]
        action: AnalyticsCmd,
    },

    /// Run cryptographic (X25519 vs RSA-3072) and Monte Carlo benchmarks.
    Bench {
        #[command(subcommand)]
        action: BenchCmd,
    },

    /// Render parameterized Linux `nftables` or `ip xfrm` scripts from a peers JSON file.
    RenderFirewall {
        #[arg(long)]
        name: String,
        #[arg(long)]
        peers: PathBuf,
        #[arg(long, value_enum, default_value_t = FirewallKind::Nft)]
        kind: FirewallKind,
        #[arg(long, default_value_t = 9000)]
        overlay_port: u16,
        #[arg(long, default_value_t = DEFAULT_CAPTURE_BASE_500)]
        capture_base_500: u16,
        #[arg(long, default_value_t = DEFAULT_CAPTURE_BASE_4500)]
        capture_base_4500: u16,
        #[arg(long, default_value_t = DEFAULT_SOCKET_MARK)]
        mark: u32,
    },
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum FirewallKind {
    Nft,
    Xfrm,
}

#[derive(Parser, Debug)]
struct NodeArgs {
    /// Logical name of this node (must match Trust Registry v2 and peers file).
    #[arg(long)]
    name: String,

    /// JSON file listing peers: `[{"name":"A","overlay_addr":"192.0.2.10:5001","underlay_ip":"192.0.2.10"}, ...]`.
    #[arg(long)]
    peers: PathBuf,

    /// Optional explicit UDP bind address (defaults to this node's `overlay_addr` in peers file).
    #[arg(long)]
    bind: Option<SocketAddr>,

    /// Path to signed Trust Registry v2 file.
    #[arg(long)]
    trust_registry: PathBuf,

    /// Path to pinned Trust Root v1 file.
    #[arg(long)]
    trust_root: PathBuf,

    /// Path to anti-rollback accepted state file (defaults to `<registry>.state.json`).
    #[arg(long)]
    trust_state: Option<PathBuf>,

    /// Path to last-valid backup registry file (defaults to `<registry>.last-valid.json`).
    #[arg(long)]
    trust_backup: Option<PathBuf>,

    /// Path to this node's Ed25519 private signing key (64 lowercase hex chars).
    #[arg(long)]
    signing_key: PathBuf,

    /// Path to this node's X25519 private encryption key (64 lowercase hex chars).
    #[arg(long)]
    encryption_key: PathBuf,

    /// Path to durable SQLite anti-replay ledger file.
    #[arg(long)]
    replay_db: PathBuf,

    /// Receiver-side MCC branch selection mode.
    #[arg(long, value_enum, default_value_t = CliSelectionMode::First)]
    mode: CliSelectionMode,

    #[arg(long, default_value_t = 3)]
    x1_fanout: usize,

    #[arg(long, default_value_t = 3)]
    x2_fanout: usize,

    #[arg(long, default_value_t = 1)]
    ike_fanout: usize,

    #[arg(long, default_value_t = 0)]
    window_ms: u64,

    #[arg(long, default_value_t = 150)]
    quiet_ms: u64,

    #[arg(long, default_value_t = 3)]
    min_copies: usize,

    #[arg(long, default_value_t = 12_000)]
    deadline_ms: u64,

    /// Disable proactive MGMT session preconnect at startup.
    #[arg(long)]
    no_preconnect: bool,

    /// Enable the Linux transparent IKEv2 capture/inject proxy backend (requires Linux + CAP_NET_RAW).
    #[arg(long)]
    ike_proxy: bool,

    #[arg(long, default_value_t = DEFAULT_CAPTURE_BASE_500)]
    ike_capture_base_500: u16,

    #[arg(long, default_value_t = DEFAULT_CAPTURE_BASE_4500)]
    ike_capture_base_4500: u16,

    #[arg(long, default_value_t = DEFAULT_SOCKET_MARK)]
    ike_mark: u32,

    /// Allow non-POSIX private key files for local test fixtures (Windows).
    #[arg(long)]
    test_fixtures: bool,
}

#[derive(Parser, Debug)]
struct WgTunnelArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    peer: String,
    #[arg(long)]
    peers: PathBuf,
    #[arg(long)]
    bind: Option<SocketAddr>,
    #[arg(long)]
    trust_registry: PathBuf,
    #[arg(long)]
    trust_root: PathBuf,
    #[arg(long)]
    trust_state: Option<PathBuf>,
    #[arg(long)]
    trust_backup: Option<PathBuf>,
    #[arg(long)]
    signing_key: PathBuf,
    #[arg(long)]
    encryption_key: PathBuf,
    #[arg(long)]
    replay_db: PathBuf,
    /// Path to 64-hex WireGuard static X25519 private key file.
    #[arg(long)]
    wg_private_key: PathBuf,
    /// Remote peer 64-hex WireGuard static X25519 public key.
    #[arg(long)]
    peer_wg_public_key: String,
    /// Local UDP socket address for direct WireGuard Type 4 transport data.
    #[arg(long)]
    direct_bind: SocketAddr,
    /// Remote peer UDP socket address for direct WireGuard Type 4 transport data.
    #[arg(long)]
    peer_direct_addr: SocketAddr,
    /// Linux TUN interface name to create/attach (e.g., `cco0`).
    #[arg(long, default_value = "cco0")]
    tun_name: String,
    #[arg(long, value_enum, default_value_t = CliSelectionMode::First)]
    mode: CliSelectionMode,
    #[arg(long, default_value_t = 2)]
    x1_fanout: usize,
    #[arg(long, default_value_t = 2)]
    x2_fanout: usize,
    #[arg(long, default_value_t = 1)]
    ike_fanout: usize,
    #[arg(long, default_value_t = 12_000)]
    deadline_ms: u64,
    /// Proactively initiate WireGuard Type 1 handshake through the MCC overlay on startup.
    #[arg(long)]
    initiate: bool,
    /// Optional path to periodically write JSON TunnelStats telemetry snapshots.
    #[arg(long)]
    stats_out: Option<PathBuf>,
    #[arg(long)]
    test_fixtures: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum CliSelectionMode {
    First,
    Window,
    Adaptive,
    WaitAll,
}

#[derive(Subcommand, Debug)]
enum TrustAdminCmd {
    /// Generate an offline Ed25519 root issuer key and pinned trust-root JSON file.
    InitRoot {
        #[arg(long)]
        issuer_id: String,
        #[arg(long)]
        key_out: PathBuf,
        #[arg(long)]
        root_out: PathBuf,
        #[arg(long)]
        test_fixtures: bool,
    },
    /// Generate separate Ed25519 signing and X25519 encryption keys for one node.
    Keygen {
        #[arg(long)]
        node: String,
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        test_fixtures: bool,
    },
    /// Sign a Trust Registry v2 document from node `public-entry.json` files.
    SignRegistry {
        #[arg(long, required = true, num_args = 2..)]
        entries: Vec<PathBuf>,
        #[arg(long)]
        trust_root: PathBuf,
        #[arg(long)]
        issuer_key: PathBuf,
        #[arg(long)]
        issuer_id: String,
        #[arg(long)]
        version: u64,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        test_fixtures: bool,
    },
    /// Verify a signed Trust Registry v2 document against a pinned root.
    Verify {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
        #[arg(long, value_delimiter = ',', required = true)]
        required_nodes: Vec<String>,
    },
    /// Atomically install a strictly newer signed registry update into a local store.
    InstallUpdate {
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
        #[arg(long)]
        state: PathBuf,
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
        #[arg(long, value_delimiter = ',', required = true)]
        required_nodes: Vec<String>,
    },
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum WgSimFormat {
    Json,
    Csv,
    EveJson,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
enum CliRouteModel {
    F1,
    F3,
    F4,
}

impl From<CliRouteModel> for RouteModel {
    fn from(value: CliRouteModel) -> Self {
        match value {
            CliRouteModel::F1 => Self::F1Tor,
            CliRouteModel::F3 => Self::F3NoRep,
            CliRouteModel::F4 => Self::F4WithRep,
        }
    }
}

#[derive(Subcommand, Debug)]
enum AnalyticsCmd {
    /// Compute exact route spaces (F1/Tor, I2P, F3, F4), uniform entropy, and optional compromise risk.
    Routes {
        #[arg(long)]
        n: usize,
        #[arg(long)]
        j: usize,
        #[arg(long)]
        m: Option<usize>,
    },
    /// Compute exact minimum network size `n50` keeping compromise risk <= 50%.
    N50 {
        #[arg(long)]
        m: usize,
        #[arg(long)]
        j: usize,
        #[arg(long, default_value_t = 1000)]
        max_n: usize,
    },
    /// Run multi-threaded `rayon` Monte Carlo compromise verification.
    MonteCarlo {
        #[arg(long, value_enum, default_value_t = CliRouteModel::F4)]
        model: CliRouteModel,
        #[arg(long)]
        n: usize,
        #[arg(long)]
        m: usize,
        #[arg(long)]
        j: usize,
        #[arg(long, default_value_t = DEFAULT_MONTE_CARLO_TRIALS)]
        trials: usize,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
}

#[derive(Subcommand, Debug)]
enum BenchCmd {
    /// Benchmark X25519 + HKDF-SHA256 + AES-128/256-GCM vs RSA-3072 OAEP and Ed25519 (Table 4.6).
    Crypto {
        #[arg(long, default_value_t = 200)]
        iters: usize,
        #[arg(long, default_value_t = 10)]
        rsa_iters: usize,
        #[arg(long, default_value_t = 1024)]
        payload_bytes: usize,
        #[arg(long)]
        include_rsa: bool,
    },
    /// Benchmark parallel `rayon` Monte Carlo throughput across F1, F3, and F4.
    MonteCarlo {
        #[arg(long, default_value_t = DEFAULT_MONTE_CARLO_TRIALS)]
        trials: usize,
        #[arg(long, default_value_t = 10)]
        n: usize,
        #[arg(long, default_value_t = 2)]
        m: usize,
        #[arg(long, default_value_t = 3)]
        j: usize,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => {
            // Fail-closed structured error without raw key material or untrusted input.
            eprintln!("{}", json!({"failed": true, "error": code}));
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Node(args) => run_node(args).await,
        Commands::TrustAdmin { action } => run_trust_admin(action),
        Commands::WgSim { format } => run_wg_sim(format),
        Commands::WgKeygen { key_out } => run_wg_keygen(key_out.as_deref()),
        Commands::WgTunnel(args) => run_wg_tunnel(args).await,
        Commands::Analytics { action } => run_analytics(action),
        Commands::Bench { action } => run_bench(action),
        Commands::RenderFirewall {
            name,
            peers,
            kind,
            overlay_port,
            capture_base_500,
            capture_base_4500,
            mark,
        } => run_render_firewall(
            &name,
            &peers,
            kind,
            overlay_port,
            capture_base_500,
            capture_base_4500,
            mark,
        ),
    }
}

async fn run_node(args: NodeArgs) -> Result<(), String> {
    let raw_peers = fs::read(&args.peers).map_err(|_| "peers_file_unavailable".to_owned())?;
    let peer_list: Vec<PeerEndpoint> =
        serde_json::from_slice(&raw_peers).map_err(|_| "invalid_peers_json".to_owned())?;
    let mut peers = BTreeMap::new();
    for p in peer_list {
        peers.insert(p.name.clone(), p);
    }
    let self_peer = peers
        .get(&args.name)
        .ok_or_else(|| "unknown_local_node".to_owned())?;
    let bind_addr = args.bind.unwrap_or(self_peer.overlay_addr);

    let state_path = args
        .trust_state
        .unwrap_or_else(|| PathBuf::from(format!("{}.state.json", args.trust_registry.display())));
    let backup_path = args.trust_backup.unwrap_or_else(|| {
        PathBuf::from(format!("{}.last-valid.json", args.trust_registry.display()))
    });

    // Fail-closed Trust Registry v2 gate BEFORE opening UDP socket!
    let store = TrustRegistryStore::new(
        &args.trust_registry,
        &args.trust_root,
        state_path,
        backup_path,
    );
    let required: Vec<&str> = peers.keys().map(String::as_str).collect();
    let verified = store.load(required).map_err(|e| e.code().to_owned())?;

    let signing = read_ed25519_key_file(&args.signing_key, args.test_fixtures)
        .map_err(|e| e.code().to_owned())?;
    let encryption = read_x25519_key_file(&args.encryption_key, args.test_fixtures)
        .map_err(|e| e.code().to_owned())?;

    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let security = EndpointSecurity::new(
        &args.name,
        verified,
        signing,
        encryption,
        &args.replay_db,
        now_s,
    )
    .map_err(|e| e.code().to_owned())?;

    let mode = match args.mode {
        CliSelectionMode::First => SelectionMode::First,
        CliSelectionMode::Window => SelectionMode::Window,
        CliSelectionMode::Adaptive => SelectionMode::Adaptive,
        CliSelectionMode::WaitAll => SelectionMode::WaitAll,
    };
    let policy = SelectionPolicy {
        mode,
        window_ms: args.window_ms,
        deadline_ms: args.deadline_ms,
        min_copies: args.min_copies,
        quiet_ms: args.quiet_ms,
    };
    policy.validate().map_err(|e| e.code().to_owned())?;

    let peer_ips: BTreeMap<String, std::net::Ipv4Addr> = peers
        .iter()
        .map(|(k, v)| (k.clone(), v.underlay_ip))
        .collect();
    let mut cfg = NodeTransportConfig::new(&args.name, bind_addr, peers);
    cfg.fanout = MccFanout {
        x1: args.x1_fanout,
        x2: args.x2_fanout,
        ike: args.ike_fanout,
    };
    cfg.policy = policy;
    cfg.preconnect = !args.no_preconnect;

    let (sink, maybe_proxy): (Arc<dyn IkeSink>, Option<Arc<LinuxIkeProxy>>) = if args.ike_proxy {
        let proxy_cfg = IkeProxyConfig::from_peers(
            &args.name,
            peer_ips,
            args.ike_capture_base_500,
            args.ike_capture_base_4500,
            args.ike_mark,
        )
        .map_err(|e| e.to_string())?;
        let proxy = Arc::new(LinuxIkeProxy::new(proxy_cfg));
        let sink_arc: Arc<dyn IkeSink> = proxy.clone();
        (sink_arc, Some(proxy))
    } else {
        (Arc::new(RelayOnlySink), None)
    };

    let handle = OverlayNode::start(cfg, security, sink)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(ref proxy) = maybe_proxy {
        proxy
            .start_capture(handle.clone())
            .map_err(|e| e.to_string())?;
    }
    println!(
        "{}",
        json!({
            "started": true,
            "node": handle.name(),
            "bind_addr": handle.local_addr().to_string(),
            "ike_proxy": args.ike_proxy,
        })
    );

    let _ = tokio::signal::ctrl_c().await;
    if let Some(ref proxy) = maybe_proxy {
        proxy.stop();
    }
    handle.shutdown().await;
    Ok(())
}

fn run_render_firewall(
    name: &str,
    peers_path: &Path,
    kind: FirewallKind,
    overlay_port: u16,
    base_500: u16,
    base_4500: u16,
    mark: u32,
) -> Result<(), String> {
    let raw = fs::read(peers_path).map_err(|_| "peers_file_unavailable".to_owned())?;
    let peer_list: Vec<PeerEndpoint> =
        serde_json::from_slice(&raw).map_err(|_| "invalid_peers_json".to_owned())?;
    let peer_ips: BTreeMap<String, std::net::Ipv4Addr> = peer_list
        .into_iter()
        .map(|p| (p.name, p.underlay_ip))
        .collect();
    let cfg = IkeProxyConfig::from_peers(name, peer_ips, base_500, base_4500, mark)
        .map_err(|e| e.to_string())?;
    match kind {
        FirewallKind::Nft => print!("{}", render_nftables_rules(&cfg)),
        FirewallKind::Xfrm => print!("{}", render_xfrm_bypass_script(&cfg, overlay_port, 1)),
    }
    Ok(())
}

fn run_trust_admin(action: TrustAdminCmd) -> Result<(), String> {
    match action {
        TrustAdminCmd::InitRoot {
            issuer_id,
            key_out,
            root_out,
            test_fixtures,
        } => {
            if !cfg!(unix) && !test_fixtures {
                return Err("private_file_permissions".to_owned());
            }
            if key_out.exists() || root_out.exists() {
                return Err("output_already_exists".to_owned());
            }
            let sk = Ed25519SecretKey::generate();
            let key_hex = sk.to_hex_zeroizing();
            write_exclusive(&key_out, format!("{}\n", *key_hex).as_bytes(), true)?;
            let mut signers = BTreeMap::new();
            signers.insert(issuer_id.clone(), sk.public_key());
            let mut root_bytes =
                build_trust_root_bytes(&signers).map_err(|e| e.code().to_owned())?;
            root_bytes.push(b'\n');
            write_exclusive(&root_out, &root_bytes, false)?;
            println!(
                "{}",
                json!({
                    "initialized": true,
                    "issuer_id": issuer_id,
                    "public_key_hex": sk.public_key().to_hex(),
                    "key_id": sk.public_key().key_id(),
                })
            );
            Ok(())
        }
        TrustAdminCmd::Keygen {
            node,
            directory,
            test_fixtures,
        } => {
            let summary = generate_node_identity(&node, &directory, test_fixtures)
                .map_err(|e| e.code().to_owned())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
        TrustAdminCmd::SignRegistry {
            entries,
            trust_root,
            issuer_key,
            issuer_id,
            version,
            output,
            test_fixtures,
        } => {
            let entry_refs: Vec<&Path> = entries.iter().map(PathBuf::as_path).collect();
            let summary = sign_registry_files(
                &entry_refs,
                &trust_root,
                &issuer_key,
                &issuer_id,
                version,
                &output,
                test_fixtures,
            )
            .map_err(|e| e.code().to_owned())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&summary).map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
        TrustAdminCmd::Verify {
            registry,
            trust_root,
            required_nodes,
        } => {
            let raw = fs::read(&registry).map_err(|_| "missing_document".to_owned())?;
            let verified = verify_registry_bytes(
                &raw,
                &trust_root,
                required_nodes.iter().map(String::as_str),
                VerifyConstraints::default(),
            )
            .map_err(|e| e.code().to_owned())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verified.status())
                    .map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
        TrustAdminCmd::InstallUpdate {
            registry,
            trust_root,
            state,
            backup,
            candidate,
            required_nodes,
        } => {
            let store = TrustRegistryStore::new(registry, trust_root, state, backup);
            let updated = store
                .install_update(&candidate, required_nodes.iter().map(String::as_str))
                .map_err(|e| e.code().to_owned())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&updated.status())
                    .map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
    }
}

fn run_wg_keygen(key_out: Option<&Path>) -> Result<(), String> {
    let sk = X25519SecretKey::generate();
    let pk_hex = sk.public_key().to_hex();
    let sk_hex = sk.to_hex_zeroizing();
    if let Some(path) = key_out {
        write_exclusive(path, format!("{}\n", *sk_hex).as_bytes(), true)?;
        println!("{}", json!({ "generated": true, "public_key_hex": pk_hex }));
    } else {
        println!(
            "{}",
            json!({ "private_key_hex": *sk_hex, "public_key_hex": pk_hex })
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_wg_tunnel(args: WgTunnelArgs) -> Result<(), String> {
    use cco_crypto::decode_canonical_hex;
    use cco_wg_tunnel::{SplitWireGuardTunnel, UnixFdTun, WgTunnelConfig};
    use zeroize::Zeroizing;

    let raw_peers = fs::read(&args.peers).map_err(|_| "peers_file_unavailable".to_owned())?;
    let peer_list: Vec<PeerEndpoint> =
        serde_json::from_slice(&raw_peers).map_err(|_| "invalid_peers_json".to_owned())?;
    let mut peers = BTreeMap::new();
    for p in peer_list {
        peers.insert(p.name.clone(), p);
    }
    let self_peer = peers
        .get(&args.name)
        .ok_or_else(|| "unknown_local_node".to_owned())?;
    let bind_addr = args.bind.unwrap_or(self_peer.overlay_addr);

    let state_path = args
        .trust_state
        .unwrap_or_else(|| PathBuf::from(format!("{}.state.json", args.trust_registry.display())));
    let backup_path = args.trust_backup.unwrap_or_else(|| {
        PathBuf::from(format!("{}.last-valid.json", args.trust_registry.display()))
    });

    let store = TrustRegistryStore::new(
        &args.trust_registry,
        &args.trust_root,
        state_path,
        backup_path,
    );
    let required: Vec<&str> = peers.keys().map(String::as_str).collect();
    let verified = store.load(required).map_err(|e| e.code().to_owned())?;
    let reg_status = verified.status();

    let signing = read_ed25519_key_file(&args.signing_key, args.test_fixtures)
        .map_err(|e| e.code().to_owned())?;
    let encryption = read_x25519_key_file(&args.encryption_key, args.test_fixtures)
        .map_err(|e| e.code().to_owned())?;
    let wg_sk = read_x25519_key_file(&args.wg_private_key, args.test_fixtures)
        .map_err(|e| e.code().to_owned())?;
    let peer_wg_pk = decode_canonical_hex::<32>(&args.peer_wg_public_key)
        .map_err(|_| "invalid_peer_wg_public_key".to_owned())?;

    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let security = EndpointSecurity::new(
        &args.name,
        verified,
        signing,
        encryption,
        &args.replay_db,
        now_s,
    )
    .map_err(|e| e.code().to_owned())?;

    let mode = match args.mode {
        CliSelectionMode::First => SelectionMode::First,
        CliSelectionMode::Window => SelectionMode::Window,
        CliSelectionMode::Adaptive => SelectionMode::Adaptive,
        CliSelectionMode::WaitAll => SelectionMode::WaitAll,
    };
    let policy = SelectionPolicy {
        mode,
        window_ms: 0,
        deadline_ms: args.deadline_ms,
        min_copies: 3,
        quiet_ms: 150,
    };
    policy.validate().map_err(|e| e.code().to_owned())?;

    let mut overlay = NodeTransportConfig::new(&args.name, bind_addr, peers);
    overlay.fanout = MccFanout {
        x1: args.x1_fanout,
        x2: args.x2_fanout,
        ike: args.ike_fanout,
    };
    overlay.policy = policy;

    let tun_fd = cco_linux_proxy::open_linux_tun(&args.tun_name).map_err(|e| e.to_string())?;
    let tun = UnixFdTun::from_owned_fd(tun_fd, false).map_err(|_| "tun_init_failed".to_owned())?;

    let handle = SplitWireGuardTunnel::start(
        WgTunnelConfig {
            peer_name: args.peer.clone(),
            wg_private_key: Zeroizing::new(*wg_sk.to_bytes_zeroizing()),
            peer_wg_public_key: peer_wg_pk,
            wg_preshared_key: None,
            direct_bind_addr: args.direct_bind,
            peer_direct_addr: args.peer_direct_addr,
            persistent_keepalive_secs: Some(25),
            overlay,
            trust_registry_version: reg_status.version,
            trust_registry_sha256: reg_status.sha256,
        },
        security,
        tun,
    )
    .await
    .map_err(|e| e.code().to_owned())?;

    println!(
        "{}",
        json!({
            "started": true,
            "node": args.name,
            "peer": args.peer,
            "tun": args.tun_name,
            "overlay_addr": handle.overlay_local_addr().to_string(),
            "direct_addr": handle.direct_local_addr().to_string(),
        })
    );

    if args.initiate {
        tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        let _ = handle.initiate_handshake().await;
    }

    let stats_path = args.stats_out.clone();
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(500));
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if let Some(ref p) = stats_path {
                    if let Ok(bytes) = serde_json::to_vec_pretty(&handle.stats()) {
                        let _ = fs::write(p, bytes);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = async {
                if let Some(ref mut s) = sigterm {
                    s.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => break,
        }
    }

    if let Some(ref p) = stats_path {
        if let Ok(bytes) = serde_json::to_vec_pretty(&handle.stats()) {
            let _ = fs::write(p, bytes);
        }
    }
    handle.shutdown().await;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
async fn run_wg_tunnel(_args: WgTunnelArgs) -> Result<(), String> {
    Err("unsupported_platform_use_gui_or_linux_tun".to_owned())
}

fn run_wg_sim(format: WgSimFormat) -> Result<(), String> {
    match format {
        WgSimFormat::Json => {
            let rows = run_canonical_27_scenarios();
            println!(
                "{}",
                serde_json::to_string_pretty(&rows).map_err(|_| "json_error".to_owned())?
            );
        }
        WgSimFormat::Csv => {
            let rows = run_canonical_27_scenarios();
            print!("{}", format_scenarios_csv(&rows));
        }
        WgSimFormat::EveJson => {
            let results = run_canonical_27_eve_results();
            println!(
                "{}",
                serde_json::to_string_pretty(&results).map_err(|_| "json_error".to_owned())?
            );
        }
    }
    Ok(())
}

fn run_analytics(action: AnalyticsCmd) -> Result<(), String> {
    match action {
        AnalyticsCmd::Routes { n, j, m } => {
            let f1 = uniform_entropy(RouteModel::F1Tor, n, j);
            let f3 = uniform_entropy(RouteModel::F3NoRep, n, j);
            let f4 = uniform_entropy(RouteModel::F4WithRep, n, j);
            let i2p_total = f_i2p(n, j).to_string();
            let compromise = m.map(|m_val| {
                json!({
                    "F1": compromise_metrics(RouteModel::F1Tor, n, m_val, j),
                    "F3": compromise_metrics(RouteModel::F3NoRep, n, m_val, j),
                    "F4": compromise_metrics(RouteModel::F4WithRep, n, m_val, j),
                })
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "n": n,
                    "j": j,
                    "i2p_total_routes": i2p_total,
                    "models": { "F1": f1, "F3": f3, "F4": f4 },
                    "compromise": compromise,
                }))
                .map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
        AnalyticsCmd::N50 { m, j, max_n } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "m": m,
                    "j": j,
                    "n50": {
                        "F1": threshold_n50(RouteModel::F1Tor, m, j, max_n),
                        "F3": threshold_n50(RouteModel::F3NoRep, m, j, max_n),
                        "F4": threshold_n50(RouteModel::F4WithRep, m, j, max_n),
                    }
                }))
                .map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
        AnalyticsCmd::MonteCarlo {
            model,
            n,
            m,
            j,
            trials,
            seed,
        } => {
            let report = simulate_compromise_monte_carlo(model.into(), n, m, j, trials, seed)
                .ok_or_else(|| "invalid_monte_carlo_parameters".to_owned())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
    }
}

fn run_bench(action: BenchCmd) -> Result<(), String> {
    match action {
        BenchCmd::Crypto {
            iters,
            rsa_iters,
            payload_bytes,
            include_rsa,
        } => {
            let report = run_crypto_benchmark(iters, rsa_iters, payload_bytes, include_rsa);
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
        BenchCmd::MonteCarlo { trials, n, m, j } => {
            let reports: Vec<_> = [
                RouteModel::F1Tor,
                RouteModel::F3NoRep,
                RouteModel::F4WithRep,
            ]
            .into_iter()
            .filter_map(|model| {
                simulate_compromise_monte_carlo(model, n, m, j, trials, 42 + model as u64)
            })
            .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&reports).map_err(|_| "json_error".to_owned())?
            );
            Ok(())
        }
    }
}

fn write_exclusive(path: &Path, data: &[u8], private: bool) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|_| "io_error".to_owned())?;
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    let _ = private;
    let mut file = opts.open(path).map_err(|_| "io_error".to_owned())?;
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .map_err(|_| "io_error".to_owned())
}
