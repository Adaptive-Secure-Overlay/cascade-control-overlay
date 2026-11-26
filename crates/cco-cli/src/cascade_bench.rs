#![forbid(unsafe_code)]
//! Live multi-node localhost UDP benchmark (`cco bench cascade`) evaluating
//! Universal H-hop Privacy Cascade across `m = 2, 3, 5, 7, 10` for both IPsec (IKEv2)
//! and WireGuard (`boringtun`), paired with exact `cco-analytics` F1/F3/F4 compromise
//! probabilities to build the "Security vs Startup Latency" curve.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cco_analytics::{RouteModel, compromise_metrics, uniform_entropy};
use cco_cascade::mcc::{
    DeliveredIkeMeta, DeliveryReceipt, EndpointSecurity, IkeInjectionOutcome, LocalDeliveryProof,
};
use cco_cascade::universal::HopSelectionModel;
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_proto::{
    IKE_AUTH, IKE_SA_INIT, IKEV2_FLAG_INITIATOR, IKEV2_FLAG_RESPONSE, parse_ikev2_packet,
};
use cco_transport::{
    CascadeTransportConfig, IkeSink, NodeTransportConfig, OverlayNode, OverlayNodeHandle,
    PeerEndpoint, RelayOnlySink, RouteMode, TransportCounters,
};
use cco_trust::{
    NodeKeyRecord, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use cco_wg_tunnel::{ChannelTun, SplitWireGuardTunnel, WgTunnelConfig};
use serde::Serialize;
use tempfile::TempDir;
use tokio::sync::Notify;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchProtocolFilter {
    Both,
    Ipsec,
    Wireguard,
}

#[derive(Debug, Clone, Serialize)]
pub struct CascadeBenchPoint {
    pub protocol: String,
    pub nodes: usize,
    pub hops: usize,
    pub compromised_nodes: usize,
    pub hop_model: String,
    pub parallel_chains: usize,
    pub trials: usize,
    pub handshake_ms_median: f64,
    pub handshake_ms_mean: f64,
    pub handshake_ms_min: f64,
    pub handshake_ms_max: f64,
    pub overlay_udp_packets_avg: f64,
    pub overlay_udp_kib_avg: f64,
    pub cascade_msgs_tx_avg: f64,
    pub active_relay_cells: usize,
    pub direct_control_leaks: u64,
    pub rss_mib: f64,
    pub f1_compromise_pct: Option<f64>,
    pub f3_compromise_pct: Option<f64>,
    pub f4_compromise_pct: Option<f64>,
    pub f3_entropy_bits: Option<f64>,
    pub f4_entropy_bits: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CascadeBenchReport {
    pub benchmark: String,
    pub nodes: usize,
    pub compromised_nodes: usize,
    pub hop_model: String,
    pub parallel_chains: usize,
    pub trials: usize,
    pub points: Vec<CascadeBenchPoint>,
}

fn pick_free_udp_ports(count: usize) -> Result<Vec<u16>, String> {
    let mut sockets = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        let s =
            StdUdpSocket::bind("127.0.0.1:0").map_err(|_| "udp_port_alloc_failed".to_owned())?;
        ports.push(
            s.local_addr()
                .map_err(|_| "udp_port_alloc_failed".to_owned())?
                .port(),
        );
        sockets.push(s);
    }
    drop(sockets);
    Ok(ports)
}

fn build_ikev2(
    udp_port: u16,
    exchange: u8,
    msg_id: u32,
    response: bool,
    spi: [u8; 8],
    tail: &[u8],
) -> Vec<u8> {
    let mut hdr = vec![0u8; 28 + tail.len()];
    hdr[0..8].copy_from_slice(&spi);
    hdr[16] = 33;
    hdr[17] = 0x20;
    hdr[18] = exchange;
    hdr[19] = if response {
        IKEV2_FLAG_RESPONSE
    } else {
        IKEV2_FLAG_INITIATOR
    };
    hdr[20..24].copy_from_slice(&msg_id.to_be_bytes());
    let len = hdr.len() as u32;
    hdr[24..28].copy_from_slice(&len.to_be_bytes());
    hdr[28..].copy_from_slice(tail);
    if udp_port == 4500 {
        let mut out = vec![0u8; 4];
        out.extend_from_slice(&hdr);
        out
    } else {
        hdr
    }
}

fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len as usize];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let mut sum: u32 = 0;
    for chunk in pkt[..20].chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// Safe cross-platform OS resident set size (RSS / Working Set) measurement in MiB (`#![forbid(unsafe_code)]`).
fn measure_rss_mib() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    if let Some(kib_str) = rest.split_whitespace().next() {
                        if let Ok(kib) = kib_str.parse::<f64>() {
                            return (kib / 1024.0 * 100.0).round() / 100.0;
                        }
                    }
                }
            }
        }
        0.0
    }
    #[cfg(target_os = "macos")]
    {
        let pid = std::process::id().to_string();
        if let Ok(out) = Command::new("ps").args(["-o", "rss=", "-p", &pid]).output() {
            if let Ok(txt) = String::from_utf8(out.stdout) {
                if let Ok(kib) = txt.trim().parse::<f64>() {
                    return (kib / 1024.0 * 100.0).round() / 100.0;
                }
            }
        }
        0.0
    }
    #[cfg(target_os = "windows")]
    {
        let pid = std::process::id();
        let filter = format!("PID eq {pid}");
        if let Ok(out) = Command::new("tasklist")
            .args(["/FI", &filter, "/FO", "CSV", "/NH"])
            .output()
        {
            if let Ok(txt) = String::from_utf8(out.stdout) {
                // CSV last field is memory in KB (e.g., `"42,128 K"` or `"42 128 КБ"`).
                if let Some(last_col) = txt.trim().rsplit(',').next() {
                    let digits: String = last_col.chars().filter(char::is_ascii_digit).collect();
                    if let Ok(kib) = digits.parse::<f64>() {
                        return (kib / 1024.0 * 100.0).round() / 100.0;
                    }
                }
            }
        }
        0.0
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        0.0
    }
}

fn sum_counters<'a>(handles: impl Iterator<Item = &'a OverlayNodeHandle>) -> TransportCounters {
    let mut acc = TransportCounters::default();
    for h in handles {
        let c = h.counters();
        acc.udp_packets_tx += c.udp_packets_tx;
        acc.udp_packets_rx += c.udp_packets_rx;
        acc.udp_bytes_tx += c.udp_bytes_tx;
        acc.udp_bytes_rx += c.udp_bytes_rx;
        acc.cascade_msgs_tx += c.cascade_msgs_tx;
        acc.cascade_msgs_rx += c.cascade_msgs_rx;
        acc.mcc_msgs_tx += c.mcc_msgs_tx;
        acc.mcc_msgs_rx += c.mcc_msgs_rx;
    }
    acc
}

fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    }
}

struct BenchIkeSink {
    delivered: Arc<StdMutex<Vec<(String, DeliveredIkeMeta)>>>,
    notify: Arc<Notify>,
    node_name: String,
    handle_slot: Arc<StdMutex<Option<OverlayNodeHandle>>>,
    auto_reply: bool,
}

impl IkeSink for BenchIkeSink {
    fn deliver(&self, proof: LocalDeliveryProof) -> (IkeInjectionOutcome, DeliveryReceipt) {
        let (payload, meta, receipt) = proof.consume();
        self.delivered
            .lock()
            .unwrap()
            .push((self.node_name.clone(), meta.clone()));
        self.notify.notify_waiters();
        if self.auto_reply && meta.direction == "fwd" {
            if let Some(h) = self.handle_slot.lock().unwrap().clone() {
                if let Ok(hdr) = parse_ikev2_packet(meta.udp_port, &payload) {
                    let resp = build_ikev2(
                        meta.udp_port,
                        hdr.exchange_type,
                        hdr.message_id,
                        true,
                        hdr.initiator_spi,
                        &[0x55u8; 200],
                    );
                    let dst = meta.src.clone();
                    let port = meta.udp_port;
                    tokio::spawn(async move {
                        let _ = h.send_local_ike(&dst, resp, port).await;
                    });
                }
            }
        }
        (IkeInjectionOutcome::Sent, receipt)
    }
}

struct ProvisionedPool {
    dir: TempDir,
    names: Vec<String>,
    peers: BTreeMap<String, PeerEndpoint>,
    signing: BTreeMap<String, Ed25519SecretKey>,
    encryption: BTreeMap<String, X25519SecretKey>,
    verified: cco_trust::VerifiedRegistry,
    extra_ports: Vec<u16>,
}

fn provision_pool(nodes: usize, extra_udp_ports: usize) -> Result<ProvisionedPool, String> {
    let dir = TempDir::new().map_err(|_| "tempdir_failed".to_owned())?;
    let names: Vec<String> = std::iter::once("A".to_owned())
        .chain((1..=nodes - 2).map(|i| format!("X{i}")))
        .chain(std::iter::once("B".to_owned()))
        .collect();

    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("bench-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    let root_bytes = build_trust_root_bytes(&signers).map_err(|e| e.code().to_owned())?;
    fs::write(&root_path, root_bytes).map_err(|_| "io_error".to_owned())?;

    let all_ports = pick_free_udp_ports(nodes + extra_udp_ports)?;
    let mut signing = BTreeMap::new();
    let mut encryption = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut peers = BTreeMap::new();

    for (i, name) in names.iter().enumerate() {
        let esk = Ed25519SecretKey::generate();
        let xsk = X25519SecretKey::generate();
        records.insert(
            name.clone(),
            NodeKeyRecord {
                encryption: xsk.public_key(),
                verification: esk.public_key(),
                key_id: esk.public_key().key_id(),
                revoked: false,
            },
        );
        signing.insert(name.clone(), esk);
        encryption.insert(name.clone(), xsk);
        peers.insert(
            name.clone(),
            PeerEndpoint {
                name: name.clone(),
                overlay_addr: SocketAddr::from(([127, 0, 0, 1], all_ports[i])),
                underlay_ip: Ipv4Addr::new(192, 0, 2, (10 + i) as u8),
            },
        );
    }

    let reg_bytes =
        sign_registry_v2(1, &records, "bench-root", &root_sk).map_err(|e| e.code().to_owned())?;
    let verified = verify_registry_bytes(
        &reg_bytes,
        &root_path,
        names.iter().map(String::as_str),
        VerifyConstraints::default(),
    )
    .map_err(|e| e.code().to_owned())?;

    Ok(ProvisionedPool {
        dir,
        names,
        peers,
        signing,
        encryption,
        verified,
        extra_ports: all_ports[nodes..].to_vec(),
    })
}

impl ProvisionedPool {
    fn security_for(&self, name: &str, suffix: &str) -> Result<EndpointSecurity, String> {
        let now_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        EndpointSecurity::new(
            name,
            self.verified.clone(),
            Ed25519SecretKey::from_bytes(*self.signing[name].to_bytes_zeroizing()),
            X25519SecretKey::from_bytes(*self.encryption[name].to_bytes_zeroizing()),
            self.dir.path().join(format!("{name}_{suffix}.sqlite")),
            now_s,
        )
        .map_err(|e| e.code().to_owned())
    }
}

async fn bench_ipsec_point(
    nodes: usize,
    hops: usize,
    compromised: usize,
    hop_model: HopSelectionModel,
    parallel_chains: usize,
    trials: usize,
) -> Result<CascadeBenchPoint, String> {
    let pool = provision_pool(nodes, 0)?;
    let delivered = Arc::new(StdMutex::new(Vec::new()));
    let notify = Arc::new(Notify::new());
    let mut handles = BTreeMap::new();

    for name in &pool.names {
        let mut cfg =
            NodeTransportConfig::new(name, pool.peers[name].overlay_addr, pool.peers.clone());
        cfg.route_mode = RouteMode::Cascade;
        cfg.cascade = CascadeTransportConfig {
            hops,
            max_hops: hops.max(16),
            hop_model,
            parallel_chains,
            route_ttl_secs: 120.0,
        };
        cfg.preconnect = true;
        let slot = Arc::new(StdMutex::new(None));
        let sink = Arc::new(BenchIkeSink {
            delivered: Arc::clone(&delivered),
            notify: Arc::clone(&notify),
            node_name: name.clone(),
            handle_slot: Arc::clone(&slot),
            auto_reply: name == "B",
        });
        let h = OverlayNode::start(cfg, pool.security_for(name, "ike")?, sink)
            .await
            .map_err(|e| e.to_string())?;
        *slot.lock().unwrap() = Some(h.clone());
        handles.insert(name.clone(), h);
    }

    // Wait for proactive MGMT link preconnect mesh to warm up so we measure pure cascade handshake.
    tokio::time::sleep(Duration::from_millis(350)).await;

    let mut latencies_ms = Vec::with_capacity(trials);
    let mut pkt_deltas = Vec::with_capacity(trials);
    let mut byte_deltas = Vec::with_capacity(trials);
    let mut msg_deltas = Vec::with_capacity(trials);
    let mut active_cells_last = 0usize;

    for t in 0..trials {
        delivered.lock().unwrap().clear();
        let before = sum_counters(handles.values());
        let start = Instant::now();

        let spi = [0xC0, 0x01, hops as u8, t as u8, 1, 2, 3, 4];
        let sa_init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, &[0xAAu8; 434]);
        handles["A"]
            .send_local_ike("B", sa_init, 500)
            .await
            .map_err(|e| e.to_string())?;

        wait_n(&delivered, &notify, 2, Duration::from_secs(12)).await?;

        let ike_auth = build_ikev2(500, IKE_AUTH, 1, false, spi, &[0xBBu8; 260]);
        handles["A"]
            .send_local_ike("B", ike_auth, 500)
            .await
            .map_err(|e| e.to_string())?;

        wait_n(&delivered, &notify, 4, Duration::from_secs(12)).await?;
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        tokio::time::sleep(Duration::from_millis(60)).await;
        let after = sum_counters(handles.values());
        latencies_ms.push(elapsed_ms);
        pkt_deltas.push((after.udp_packets_tx - before.udp_packets_tx) as f64);
        byte_deltas.push((after.udp_bytes_tx - before.udp_bytes_tx) as f64);
        msg_deltas.push((after.cascade_msgs_tx - before.cascade_msgs_tx) as f64);

        let mut cells = 0usize;
        for h in handles.values() {
            cells += h.cascade_counts().await.relay_cells;
        }
        active_cells_last = cells;

        handles["A"].close_cascade_route("B").await;
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    let rss_mib = measure_rss_mib();
    for h in handles.values() {
        h.shutdown().await;
    }

    Ok(build_point(
        "ipsec-ikev2",
        nodes,
        hops,
        compromised,
        hop_model,
        parallel_chains,
        trials,
        &latencies_ms,
        &pkt_deltas,
        &byte_deltas,
        &msg_deltas,
        active_cells_last,
        0,
        rss_mib,
    ))
}

async fn bench_wireguard_point(
    nodes: usize,
    hops: usize,
    compromised: usize,
    hop_model: HopSelectionModel,
    parallel_chains: usize,
    trials: usize,
) -> Result<CascadeBenchPoint, String> {
    let mut latencies_ms = Vec::with_capacity(trials);
    let mut pkt_deltas = Vec::with_capacity(trials);
    let mut byte_deltas = Vec::with_capacity(trials);
    let mut msg_deltas = Vec::with_capacity(trials);
    let mut active_cells_last = 0usize;
    let mut direct_leaks = 0u64;
    let mut rss_mib = 0.0f64;

    for t in 0..trials {
        let pool = provision_pool(nodes, 2)?;
        let cascade_cfg = CascadeTransportConfig {
            hops,
            max_hops: hops.max(16),
            hop_model,
            parallel_chains,
            route_ttl_secs: 120.0,
        };
        let mut relays = Vec::new();
        for relay in &pool.names[1..pool.names.len() - 1] {
            let mut cfg =
                NodeTransportConfig::new(relay, pool.peers[relay].overlay_addr, pool.peers.clone());
            cfg.route_mode = RouteMode::Cascade;
            cfg.cascade = cascade_cfg.clone();
            let h = OverlayNode::start(
                cfg,
                pool.security_for(relay, &format!("wg{t}"))?,
                Arc::new(RelayOnlySink),
            )
            .await
            .map_err(|e| e.to_string())?;
            relays.push(h);
        }

        let wg_sk_a = X25519SecretKey::generate();
        let wg_pk_a = *wg_sk_a.public_key().as_bytes();
        let wg_sk_b = X25519SecretKey::generate();
        let wg_pk_b = *wg_sk_b.public_key().as_bytes();
        let direct_a = SocketAddr::from(([127, 0, 0, 1], pool.extra_ports[0]));
        let direct_b = SocketAddr::from(([127, 0, 0, 1], pool.extra_ports[1]));
        let (tun_a, app_a) = ChannelTun::pair(64);
        let (tun_b, app_b) = ChannelTun::pair(64);
        let reg_sha = pool.verified.status().sha256;

        let mut ov_b =
            NodeTransportConfig::new("B", pool.peers["B"].overlay_addr, pool.peers.clone());
        ov_b.route_mode = RouteMode::Cascade;
        ov_b.cascade = cascade_cfg.clone();
        let handle_b = SplitWireGuardTunnel::start(
            WgTunnelConfig {
                peer_name: "A".to_owned(),
                wg_private_key: Zeroizing::new(*wg_sk_b.to_bytes_zeroizing()),
                peer_wg_public_key: wg_pk_a,
                wg_preshared_key: None,
                direct_bind_addr: direct_b,
                peer_direct_addr: direct_a,
                persistent_keepalive_secs: Some(25),
                overlay: ov_b,
                trust_registry_version: 1,
                trust_registry_sha256: reg_sha.clone(),
            },
            pool.security_for("B", &format!("wg{t}"))?,
            tun_b,
        )
        .await
        .map_err(|e| e.code().to_owned())?;

        let mut ov_a =
            NodeTransportConfig::new("A", pool.peers["A"].overlay_addr, pool.peers.clone());
        ov_a.route_mode = RouteMode::Cascade;
        ov_a.cascade = cascade_cfg;
        let handle_a = SplitWireGuardTunnel::start(
            WgTunnelConfig {
                peer_name: "B".to_owned(),
                wg_private_key: Zeroizing::new(*wg_sk_a.to_bytes_zeroizing()),
                peer_wg_public_key: wg_pk_b,
                wg_preshared_key: None,
                direct_bind_addr: direct_a,
                peer_direct_addr: direct_b,
                persistent_keepalive_secs: Some(25),
                overlay: ov_a,
                trust_registry_version: 1,
                trust_registry_sha256: reg_sha,
            },
            pool.security_for("A", &format!("wg{t}"))?,
            tun_a,
        )
        .await
        .map_err(|e| e.code().to_owned())?;

        tokio::time::sleep(Duration::from_millis(350)).await;

        let all_handles = || {
            relays
                .iter()
                .chain(std::iter::once(handle_a.overlay_handle()))
                .chain(std::iter::once(handle_b.overlay_handle()))
        };
        let before = sum_counters(all_handles());
        let start = Instant::now();

        let pkt_ab = build_ipv4_udp(
            Ipv4Addr::new(198, 51, 100, 10),
            Ipv4Addr::new(198, 51, 100, 13),
            42000,
            42001,
            b"wg-bench-first-packet",
        );
        app_a
            .send_outbound_ip(pkt_ab)
            .await
            .map_err(|_| "tun_send_failed".to_owned())?;
        tokio::time::timeout(Duration::from_secs(12), app_b.recv_inbound_ip())
            .await
            .map_err(|_| "wg_handshake_timeout".to_owned())?
            .ok_or_else(|| "tun_closed".to_owned())?;

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let after = sum_counters(all_handles());

        let stats_a = handle_a.stats();
        direct_leaks += stats_a.direct_handshake_tx;
        latencies_ms.push(elapsed_ms);
        pkt_deltas.push((after.udp_packets_tx - before.udp_packets_tx) as f64);
        byte_deltas.push((after.udp_bytes_tx - before.udp_bytes_tx) as f64);
        msg_deltas.push((after.cascade_msgs_tx - before.cascade_msgs_tx) as f64);

        let mut cells = 0usize;
        for h in all_handles() {
            cells += h.cascade_counts().await.relay_cells;
        }
        active_cells_last = cells;
        rss_mib = measure_rss_mib();

        handle_a.shutdown().await;
        handle_b.shutdown().await;
        for r in relays {
            r.shutdown().await;
        }
    }

    Ok(build_point(
        "wireguard",
        nodes,
        hops,
        compromised,
        hop_model,
        parallel_chains,
        trials,
        &latencies_ms,
        &pkt_deltas,
        &byte_deltas,
        &msg_deltas,
        active_cells_last,
        direct_leaks,
        rss_mib,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_point(
    protocol: &str,
    nodes: usize,
    hops: usize,
    compromised: usize,
    hop_model: HopSelectionModel,
    parallel_chains: usize,
    trials: usize,
    latencies_ms: &[f64],
    pkt_deltas: &[f64],
    byte_deltas: &[f64],
    msg_deltas: &[f64],
    active_relay_cells: usize,
    direct_control_leaks: u64,
    rss_mib: f64,
) -> CascadeBenchPoint {
    let mean = |xs: &[f64]| {
        if xs.is_empty() {
            0.0
        } else {
            xs.iter().sum::<f64>() / (xs.len() as f64)
        }
    };
    let round2 = |v: f64| (v * 100.0).round() / 100.0;

    // Exact Chapter 3 compromise probabilities from `cco-analytics`:
    // signature is `compromise_metrics(model, n=nodes, m=compromised_nodes, j=hops)`.
    let f1_c = compromise_metrics(RouteModel::F1Tor, nodes, compromised, hops);
    let f3_c = compromise_metrics(RouteModel::F3NoRep, nodes, compromised, hops);
    let f4_c = compromise_metrics(RouteModel::F4WithRep, nodes, compromised, hops);
    let f3_e = uniform_entropy(RouteModel::F3NoRep, nodes, hops);
    let f4_e = uniform_entropy(RouteModel::F4WithRep, nodes, hops);

    CascadeBenchPoint {
        protocol: protocol.to_owned(),
        nodes,
        hops,
        compromised_nodes: compromised,
        hop_model: hop_model.as_str().to_owned(),
        parallel_chains,
        trials,
        handshake_ms_median: round2(median(latencies_ms)),
        handshake_ms_mean: round2(mean(latencies_ms)),
        handshake_ms_min: round2(latencies_ms.iter().copied().fold(f64::INFINITY, f64::min)),
        handshake_ms_max: round2(latencies_ms.iter().copied().fold(0.0_f64, f64::max)),
        overlay_udp_packets_avg: round2(mean(pkt_deltas)),
        overlay_udp_kib_avg: round2(mean(byte_deltas) / 1024.0),
        cascade_msgs_tx_avg: round2(mean(msg_deltas)),
        active_relay_cells,
        direct_control_leaks,
        rss_mib,
        f1_compromise_pct: f1_c.compromise_prob.map(|p| round2(p * 100.0)),
        f3_compromise_pct: f3_c.compromise_prob.map(|p| round2(p * 100.0)),
        f4_compromise_pct: f4_c.compromise_prob.map(|p| round2(p * 100.0)),
        f3_entropy_bits: f3_e.h_uniform_bits.map(round2),
        f4_entropy_bits: f4_e.h_uniform_bits.map(round2),
    }
}

async fn wait_n(
    delivered: &Arc<StdMutex<Vec<(String, DeliveredIkeMeta)>>>,
    notify: &Arc<Notify>,
    target: usize,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if delivered.lock().unwrap().len() >= target {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("cascade_bench_timeout_waiting_for_{target}"));
        }
        let _ = tokio::time::timeout(Duration::from_millis(50), notify.notified()).await;
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_cascade_benchmark(
    nodes: usize,
    hops_list: &[usize],
    compromised: usize,
    hop_model: HopSelectionModel,
    parallel_chains: usize,
    protocol: BenchProtocolFilter,
    trials: usize,
    format: &str,
    json_out: Option<&Path>,
) -> Result<(), String> {
    if nodes < 4 {
        return Err("nodes_must_be_at_least_4".to_owned());
    }
    if hops_list.is_empty() || hops_list.iter().any(|&h| h < 2) {
        return Err("invalid_hops_list".to_owned());
    }
    if hop_model == HopSelectionModel::F3NoRep {
        let max_h = hops_list.iter().copied().max().unwrap_or(2);
        if nodes < max_h + 2 {
            return Err("f3_requires_nodes_gte_hops_plus_2".to_owned());
        }
    }

    let mut points = Vec::new();
    for &hops in hops_list {
        if matches!(
            protocol,
            BenchProtocolFilter::Both | BenchProtocolFilter::Ipsec
        ) {
            points.push(
                bench_ipsec_point(
                    nodes,
                    hops,
                    compromised,
                    hop_model,
                    parallel_chains,
                    trials.max(1),
                )
                .await?,
            );
        }
        if matches!(
            protocol,
            BenchProtocolFilter::Both | BenchProtocolFilter::Wireguard
        ) {
            points.push(
                bench_wireguard_point(
                    nodes,
                    hops,
                    compromised,
                    hop_model,
                    parallel_chains,
                    trials.max(1),
                )
                .await?,
            );
        }
    }

    let report = CascadeBenchReport {
        benchmark: "universal-cascade-multi-node-udp".to_owned(),
        nodes,
        compromised_nodes: compromised,
        hop_model: hop_model.as_str().to_owned(),
        parallel_chains,
        trials: trials.max(1),
        points,
    };

    if let Some(path) = json_out {
        let bytes = serde_json::to_vec_pretty(&report).map_err(|_| "json_error".to_owned())?;
        fs::write(path, bytes).map_err(|_| "io_error".to_owned())?;
    }

    if format == "table" || format == "both" {
        println!(
            "=== Universal Cascade Security vs Startup Latency (n={nodes}, compromised j={compromised}, model={}, K={parallel_chains}, trials={}) ===",
            hop_model.as_str(),
            trials.max(1)
        );
        println!(
            "| {:<11} | {:>3} | {:>9} | {:>9} | {:>8} | {:>8} | {:>7} | {:>8} | {:>8} | {:>8} | {:>7} |",
            "Protocol",
            "m",
            "Med (ms)",
            "UDP pkts",
            "KiB",
            "Msgs",
            "RSS MiB",
            "P_F1 (%)",
            "P_F3 (%)",
            "P_F4 (%)",
            "H_F4(b)"
        );
        println!(
            "|{:-<13}|{:-<5}|{:-<11}|{:-<11}|{:-<10}|{:-<10}|{:-<9}|{:-<10}|{:-<10}|{:-<10}|{:-<9}|",
            "", "", "", "", "", "", "", "", "", "", ""
        );
        for p in &report.points {
            let opt = |v: Option<f64>| v.map_or_else(|| "n/a".to_owned(), |x| format!("{x:.2}"));
            println!(
                "| {:<11} | {:>3} | {:>9.2} | {:>9.1} | {:>8.1} | {:>8.1} | {:>7.1} | {:>8} | {:>8} | {:>8} | {:>7} |",
                p.protocol,
                p.hops,
                p.handshake_ms_median,
                p.overlay_udp_packets_avg,
                p.overlay_udp_kib_avg,
                p.cascade_msgs_tx_avg,
                p.rss_mib,
                opt(p.f1_compromise_pct),
                opt(p.f3_compromise_pct),
                opt(p.f4_compromise_pct),
                opt(p.f4_entropy_bits),
            );
        }
    }

    if format == "json" || format == "both" {
        if format == "both" {
            println!();
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|_| "json_error".to_owned())?
        );
    }

    Ok(())
}
