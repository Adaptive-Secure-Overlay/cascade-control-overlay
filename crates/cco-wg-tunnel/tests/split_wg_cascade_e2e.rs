#![forbid(unsafe_code)]
//! Live multi-node E2E verification of userspace WireGuard (`boringtun`) over
//! Universal H-hop Privacy Cascade (`m = 3, 5, 10`, both `F3` and `F4`, `K = 2` parallel chains).
//!
//! Proves:
//! - WireGuard Type 1/2/3 traverses `m` intermediate relays (`direct_handshake_tx == 0`)
//! - WireGuard Type 4 encrypted transport flows directly `A <-> B`
//! - Both 14-node `F3` (zero repeats) and 4-node `F4` (repeats over `X1, X2`) succeed for `m = 10`

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cco_cascade::mcc::EndpointSecurity;
use cco_cascade::universal::HopSelectionModel;
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_transport::{
    CascadeTransportConfig, NodeTransportConfig, OverlayNode, PeerEndpoint, RelayOnlySink,
    RouteMode,
};
use cco_trust::{
    NodeKeyRecord, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use cco_wg_tunnel::{ChannelTun, SplitWireGuardTunnel, TunnelState, WgTunnelConfig};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn pick_free_udp_ports(count: usize) -> Vec<u16> {
    let mut sockets = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        let s = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        ports.push(s.local_addr().unwrap().port());
        sockets.push(s);
    }
    drop(sockets);
    ports
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

async fn run_wg_cascade_case(
    node_count: usize,
    hops: usize,
    hop_model: HopSelectionModel,
    parallel_chains: usize,
) {
    let dir = TempDir::new().unwrap();
    let names: Vec<String> = std::iter::once("A".to_owned())
        .chain((1..=node_count - 2).map(|i| format!("X{i}")))
        .chain(std::iter::once("B".to_owned()))
        .collect();

    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("wg-cascade-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    let ports = pick_free_udp_ports(names.len() + 2);
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
                overlay_addr: SocketAddr::from(([127, 0, 0, 1], ports[i])),
                underlay_ip: Ipv4Addr::new(192, 0, 2, (10 + i) as u8),
            },
        );
    }

    let reg_bytes = sign_registry_v2(1, &records, "wg-cascade-root", &root_sk).unwrap();
    let verified = verify_registry_bytes(
        &reg_bytes,
        &root_path,
        names.iter().map(String::as_str),
        VerifyConstraints::default(),
    )
    .unwrap();
    let reg_sha256 = verified.status().sha256;
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let make_sec = |name: &str| {
        EndpointSecurity::new(
            name,
            verified.clone(),
            Ed25519SecretKey::from_bytes(*signing[name].to_bytes_zeroizing()),
            X25519SecretKey::from_bytes(*encryption[name].to_bytes_zeroizing()),
            dir.path().join(format!("{name}.sqlite")),
            now_s,
        )
        .unwrap()
    };

    let cascade_cfg = CascadeTransportConfig {
        hops,
        max_hops: 16,
        hop_model,
        parallel_chains,
        route_ttl_secs: 120.0,
    };

    let mut relays = Vec::new();
    for relay in &names[1..names.len() - 1] {
        let mut cfg = NodeTransportConfig::new(relay, peers[relay].overlay_addr, peers.clone());
        cfg.route_mode = RouteMode::Cascade;
        cfg.cascade = cascade_cfg.clone();
        let h = OverlayNode::start(cfg, make_sec(relay), Arc::new(RelayOnlySink))
            .await
            .unwrap();
        relays.push(h);
    }

    let wg_sk_a = X25519SecretKey::generate();
    let wg_pk_a = *wg_sk_a.public_key().as_bytes();
    let wg_sk_b = X25519SecretKey::generate();
    let wg_pk_b = *wg_sk_b.public_key().as_bytes();

    let direct_a = SocketAddr::from(([127, 0, 0, 1], ports[names.len()]));
    let direct_b = SocketAddr::from(([127, 0, 0, 1], ports[names.len() + 1]));
    let (tun_a, app_a) = ChannelTun::pair(64);
    let (tun_b, app_b) = ChannelTun::pair(64);

    let mut ov_b = NodeTransportConfig::new("B", peers["B"].overlay_addr, peers.clone());
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
            trust_registry_sha256: reg_sha256.clone(),
        },
        make_sec("B"),
        tun_b,
    )
    .await
    .unwrap();

    let mut ov_a = NodeTransportConfig::new("A", peers["A"].overlay_addr, peers.clone());
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
            trust_registry_sha256: reg_sha256,
        },
        make_sec("A"),
        tun_a,
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_millis(250)).await;

    let pkt_ab = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(198, 51, 100, 13),
        41000,
        41001,
        b"wg-direct-type4-after-m-hop-cascade",
    );
    app_a.send_outbound_ip(pkt_ab.clone()).await.unwrap();

    let got_b = tokio::time::timeout(Duration::from_secs(10), app_b.recv_inbound_ip())
        .await
        .expect("timed out waiting for WG packet on B")
        .expect("tun B closed");
    assert_eq!(got_b, pkt_ab);

    let pkt_ba = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 13),
        Ipv4Addr::new(198, 51, 100, 10),
        41001,
        41000,
        b"wg-reply-direct-type4",
    );
    app_b.send_outbound_ip(pkt_ba.clone()).await.unwrap();
    let got_a = tokio::time::timeout(Duration::from_secs(5), app_a.recv_inbound_ip())
        .await
        .expect("timed out waiting for WG reply on A")
        .expect("tun A closed");
    assert_eq!(got_a, pkt_ba);

    let stats_a = handle_a.stats();
    assert_eq!(stats_a.state, TunnelState::ConnectedDirectData);
    assert_eq!(stats_a.direct_handshake_tx, 0);
    assert_eq!(stats_a.route_mode, "cascade");
    assert_eq!(stats_a.selected_route_hops, hops as u8);
    assert!(stats_a.overlay_handshake_tx >= 1);
    assert!(stats_a.overlay_handshake_rx >= 1);
    assert!(stats_a.direct_data_tx >= 1);
    assert!(stats_a.direct_data_rx >= 1);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    for r in relays {
        r.shutdown().await;
    }
}

#[tokio::test]
async fn wireguard_over_universal_cascade_f3_14nodes_m10_and_f4_4nodes_m3_5_10() {
    run_wg_cascade_case(14, 10, HopSelectionModel::F3NoRep, 2).await;
    run_wg_cascade_case(4, 3, HopSelectionModel::F4WithRep, 2).await;
    run_wg_cascade_case(4, 5, HopSelectionModel::F4WithRep, 2).await;
    run_wg_cascade_case(4, 10, HopSelectionModel::F4WithRep, 2).await;
}
