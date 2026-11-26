#![forbid(unsafe_code)]
//! 4-node in-memory E2E verification (`A -> X1 -> X2 -> B`) of userspace WireGuard
//! split control-overlay and direct-data transport without root privileges.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cco_cascade::mcc::{EndpointSecurity, MccFanout, SelectionPolicy};
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_transport::{NodeTransportConfig, OverlayNode, PeerEndpoint, RelayOnlySink};
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

/// Builds a syntactically valid IPv4/UDP packet with accurate IPv4 header checksum
/// so `boringtun::noise::Tunn` accepts and routes it inside the WireGuard tunnel.
fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len as usize];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
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

#[tokio::test]
async fn four_node_split_wireguard_handshake_via_mcc_and_direct_type4_data() {
    let dir = TempDir::new().unwrap();
    let names = ["A", "X1", "X2", "B"];

    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("wg-e2e-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    // 4 overlay UDP ports + 2 direct WG data UDP ports (A and B)
    let ports = pick_free_udp_ports(6);
    let mut signing = BTreeMap::new();
    let mut encryption = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut peers = BTreeMap::new();

    for (i, &name) in names.iter().enumerate() {
        let esk = Ed25519SecretKey::generate();
        let xsk = X25519SecretKey::generate();
        records.insert(
            name.to_owned(),
            NodeKeyRecord {
                encryption: xsk.public_key(),
                verification: esk.public_key(),
                key_id: esk.public_key().key_id(),
                revoked: false,
            },
        );
        signing.insert(name.to_owned(), esk);
        encryption.insert(name.to_owned(), xsk);
        peers.insert(
            name.to_owned(),
            PeerEndpoint {
                name: name.to_owned(),
                overlay_addr: SocketAddr::from(([127, 0, 0, 1], ports[i])),
                underlay_ip: Ipv4Addr::new(192, 0, 2, (10 + i) as u8),
            },
        );
    }

    let reg_bytes = sign_registry_v2(1, &records, "wg-e2e-root", &root_sk).unwrap();
    let verified = verify_registry_bytes(
        &reg_bytes,
        &root_path,
        names.iter().copied(),
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

    // Start relay nodes X1 and X2 (pure MCC relays, zero WireGuard keys!)
    let mut relay_handles = Vec::new();
    for &relay in &["X1", "X2"] {
        let mut cfg = NodeTransportConfig::new(relay, peers[relay].overlay_addr, peers.clone());
        cfg.fanout = MccFanout {
            x1: 2,
            x2: 2,
            ike: 1,
        };
        cfg.policy = SelectionPolicy::first(12_000);
        let h = OverlayNode::start(cfg, make_sec(relay), Arc::new(RelayOnlySink))
            .await
            .unwrap();
        relay_handles.push(h);
    }

    // Separate WireGuard static X25519 keypairs for A and B
    let wg_sk_a = X25519SecretKey::generate();
    let wg_pk_a = *wg_sk_a.public_key().as_bytes();
    let wg_sk_b = X25519SecretKey::generate();
    let wg_pk_b = *wg_sk_b.public_key().as_bytes();

    let direct_addr_a = SocketAddr::from(([127, 0, 0, 1], ports[4]));
    let direct_addr_b = SocketAddr::from(([127, 0, 0, 1], ports[5]));

    let (tun_a, app_a) = ChannelTun::pair(64);
    let (tun_b, app_b) = ChannelTun::pair(64);

    let mut ov_b = NodeTransportConfig::new("B", peers["B"].overlay_addr, peers.clone());
    ov_b.fanout = MccFanout {
        x1: 2,
        x2: 2,
        ike: 1,
    };
    ov_b.policy = SelectionPolicy::first(12_000);

    let handle_b = SplitWireGuardTunnel::start(
        WgTunnelConfig {
            peer_name: "A".to_owned(),
            wg_private_key: Zeroizing::new(*wg_sk_b.to_bytes_zeroizing()),
            peer_wg_public_key: wg_pk_a,
            wg_preshared_key: None,
            direct_bind_addr: direct_addr_b,
            peer_direct_addr: direct_addr_a,
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
    ov_a.fanout = MccFanout {
        x1: 2,
        x2: 2,
        ike: 1,
    };
    ov_a.policy = SelectionPolicy::first(12_000);

    let handle_a = SplitWireGuardTunnel::start(
        WgTunnelConfig {
            peer_name: "B".to_owned(),
            wg_private_key: Zeroizing::new(*wg_sk_a.to_bytes_zeroizing()),
            peer_wg_public_key: wg_pk_b,
            wg_preshared_key: None,
            direct_bind_addr: direct_addr_a,
            peer_direct_addr: direct_addr_b,
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

    // Give proactive MGMT preconnect a brief moment
    tokio::time::sleep(Duration::from_millis(200)).await;

    // 1. Send an IPv4 packet from A to B — triggers WG type 1 via MCC overlay,
    //    WG type 2 back via PRIV_BACK, and then delivers the queued IPv4 packet over DIRECT type 4!
    let pkt_a_to_b = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(198, 51, 100, 13),
        40000,
        40001,
        b"hello-over-direct-wg-type4-after-mcc-handshake",
    );
    app_a.send_outbound_ip(pkt_a_to_b.clone()).await.unwrap();

    let recv_on_b = match tokio::time::timeout(Duration::from_secs(6), app_b.recv_inbound_ip())
        .await
    {
        Ok(Some(pkt)) => pkt,
        other => panic!(
            "failed waiting for A->B IP packet on B ({other:?})\nstats_a={:?}\nevents_a={:?}\nstats_b={:?}\nevents_b={:?}",
            handle_a.stats(),
            handle_a.drain_events(),
            handle_b.stats(),
            handle_b.drain_events(),
        ),
    };
    assert_eq!(recv_on_b, pkt_a_to_b);

    // 2. Reply B -> A directly over WG type 4!
    let pkt_b_to_a = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 13),
        Ipv4Addr::new(198, 51, 100, 10),
        40001,
        40000,
        b"reply-direct-wg-type4-zero-overlay-rtt",
    );
    app_b.send_outbound_ip(pkt_b_to_a.clone()).await.unwrap();

    let recv_on_a = tokio::time::timeout(Duration::from_secs(5), app_a.recv_inbound_ip())
        .await
        .expect("timed out waiting for B->A IP packet on A")
        .expect("A TUN closed");
    assert_eq!(recv_on_a, pkt_b_to_a);

    // 3. Negative security check: unsolicited WG type 1 sent directly to B's direct UDP port MUST be dropped!
    let attacker = StdUdpSocket::bind("127.0.0.1:0").unwrap();
    let mut forged_type1 = vec![0u8; 148];
    forged_type1[0] = 1; // HandshakeInitiation, reserved=[0,0,0]
    attacker.send_to(&forged_type1, direct_addr_b).unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;

    // 4. Verify all strict split-plane security & telemetry invariants!
    let stats_a = handle_a.stats();
    let stats_b = handle_b.stats();

    assert_eq!(stats_a.state, TunnelState::ConnectedDirectData);
    assert_eq!(stats_b.state, TunnelState::ConnectedDirectData);
    assert_eq!(stats_a.direct_handshake_tx, 0);
    assert_eq!(stats_b.direct_handshake_tx, 0);
    assert!(stats_a.overlay_handshake_tx >= 1);
    assert!(stats_a.overlay_handshake_rx >= 1);
    assert!(stats_b.overlay_handshake_rx >= 1);
    assert!(stats_b.overlay_handshake_tx >= 1);
    assert!(stats_a.direct_data_tx >= 1);
    assert!(stats_a.direct_data_rx >= 1);
    assert!(stats_b.direct_data_tx >= 1);
    assert!(stats_b.direct_data_rx >= 1);
    assert!(stats_a.handshake_ms.is_some());
    assert!(stats_a.selected_x1.is_some());
    assert!(stats_b.direct_handshake_rx_dropped >= 1);

    handle_a.shutdown().await;
    handle_b.shutdown().await;
    for r in relay_handles {
        r.shutdown().await;
    }
}
