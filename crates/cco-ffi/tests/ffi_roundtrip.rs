#![deny(unsafe_code)]
//! End-to-end C-ABI & safe core FFI verification tests:
//! - Trust Registry v2 bundle verification + tamper rejection
//! - Chapter 3 analytics summary (exact F1/F3/F4 + n50 + rayon Monte Carlo)
//! - Demo bundle generation & verification
//! - Full 4-node split WireGuard tunnel roundtrip strictly over the C-ABI boundary!

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cco_cascade::mcc::{EndpointSecurity, MccFanout, SelectionPolicy};
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_ffi::c_abi::{
    cco_analytics_summary, cco_generate_demo_bundle, cco_string_free, cco_tunnel_drain_events,
    cco_tunnel_pop_inbound_ip, cco_tunnel_push_outbound_ip, cco_tunnel_start_channel,
    cco_tunnel_stats, cco_tunnel_stop, cco_verify_trust_bundle, cco_version,
};
use cco_transport::{NodeTransportConfig, OverlayNode, PeerEndpoint, RelayOnlySink};
use cco_trust::{
    NodeKeyRecord, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use serde_json::{Value, json};
use tempfile::TempDir;

#[allow(unsafe_code)]
fn take_c_string(ptr: *mut std::ffi::c_char) -> String {
    assert!(!ptr.is_null(), "expected non-null C string from cco_ffi");
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .expect("valid UTF-8")
        .to_owned();
    unsafe { cco_string_free(ptr) };
    s
}

fn pick_free_udp_ports(count: usize) -> Vec<u16> {
    let mut socks = Vec::with_capacity(count);
    let mut ports = Vec::with_capacity(count);
    for _ in 0..count {
        let s = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        ports.push(s.local_addr().unwrap().port());
        socks.push(s);
    }
    drop(socks);
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
    pkt[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

#[allow(unsafe_code)]
#[test]
fn c_abi_version_analytics_and_demo_bundle_verification() {
    let ver = take_c_string(cco_version());
    assert!(!ver.is_empty());

    // Analytics n=10, m=2, j=3 (dissertation Chapter 3 committee example)
    let raw_an = take_c_string(cco_analytics_summary(10, 2, 3));
    let an: Value = serde_json::from_str(&raw_an).unwrap();
    assert_eq!(an["ok"], true);
    assert_eq!(an["data"]["f1_routes"], "336");
    assert_eq!(an["data"]["f3_routes"], "584");
    assert_eq!(an["data"]["f4_routes"], "656");
    assert_eq!(an["data"]["f4_n50"], 11);

    // Demo bundle -> verify_trust_bundle succeeds, tampered bundle fails closed
    let a = CString::new("A").unwrap();
    let b = CString::new("B").unwrap();
    let raw_demo = take_c_string(unsafe { cco_generate_demo_bundle(a.as_ptr(), b.as_ptr()) });
    let demo: Value = serde_json::from_str(&raw_demo).unwrap();
    assert_eq!(demo["ok"], true);

    let reg_c = CString::new(demo["data"]["trust_registry_json"].as_str().unwrap()).unwrap();
    let root_c = CString::new(demo["data"]["trust_root_json"].as_str().unwrap()).unwrap();
    let req_c = CString::new(r#"["A","X1","X2","B"]"#).unwrap();

    let verified_raw = take_c_string(unsafe {
        cco_verify_trust_bundle(reg_c.as_ptr(), root_c.as_ptr(), req_c.as_ptr())
    });
    let verified: Value = serde_json::from_str(&verified_raw).unwrap();
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["data"]["authenticated"], true);
    assert_eq!(verified["data"]["version"], 1);

    // Tampered registry MUST fail closed
    let tampered = demo["data"]["trust_registry_json"]
        .as_str()
        .unwrap()
        .replace("\"version\":1", "\"version\":2");
    let tam_c = CString::new(tampered).unwrap();
    let bad_raw = take_c_string(unsafe {
        cco_verify_trust_bundle(tam_c.as_ptr(), root_c.as_ptr(), req_c.as_ptr())
    });
    let bad: Value = serde_json::from_str(&bad_raw).unwrap();
    assert_eq!(bad["ok"], false);
}

#[allow(unsafe_code)]
#[test]
fn c_abi_channel_tunnel_four_node_split_wireguard_roundtrip() {
    let dir = TempDir::new().unwrap();
    let names = ["A", "X1", "X2", "B"];

    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("ffi-root".to_owned(), root_sk.public_key());
    let root_bytes = build_trust_root_bytes(&signers).unwrap();
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, &root_bytes).unwrap();
    let root_json = String::from_utf8(root_bytes).unwrap();

    let ports = pick_free_udp_ports(6);
    let mut signing = BTreeMap::new();
    let mut encryption = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut peers_map = BTreeMap::new();
    let mut peers_vec = Vec::new();

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
        let ep = PeerEndpoint {
            name: name.to_owned(),
            overlay_addr: SocketAddr::from(([127, 0, 0, 1], ports[i])),
            underlay_ip: Ipv4Addr::new(192, 0, 2, (10 + i) as u8),
        };
        peers_map.insert(name.to_owned(), ep.clone());
        peers_vec.push(ep);
    }

    let reg_bytes = sign_registry_v2(1, &records, "ffi-root", &root_sk).unwrap();
    let verified = verify_registry_bytes(
        &reg_bytes,
        &root_path,
        names.iter().copied(),
        VerifyConstraints::default(),
    )
    .unwrap();
    let reg_json = String::from_utf8(reg_bytes).unwrap();

    // Start relays X1 & X2 in a dedicated background runtime
    let relay_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let relays = relay_rt.block_on(async {
        let mut hs = Vec::new();
        for &relay in &["X1", "X2"] {
            let sec = EndpointSecurity::new(
                relay,
                verified.clone(),
                Ed25519SecretKey::from_bytes(*signing[relay].to_bytes_zeroizing()),
                X25519SecretKey::from_bytes(*encryption[relay].to_bytes_zeroizing()),
                dir.path().join(format!("{relay}.sqlite")),
                now_s,
            )
            .unwrap();
            let mut cfg =
                NodeTransportConfig::new(relay, peers_map[relay].overlay_addr, peers_map.clone());
            cfg.fanout = MccFanout {
                x1: 2,
                x2: 2,
                ike: 1,
            };
            cfg.policy = SelectionPolicy::first(12_000);
            hs.push(
                OverlayNode::start(cfg, sec, Arc::new(RelayOnlySink))
                    .await
                    .unwrap(),
            );
        }
        hs
    });

    let wg_sk_a = X25519SecretKey::generate();
    let wg_sk_b = X25519SecretKey::generate();

    let cfg_b = json!({
        "node_name": "B",
        "peer_name": "A",
        "peers": peers_vec,
        "trust_registry_json": reg_json,
        "trust_root_json": root_json,
        "signing_key_hex": *signing["B"].to_hex_zeroizing(),
        "encryption_key_hex": *encryption["B"].to_hex_zeroizing(),
        "wg_private_key_hex": *wg_sk_b.to_hex_zeroizing(),
        "peer_wg_public_key_hex": wg_sk_a.public_key().to_hex(),
        "direct_bind_addr": format!("127.0.0.1:{}", ports[5]),
        "peer_direct_addr": format!("127.0.0.1:{}", ports[4]),
        "replay_db_path": dir.path().join("B.sqlite"),
        "mcc_mode": "first",
        "x1_fanout": 2,
        "x2_fanout": 2,
        "ike_fanout": 1,
        "initiate_handshake": false
    });
    let cfg_a = json!({
        "node_name": "A",
        "peer_name": "B",
        "peers": peers_vec,
        "trust_registry_json": reg_json,
        "trust_root_json": root_json,
        "signing_key_hex": *signing["A"].to_hex_zeroizing(),
        "encryption_key_hex": *encryption["A"].to_hex_zeroizing(),
        "wg_private_key_hex": *wg_sk_a.to_hex_zeroizing(),
        "peer_wg_public_key_hex": wg_sk_b.public_key().to_hex(),
        "direct_bind_addr": format!("127.0.0.1:{}", ports[4]),
        "peer_direct_addr": format!("127.0.0.1:{}", ports[5]),
        "replay_db_path": dir.path().join("A.sqlite"),
        "mcc_mode": "first",
        "x1_fanout": 2,
        "x2_fanout": 2,
        "ike_fanout": 1,
        "initiate_handshake": false
    });

    let cfg_b_c = CString::new(cfg_b.to_string()).unwrap();
    let cfg_a_c = CString::new(cfg_a.to_string()).unwrap();
    let mut err_ptr: *mut std::ffi::c_char = ptr::null_mut();

    let handle_b = unsafe { cco_tunnel_start_channel(cfg_b_c.as_ptr(), &mut err_ptr) };
    assert!(!handle_b.is_null(), "failed starting B via C-ABI");
    let handle_a = unsafe { cco_tunnel_start_channel(cfg_a_c.as_ptr(), &mut err_ptr) };
    assert!(!handle_a.is_null(), "failed starting A via C-ABI");

    std::thread::sleep(Duration::from_millis(200));

    let pkt = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(198, 51, 100, 13),
        50000,
        50001,
        b"c-abi-direct-type4-after-mcc",
    );
    assert_eq!(
        unsafe { cco_tunnel_push_outbound_ip(handle_a, pkt.as_ptr(), pkt.len()) },
        0
    );

    let mut recv_buf = vec![0u8; 4096];
    let mut got_len = 0isize;
    for _ in 0..80 {
        got_len =
            unsafe { cco_tunnel_pop_inbound_ip(handle_b, recv_buf.as_mut_ptr(), recv_buf.len()) };
        if got_len > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(got_len as usize, pkt.len());
    assert_eq!(&recv_buf[..pkt.len()], pkt.as_slice());

    let stats_raw = take_c_string(unsafe { cco_tunnel_stats(handle_a) });
    let stats: Value = serde_json::from_str(&stats_raw).unwrap();
    assert_eq!(stats["ok"], true);
    assert_eq!(stats["data"]["direct_handshake_tx"], 0);
    assert!(stats["data"]["overlay_handshake_tx"].as_u64().unwrap() >= 1);
    assert!(stats["data"]["direct_data_tx"].as_u64().unwrap() >= 1);

    let events_raw = take_c_string(unsafe { cco_tunnel_drain_events(handle_a) });
    let events: Value = serde_json::from_str(&events_raw).unwrap();
    assert_eq!(events["ok"], true);
    assert!(!events["data"].as_array().unwrap().is_empty());

    unsafe {
        cco_tunnel_stop(handle_a);
        cco_tunnel_stop(handle_b);
    }
    relay_rt.block_on(async {
        for r in relays {
            r.shutdown().await;
        }
    });
}

#[test]
#[allow(unsafe_code)]
fn c_abi_channel_tunnel_f4_five_hop_cascade_roundtrip() {
    let dir = TempDir::new().unwrap();
    let names = ["A", "X1", "X2", "B"];
    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("ffi-cascade-root".to_owned(), root_sk.public_key());
    let root_bytes = build_trust_root_bytes(&signers).unwrap();
    let root_json = String::from_utf8(root_bytes.clone()).unwrap();
    let root_path = dir.path().join("root.json");
    std::fs::write(&root_path, &root_bytes).unwrap();

    let ports = pick_free_udp_ports(6);
    let mut signing = BTreeMap::new();
    let mut encryption = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut peers_vec = Vec::new();
    let mut peers_map = BTreeMap::new();

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
        let ep = PeerEndpoint {
            name: name.to_owned(),
            overlay_addr: SocketAddr::from(([127, 0, 0, 1], ports[i])),
            underlay_ip: Ipv4Addr::new(192, 0, 2, (10 + i) as u8),
        };
        peers_vec.push(ep.clone());
        peers_map.insert(name.to_owned(), ep);
    }

    let reg_bytes = sign_registry_v2(1, &records, "ffi-cascade-root", &root_sk).unwrap();
    let verified = verify_registry_bytes(
        &reg_bytes,
        &root_path,
        names.iter().copied(),
        VerifyConstraints::default(),
    )
    .unwrap();
    let reg_json = String::from_utf8(reg_bytes).unwrap();

    let relay_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let relays = relay_rt.block_on(async {
        let mut hs = Vec::new();
        for &relay in &["X1", "X2"] {
            let sec = EndpointSecurity::new(
                relay,
                verified.clone(),
                Ed25519SecretKey::from_bytes(*signing[relay].to_bytes_zeroizing()),
                X25519SecretKey::from_bytes(*encryption[relay].to_bytes_zeroizing()),
                dir.path().join(format!("{relay}.sqlite")),
                now_s,
            )
            .unwrap();
            let mut cfg =
                NodeTransportConfig::new(relay, peers_map[relay].overlay_addr, peers_map.clone());
            cfg.route_mode = cco_transport::RouteMode::Cascade;
            cfg.cascade.hops = 5;
            cfg.cascade.hop_model = cco_cascade::universal::HopSelectionModel::F4WithRep;
            cfg.cascade.parallel_chains = 2;
            hs.push(
                OverlayNode::start(cfg, sec, Arc::new(RelayOnlySink))
                    .await
                    .unwrap(),
            );
        }
        hs
    });

    let wg_sk_a = X25519SecretKey::generate();
    let wg_sk_b = X25519SecretKey::generate();
    let cfg_b = json!({
        "node_name": "B",
        "peer_name": "A",
        "peers": peers_vec,
        "trust_registry_json": reg_json,
        "trust_root_json": root_json,
        "signing_key_hex": *signing["B"].to_hex_zeroizing(),
        "encryption_key_hex": *encryption["B"].to_hex_zeroizing(),
        "wg_private_key_hex": *wg_sk_b.to_hex_zeroizing(),
        "peer_wg_public_key_hex": wg_sk_a.public_key().to_hex(),
        "direct_bind_addr": format!("127.0.0.1:{}", ports[5]),
        "peer_direct_addr": format!("127.0.0.1:{}", ports[4]),
        "replay_db_path": dir.path().join("B.sqlite"),
        "route_mode": "cascade",
        "cascade_hops": 5,
        "max_hops": 16,
        "hop_model": "f4",
        "parallel_chains": 2,
        "initiate_handshake": false
    });
    let cfg_a = json!({
        "node_name": "A",
        "peer_name": "B",
        "peers": peers_vec,
        "trust_registry_json": reg_json,
        "trust_root_json": root_json,
        "signing_key_hex": *signing["A"].to_hex_zeroizing(),
        "encryption_key_hex": *encryption["A"].to_hex_zeroizing(),
        "wg_private_key_hex": *wg_sk_a.to_hex_zeroizing(),
        "peer_wg_public_key_hex": wg_sk_b.public_key().to_hex(),
        "direct_bind_addr": format!("127.0.0.1:{}", ports[4]),
        "peer_direct_addr": format!("127.0.0.1:{}", ports[5]),
        "replay_db_path": dir.path().join("A.sqlite"),
        "route_mode": "cascade",
        "cascade_hops": 5,
        "max_hops": 16,
        "hop_model": "f4",
        "parallel_chains": 2,
        "initiate_handshake": false
    });

    let cfg_b_c = CString::new(cfg_b.to_string()).unwrap();
    let cfg_a_c = CString::new(cfg_a.to_string()).unwrap();
    let mut err_ptr: *mut std::ffi::c_char = ptr::null_mut();

    let handle_b = unsafe { cco_tunnel_start_channel(cfg_b_c.as_ptr(), &mut err_ptr) };
    assert!(!handle_b.is_null());
    let handle_a = unsafe { cco_tunnel_start_channel(cfg_a_c.as_ptr(), &mut err_ptr) };
    assert!(!handle_a.is_null());

    std::thread::sleep(Duration::from_millis(250));

    let pkt = build_ipv4_udp(
        Ipv4Addr::new(198, 51, 100, 10),
        Ipv4Addr::new(198, 51, 100, 13),
        51000,
        51001,
        b"c-abi-5hop-f4-cascade",
    );
    assert_eq!(
        unsafe { cco_tunnel_push_outbound_ip(handle_a, pkt.as_ptr(), pkt.len()) },
        0
    );

    let mut recv_buf = vec![0u8; 4096];
    let mut got_len = 0isize;
    for _ in 0..100 {
        got_len =
            unsafe { cco_tunnel_pop_inbound_ip(handle_b, recv_buf.as_mut_ptr(), recv_buf.len()) };
        if got_len > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(got_len as usize, pkt.len());
    assert_eq!(&recv_buf[..pkt.len()], pkt.as_slice());

    let stats_raw = take_c_string(unsafe { cco_tunnel_stats(handle_a) });
    let stats: Value = serde_json::from_str(&stats_raw).unwrap();
    assert_eq!(stats["ok"], true);
    assert_eq!(stats["data"]["route_mode"], "cascade");
    assert_eq!(stats["data"]["hop_model"], "f4");
    assert_eq!(stats["data"]["selected_route_hops"], 5);
    assert_eq!(stats["data"]["parallel_chains"], 2);
    assert_eq!(stats["data"]["direct_handshake_tx"], 0);

    unsafe {
        cco_tunnel_stop(handle_a);
        cco_tunnel_stop(handle_b);
    }
    relay_rt.block_on(async {
        for r in relays {
            r.shutdown().await;
        }
    });
}
