#![forbid(unsafe_code)]
//! Live localhost multi-node UDP E2E tests for Universal H-hop Privacy Cascade (`m = 3, 5, 10`)
//! over real Tokio UDP sockets, MGMT hop sessions, `LINK_FRAG`, and Ed25519 Trust Registry v2.
//!
//! Verifies:
//! 1. Full IKEv2 `IKE_SA_INIT` + `IKE_AUTH` bidirectional handshake across `m = 3, 5, 10` hops
//!    in both `F3` (14-node pool, zero repeated relays) and `F4` (4-node WAN-style pool with repeats).
//! 2. Role-limited knowledge invariants in the live memory of every node `X1..Xm`, `A`, and `B`.
//! 3. Linear `K = 2` parallel chains with single delivery deduplication on `B`.

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    PeerEndpoint, RouteMode,
};
use cco_trust::{
    NodeKeyRecord, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use tempfile::TempDir;
use tokio::sync::Notify;

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

type DeliveredLog = Arc<StdMutex<Vec<(String, DeliveredIkeMeta, Vec<u8>)>>>;

struct AutoReplyIkeSink {
    node_name: String,
    delivered: DeliveredLog,
    notify: Arc<Notify>,
    handle_slot: Arc<StdMutex<Option<OverlayNodeHandle>>>,
    auto_reply: bool,
}

impl IkeSink for AutoReplyIkeSink {
    fn deliver(&self, proof: LocalDeliveryProof) -> (IkeInjectionOutcome, DeliveryReceipt) {
        let (payload, meta, receipt) = proof.consume();
        self.delivered.lock().unwrap().push((
            self.node_name.clone(),
            meta.clone(),
            payload.clone(),
        ));
        self.notify.notify_waiters();

        if self.auto_reply && meta.direction == "fwd" {
            if let Some(handle) = self.handle_slot.lock().unwrap().clone() {
                if let Ok(hdr) = parse_ikev2_packet(meta.udp_port, &payload) {
                    let resp = build_ikev2(
                        meta.udp_port,
                        hdr.exchange_type,
                        hdr.message_id,
                        true,
                        hdr.initiator_spi,
                        b"cascade-udp-ike-resp",
                    );
                    let dst_user = meta.src.clone();
                    let port = meta.udp_port;
                    tokio::spawn(async move {
                        let _ = handle.send_local_ike(&dst_user, resp, port).await;
                    });
                }
            }
        }
        (IkeInjectionOutcome::Sent, receipt)
    }
}

async fn start_cascade_cluster(
    names: &[String],
    hops: usize,
    hop_model: HopSelectionModel,
    parallel_chains: usize,
) -> (
    TempDir,
    BTreeMap<String, OverlayNodeHandle>,
    DeliveredLog,
    Arc<Notify>,
) {
    let dir = TempDir::new().unwrap();
    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("cascade-udp-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    let ports = pick_free_udp_ports(names.len());
    let mut signing = BTreeMap::new();
    let mut encryption = BTreeMap::new();
    let mut records = BTreeMap::new();
    let mut peers = BTreeMap::new();

    for (idx, name) in names.iter().enumerate() {
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
                overlay_addr: SocketAddr::from(([127, 0, 0, 1], ports[idx])),
                underlay_ip: Ipv4Addr::new(192, 0, 2, (10 + idx) as u8),
            },
        );
    }

    let reg_bytes = sign_registry_v2(1, &records, "cascade-udp-root", &root_sk).unwrap();
    let verified = verify_registry_bytes(
        &reg_bytes,
        &root_path,
        names.iter().map(String::as_str),
        VerifyConstraints::default(),
    )
    .unwrap();
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let delivered: DeliveredLog = Arc::new(StdMutex::new(Vec::new()));
    let notify = Arc::new(Notify::new());
    let mut handles = BTreeMap::new();

    for name in names {
        let sec = EndpointSecurity::new(
            name,
            verified.clone(),
            Ed25519SecretKey::from_bytes(*signing[name].to_bytes_zeroizing()),
            X25519SecretKey::from_bytes(*encryption[name].to_bytes_zeroizing()),
            dir.path().join(format!("{name}.sqlite")),
            now_s,
        )
        .unwrap();
        let mut cfg = NodeTransportConfig::new(name, peers[name].overlay_addr, peers.clone());
        cfg.route_mode = RouteMode::Cascade;
        cfg.cascade = CascadeTransportConfig {
            hops,
            max_hops: 16,
            hop_model,
            parallel_chains,
            route_ttl_secs: 120.0,
        };
        cfg.preconnect = true;

        let slot = Arc::new(StdMutex::new(None));
        let sink = Arc::new(AutoReplyIkeSink {
            node_name: name.clone(),
            delivered: Arc::clone(&delivered),
            notify: Arc::clone(&notify),
            handle_slot: Arc::clone(&slot),
            auto_reply: name == names.last().unwrap(),
        });
        let handle = OverlayNode::start(cfg, sec, sink).await.unwrap();
        *slot.lock().unwrap() = Some(handle.clone());
        handles.insert(name.clone(), handle);
    }

    // Give proactive MGMT preconnect a brief moment
    tokio::time::sleep(Duration::from_millis(250)).await;
    (dir, handles, delivered, notify)
}

async fn wait_deliveries(delivered: &DeliveredLog, notify: &Arc<Notify>, target: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        if delivered.lock().unwrap().len() >= target {
            return;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(
            !remaining.is_zero(),
            "timed out waiting for {target} cascade deliveries (got {})",
            delivered.lock().unwrap().len()
        );
        let _ = tokio::time::timeout(Duration::from_millis(100), notify.notified()).await;
    }
}

#[tokio::test]
async fn live_udp_fourteen_node_f3_ikev2_m_3_5_10_and_role_limited_memory_audit() {
    let names: Vec<String> = std::iter::once("InitNodeA".to_owned())
        .chain((1..=12).map(|i| format!("Relay{i:02}")))
        .chain(std::iter::once("RespNodeB".to_owned()))
        .collect();

    for hops in [3usize, 5, 10] {
        let (_dir, handles, delivered, notify) =
            start_cascade_cluster(&names, hops, HopSelectionModel::F3NoRep, 2).await;

        let spi = [0xA1, 0xB2, 0xC3, 0xD4, 0x01, 0x02, 0x03, hops as u8];
        let sa_init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"cascade-sa-init-payload");
        handles["InitNodeA"]
            .send_local_ike("RespNodeB", sa_init, 500)
            .await
            .unwrap();
        // Expect 2 deliveries: fwd SA_INIT on RespNodeB + auto-replied back SA_INIT on InitNodeA
        wait_deliveries(&delivered, &notify, 2).await;

        // Send IKE_AUTH over the established active m-hop route
        let ike_auth = build_ikev2(500, IKE_AUTH, 1, false, spi, b"cascade-ike-auth-payload");
        handles["InitNodeA"]
            .send_local_ike("RespNodeB", ike_auth, 500)
            .await
            .unwrap();
        wait_deliveries(&delivered, &notify, 4).await;

        // Give losing parallel chain CASCADE_CLOSE a brief moment to settle
        tokio::time::sleep(Duration::from_millis(150)).await;

        let log = delivered.lock().unwrap().clone();
        assert_eq!(
            log.len(),
            4,
            "hops={hops}: K=2 parallel chains must deduplicate cleanly"
        );
        assert_eq!(log[0].0, "RespNodeB");
        assert_eq!(log[1].0, "InitNodeA");
        assert_eq!(log[2].0, "RespNodeB");
        assert_eq!(log[3].0, "InitNodeA");

        // Role-limited knowledge audit across ALL 14 live UDP nodes!
        let first_hop = handles["InitNodeA"]
            .cascade_first_hop("RespNodeB")
            .await
            .expect("InitNodeA must know X1");
        let last_hop = handles["RespNodeB"]
            .cascade_last_hop("InitNodeA")
            .await
            .expect("RespNodeB must know Xm");
        assert_ne!(first_hop, last_hop, "F3 m>=3 must have distinct X1 and Xm");

        // Follow the active chain hop-by-hop and verify every node X1..Xm sees ONLY neighbors!
        let mut cur = first_hop.clone();
        let mut expected_prev = "InitNodeA".to_owned();
        let mut visited_relays = std::collections::BTreeSet::new();
        for pos in 1..=hops {
            assert!(
                visited_relays.insert(cur.clone()),
                "F3 must never repeat relay {cur}"
            );
            let knowledge = handles[&cur].cascade_relay_knowledge().await;
            let active_cells: Vec<_> = knowledge
                .into_iter()
                .filter(|c| c.state == "active")
                .collect();
            assert_eq!(active_cells.len(), 1);
            assert_eq!(active_cells[0].previous_peer, expected_prev);
            assert_ne!(
                active_cells[0].inbound_handle,
                active_cells[0].outbound_handle
            );
            let next = active_cells[0].next_peer.clone();

            let mem_dump = handles[&cur].cascade_memory_debug().await;
            let mem_str = serde_json::to_string(&mem_dump).unwrap();
            if pos >= 2 && pos < hops {
                // Interior relay Xk (2 <= k <= m-1) must NEVER hold InitNodeA or RespNodeB!
                assert!(
                    !mem_str.contains("InitNodeA"),
                    "LEAK on interior relay {cur} (pos {pos}/{hops}): {mem_str}"
                );
                assert!(
                    !mem_str.contains("RespNodeB"),
                    "LEAK on interior relay {cur} (pos {pos}/{hops}): {mem_str}"
                );
            } else if pos == 1 {
                assert!(!mem_str.contains("RespNodeB"));
            } else if pos == hops {
                assert_eq!(next, "RespNodeB");
                assert!(!mem_str.contains("InitNodeA"));
            }

            expected_prev = cur;
            cur = next;
        }
        assert_eq!(expected_prev, last_hop);
        assert_eq!(cur, "RespNodeB");

        for h in handles.values() {
            h.shutdown().await;
        }
    }
}

#[tokio::test]
async fn live_udp_four_node_f4_ikev2_m_3_5_10_with_repeats() {
    let names = vec![
        "A".to_owned(),
        "X1".to_owned(),
        "X2".to_owned(),
        "B".to_owned(),
    ];
    for hops in [3usize, 5, 10] {
        let (_dir, handles, delivered, notify) =
            start_cascade_cluster(&names, hops, HopSelectionModel::F4WithRep, 2).await;

        let spi = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, hops as u8];
        let sa_init = build_ikev2(4500, IKE_SA_INIT, 0, false, spi, b"f4-4node-sa-init");
        handles["A"]
            .send_local_ike("B", sa_init, 4500)
            .await
            .unwrap();
        wait_deliveries(&delivered, &notify, 2).await;

        let ike_auth = build_ikev2(4500, IKE_AUTH, 1, false, spi, b"f4-4node-ike-auth");
        handles["A"]
            .send_local_ike("B", ike_auth, 4500)
            .await
            .unwrap();
        wait_deliveries(&delivered, &notify, 4).await;

        tokio::time::sleep(Duration::from_millis(120)).await;
        let x1_active = handles["X1"]
            .cascade_relay_knowledge()
            .await
            .into_iter()
            .filter(|c| c.state == "active")
            .count();
        let x2_active = handles["X2"]
            .cascade_relay_knowledge()
            .await
            .into_iter()
            .filter(|c| c.state == "active")
            .count();
        assert_eq!(
            x1_active + x2_active,
            hops,
            "4-node F4 hops={hops}: total active cells across X1+X2 must equal {hops}"
        );

        for h in handles.values() {
            h.shutdown().await;
        }
    }
}
