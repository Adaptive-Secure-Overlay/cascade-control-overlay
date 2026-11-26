#![forbid(unsafe_code)]
//! Sans-I/O test suite for Universal H-hop Privacy Cascade (`universal_cascade.py`).

use std::collections::{BTreeMap, VecDeque};

use cco_cascade::universal::{
    CASCADE_FIXED_WIRE_BYTES, CascadeAction, CascadeIdentity, HopSelectionModel, PeerChooser,
    UniversalCascade, calculate_copy_budget, validate_hop_count,
};
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_proto::{MessageType, jdump};
use cco_trust::{
    NodeKeyRecord, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use serde_json::{Map, Value};

struct CascadeNet {
    nodes: BTreeMap<String, UniversalCascade>,
    queue: VecDeque<(String, String, MessageType, Value)>,
    deliveries: Vec<(String, String, String, Vec<u8>)>,
    ready: Vec<(String, String, usize)>,
    now: f64,
}

impl CascadeNet {
    fn new(names: &[&str], max_hops: usize) -> Self {
        let mut secrets = BTreeMap::new();
        let mut publics = BTreeMap::new();
        for &n in names {
            let sk = X25519SecretKey::generate();
            publics.insert(n.to_owned(), sk.public_key());
            secrets.insert(n.to_owned(), sk);
        }
        let member_vec: Vec<String> = names.iter().map(|s| (*s).to_owned()).collect();
        let mut nodes = BTreeMap::new();
        for &n in names {
            let id = CascadeIdentity::new(n, secrets.remove(n).unwrap(), publics.clone()).unwrap();
            // Deterministic first-candidate chooser for reproducible hop paths
            let chooser: PeerChooser = Box::new(|_node, _purpose, cands| cands[0].clone());
            let uc = UniversalCascade::new(id, member_vec.clone(), max_hops, 120.0, Some(chooser))
                .unwrap();
            nodes.insert(n.to_owned(), uc);
        }
        Self {
            nodes,
            queue: VecDeque::new(),
            deliveries: Vec::new(),
            ready: Vec::new(),
            now: 1000.0,
        }
    }

    fn enqueue(&mut self, from: &str, actions: Vec<CascadeAction>) {
        for act in actions {
            match act {
                CascadeAction::Send {
                    peer,
                    message_type,
                    message,
                } => self
                    .queue
                    .push_back((from.to_owned(), peer, message_type, message)),
                CascadeAction::Deliver {
                    direction,
                    remote_peer,
                    payload,
                    ..
                } => self
                    .deliveries
                    .push((from.to_owned(), direction, remote_peer, payload)),
                CascadeAction::RouteReady {
                    remote_peer, hops, ..
                } => self.ready.push((from.to_owned(), remote_peer, hops)),
            }
        }
    }

    fn pump(&mut self) {
        while let Some((src, dst, mtype, msg)) = self.queue.pop_front() {
            let actions = self
                .nodes
                .get_mut(&dst)
                .unwrap()
                .receive(&src, mtype, &msg, "", self.now)
                .unwrap();
            self.enqueue(&dst, actions);
        }
    }
}

#[test]
fn universal_cascade_arbitrary_hops_two_through_five_with_privacy_and_bidirectional_data() {
    let members = ["A", "X1", "X2", "X3", "X4", "X5", "B"];
    for hops in 2..=5 {
        let mut net = CascadeNet::new(&members, 8);
        let init_actions = net
            .nodes
            .get_mut("A")
            .unwrap()
            .start_route("B", hops, b"ike-sa-init", Map::new(), Some("X1"), net.now)
            .unwrap();
        net.enqueue("A", init_actions);

        // Queue a forward packet while route is still building -> must flush on RouteReady
        let queued = net
            .nodes
            .get_mut("A")
            .unwrap()
            .send_forward("B", b"queued-ike-auth", Map::new(), net.now)
            .unwrap();
        assert!(queued.is_empty());

        net.pump();

        assert_eq!(net.ready, vec![("A".to_owned(), "B".to_owned(), hops)]);
        assert_eq!(net.deliveries.len(), 2);
        assert_eq!(
            net.deliveries[0],
            (
                "B".to_owned(),
                "fwd".to_owned(),
                "A".to_owned(),
                b"ike-sa-init".to_vec()
            )
        );
        assert_eq!(
            net.deliveries[1],
            (
                "B".to_owned(),
                "fwd".to_owned(),
                "A".to_owned(),
                b"queued-ike-auth".to_vec()
            )
        );

        // Reverse data B -> A through the same H relays
        let back = net
            .nodes
            .get_mut("B")
            .unwrap()
            .send_reverse("A", b"ike-sa-resp", Map::new(), net.now)
            .unwrap();
        net.enqueue("B", back);
        net.pump();

        assert_eq!(net.deliveries.len(), 3);
        assert_eq!(
            net.deliveries[2],
            (
                "A".to_owned(),
                "back".to_owned(),
                "B".to_owned(),
                b"ike-sa-resp".to_vec()
            )
        );

        // Verify relay privacy invariants: active relays == hops, distinct in/out handles
        let mut active_relays = 0usize;
        for name in &members {
            let knowledge = net.nodes.get_mut(*name).unwrap().relay_knowledge(net.now);
            for cell in knowledge {
                assert_eq!(cell.state, "active");
                assert_ne!(cell.inbound_handle, cell.outbound_handle);
                assert_ne!(cell.previous_peer, cell.next_peer);
                active_relays += 1;
            }
        }
        assert_eq!(active_relays, hops);

        // Clean teardown via CASCADE_CLOSE removes all relay cells and endpoint route
        let close = net.nodes.get_mut("A").unwrap().close_source_route("B");
        net.enqueue("A", close);
        net.pump();
        for name in &members {
            let c = net.nodes.get_mut(*name).unwrap().local_counts(net.now);
            assert_eq!(c.relay_cells, 0);
            assert_eq!(c.source_routes, 0);
            assert_eq!(c.endpoint_routes, 0);
        }
    }
}

#[test]
fn universal_cascade_reject_reroutes_around_destination_and_abort_rebuilds_route() {
    let members = ["A", "B", "X1", "X2", "X3"];
    let mut net = CascadeNet::new(&members, 6);

    // X1's deterministic chooser picks "B" first as relay-2 (which is the destination!).
    // B MUST send CASCADE_REJECT and X1 MUST transparently reroute to X2 without learning B is dst!
    let start = net
        .nodes
        .get_mut("A")
        .unwrap()
        .start_route("B", 2, b"hello-reroute", Map::new(), Some("X1"), net.now)
        .unwrap();
    net.enqueue("A", start);
    net.pump();

    assert_eq!(net.ready, vec![("A".to_owned(), "B".to_owned(), 2)]);
    assert_eq!(net.deliveries.len(), 1);
    assert_eq!(net.deliveries[0].3, b"hello-reroute");

    // Simulate link failure on X1 -> next_hop during forward data -> CASCADE_ABORT rebuilds on A
    let fwd = net
        .nodes
        .get_mut("A")
        .unwrap()
        .send_forward("B", b"after-abort", Map::new(), net.now)
        .unwrap();
    net.enqueue("A", fwd);

    // Deliver A->X1, then inject send failure at X1->X2
    let (src, dst, mtype, msg) = net.queue.pop_front().unwrap();
    assert_eq!((src.as_str(), dst.as_str()), ("A", "X1"));
    let x1_out = net
        .nodes
        .get_mut("X1")
        .unwrap()
        .receive("A", mtype, &msg, "", net.now)
        .unwrap();
    let CascadeAction::Send {
        peer: failed_peer,
        message_type: failed_type,
        message: failed_msg,
    } = &x1_out[0]
    else {
        panic!("expected forwarded CASCADE_DATA");
    };
    let abort_actions = net
        .nodes
        .get_mut("X1")
        .unwrap()
        .handle_send_failure(failed_peer, *failed_type, failed_msg, net.now)
        .unwrap();
    net.enqueue("X1", abort_actions);
    net.pump();

    // Route automatically rebuilt and delivered the in-flight payload!
    assert_eq!(net.deliveries.len(), 2);
    assert_eq!(net.deliveries[1].3, b"after-abort");
    assert!(
        net.nodes
            .get_mut("A")
            .unwrap()
            .has_source_route("B", true, net.now)
    );
}

#[test]
fn universal_cascade_anti_replay_and_budget_helpers() {
    assert_eq!(validate_hop_count(3, 2, 16).unwrap(), 3);
    assert!(validate_hop_count(1, 2, 16).is_err());
    assert_eq!(calculate_copy_budget(&[3, 3, 3], Some(64)).unwrap(), 27);
    assert!(calculate_copy_budget(&[5, 5, 5], Some(64)).is_err());

    let members = ["A", "X1", "X2", "B"];
    let mut net = CascadeNet::new(&members, 6);
    let start = net
        .nodes
        .get_mut("A")
        .unwrap()
        .start_route("B", 2, b"init", Map::new(), Some("X1"), net.now)
        .unwrap();
    net.enqueue("A", start);
    net.pump();

    let fwd = net
        .nodes
        .get_mut("A")
        .unwrap()
        .send_forward("B", b"once", Map::new(), net.now)
        .unwrap();
    let CascadeAction::Send {
        peer,
        message_type,
        message,
    } = fwd[0].clone()
    else {
        panic!("expected send");
    };
    // Deliver normally once, then replay the exact same wire message
    net.enqueue(
        "A",
        vec![CascadeAction::Send {
            peer: peer.clone(),
            message_type,
            message: message.clone(),
        }],
    );
    net.pump();
    assert_eq!(net.deliveries.len(), 2);

    net.enqueue(
        "A",
        vec![CascadeAction::Send {
            peer,
            message_type,
            message,
        }],
    );
    net.pump();
    // Anti-replay set on B drops duplicate sequence number!
    assert_eq!(net.deliveries.len(), 2);
}

#[test]
fn negative_knowledge_leakage_and_constant_size_padding_for_m_3_5_10() {
    // Use distinctive unambiguous node identifiers so substring checks catch any leak reliably.
    let members = [
        "EndpointInitA",
        "RelayNode01",
        "RelayNode02",
        "RelayNode03",
        "RelayNode04",
        "RelayNode05",
        "RelayNode06",
        "RelayNode07",
        "RelayNode08",
        "RelayNode09",
        "RelayNode10",
        "RelayNode11",
        "RelayNode12",
        "EndpointRespB",
    ];
    let member_vec: Vec<String> = members.iter().map(|s| (*s).to_owned()).collect();

    // Build a real Ed25519-signed Trust Registry v2 so capsule Ed25519 signatures are verified too.
    let dir = tempfile::TempDir::new().unwrap();
    let root_sk = Ed25519SecretKey::generate();
    let mut root_signers = BTreeMap::new();
    root_signers.insert("audit-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    std::fs::write(&root_path, build_trust_root_bytes(&root_signers).unwrap()).unwrap();

    let mut enc_keys = BTreeMap::new();
    let mut sig_keys = BTreeMap::new();
    let mut records = BTreeMap::new();
    for &name in &members {
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
        sig_keys.insert(name.to_owned(), esk);
        enc_keys.insert(name.to_owned(), xsk);
    }
    let reg_bytes = sign_registry_v2(1, &records, "audit-root", &root_sk).unwrap();
    let verified = verify_registry_bytes(
        &reg_bytes,
        &root_path,
        members.iter().copied(),
        VerifyConstraints::default(),
    )
    .unwrap();

    let forbidden_wire_keys = [
        "remaining",
        "hops",
        "total_hops",
        "visited",
        "path",
        "source",
        "destination",
        "route_tag",
        "exchange_id",
    ];

    for hops in [3usize, 5, 10] {
        // Construct deterministic linear relay sequence RelayNode01 -> RelayNode02 -> ... -> RelayNode{hops}
        let mut nodes = BTreeMap::new();
        for &name in &members {
            let id = CascadeIdentity::from_verified_registry_signed(
                name,
                X25519SecretKey::from_bytes(*enc_keys[name].to_bytes_zeroizing()),
                Ed25519SecretKey::from_bytes(*sig_keys[name].to_bytes_zeroizing()),
                &verified,
            )
            .unwrap();
            let target_next: Option<String> = if let Some(num_str) = name.strip_prefix("RelayNode")
            {
                let idx: usize = num_str.parse().unwrap();
                Some(format!("RelayNode{:02}", idx + 1))
            } else {
                None
            };
            let chooser: PeerChooser = Box::new(move |_node, _purpose, cands| {
                if let Some(ref wanted) = target_next {
                    if cands.iter().any(|c| c == wanted) {
                        return wanted.clone();
                    }
                }
                cands[0].clone()
            });
            let uc = UniversalCascade::new_with_model(
                id,
                member_vec.clone(),
                16,
                120.0,
                HopSelectionModel::F3NoRep,
                Some(chooser),
            )
            .unwrap();
            nodes.insert(name.to_owned(), uc);
        }

        let mut queue: VecDeque<(String, String, MessageType, Value)> = VecDeque::new();
        let mut wire_log: Vec<(String, String, MessageType, Vec<u8>, Value)> = Vec::new();
        let mut deliveries = Vec::new();
        let now = 2000.0;

        // Test with different payload lengths (64 B WG-like vs 900 B IKEv2-like)
        let init_payload = vec![0x42u8; if hops == 3 { 64 } else { 900 }];
        let init_acts = nodes
            .get_mut("EndpointInitA")
            .unwrap()
            .start_route(
                "EndpointRespB",
                hops,
                &init_payload,
                Map::new(),
                Some("RelayNode01"),
                now,
            )
            .unwrap();
        for act in init_acts {
            if let CascadeAction::Send {
                peer,
                message_type,
                message,
            } = act
            {
                let raw = jdump(&message).unwrap();
                wire_log.push((
                    "EndpointInitA".to_owned(),
                    peer.clone(),
                    message_type,
                    raw,
                    message.clone(),
                ));
                queue.push_back(("EndpointInitA".to_owned(), peer, message_type, message));
            }
        }

        while let Some((src, dst, mtype, msg)) = queue.pop_front() {
            let acts = nodes
                .get_mut(&dst)
                .unwrap()
                .receive(&src, mtype, &msg, "", now)
                .unwrap();
            for act in acts {
                match act {
                    CascadeAction::Send {
                        peer,
                        message_type,
                        message,
                    } => {
                        let raw = jdump(&message).unwrap();
                        wire_log.push((
                            dst.clone(),
                            peer.clone(),
                            message_type,
                            raw,
                            message.clone(),
                        ));
                        queue.push_back((dst.clone(), peer, message_type, message));
                    }
                    CascadeAction::Deliver {
                        direction,
                        remote_peer,
                        payload,
                        ..
                    } => {
                        deliveries.push((dst.clone(), direction, remote_peer, payload));
                    }
                    CascadeAction::RouteReady { .. } => {}
                }
            }
        }

        // Send forward + reverse control packets across the active m-hop route
        for (sender, is_fwd, data) in [
            ("EndpointInitA", true, vec![0x11u8; 288]),
            ("EndpointRespB", false, vec![0x22u8; 92]),
        ] {
            let acts = if is_fwd {
                nodes
                    .get_mut(sender)
                    .unwrap()
                    .send_forward("EndpointRespB", &data, Map::new(), now)
                    .unwrap()
            } else {
                nodes
                    .get_mut(sender)
                    .unwrap()
                    .send_reverse("EndpointInitA", &data, Map::new(), now)
                    .unwrap()
            };
            for act in acts {
                if let CascadeAction::Send {
                    peer,
                    message_type,
                    message,
                } = act
                {
                    let raw = jdump(&message).unwrap();
                    wire_log.push((
                        sender.to_owned(),
                        peer.clone(),
                        message_type,
                        raw,
                        message.clone(),
                    ));
                    queue.push_back((sender.to_owned(), peer, message_type, message));
                }
            }
            while let Some((src, dst, mtype, msg)) = queue.pop_front() {
                let acts = nodes
                    .get_mut(&dst)
                    .unwrap()
                    .receive(&src, mtype, &msg, "", now)
                    .unwrap();
                for act in acts {
                    match act {
                        CascadeAction::Send {
                            peer,
                            message_type,
                            message,
                        } => {
                            let raw = jdump(&message).unwrap();
                            wire_log.push((
                                dst.clone(),
                                peer.clone(),
                                message_type,
                                raw,
                                message.clone(),
                            ));
                            queue.push_back((dst.clone(), peer, message_type, message));
                        }
                        CascadeAction::Deliver {
                            direction,
                            remote_peer,
                            payload,
                            ..
                        } => deliveries.push((dst.clone(), direction, remote_peer, payload)),
                        CascadeAction::RouteReady { .. } => {}
                    }
                }
            }
        }

        assert_eq!(deliveries.len(), 3, "hops={hops}: expected init+fwd+back");

        // 1. Wire-level audit across EVERY message on EVERY hop:
        //    - EXACT constant size == CASCADE_FIXED_WIRE_BYTES
        //    - ZERO forbidden plaintext fields (remaining/hops/visited/source/destination/etc.)
        //    - ZERO endpoint/unrelated relay names in ANY wire message!
        for (src, dst, mtype, raw, val) in &wire_log {
            assert_eq!(
                raw.len(),
                CASCADE_FIXED_WIRE_BYTES,
                "wire size leak at hops={hops} {src}->{dst} ({mtype:?})"
            );
            let obj = val.as_object().unwrap();
            for bad_key in forbidden_wire_keys {
                assert!(
                    !obj.contains_key(bad_key),
                    "forbidden plaintext field `{bad_key}` leaked in {mtype:?} ({src}->{dst})"
                );
            }
            let raw_str = std::str::from_utf8(raw).unwrap();
            for &node_name in &members {
                assert!(
                    !raw_str.contains(node_name),
                    "node identifier `{node_name}` leaked inside wire payload {mtype:?} ({src}->{dst})"
                );
            }
        }

        // 2. Role-limited memory audit for Initiator A, Responder B, and EVERY relay X1..Xm:
        assert_eq!(
            nodes["EndpointInitA"]
                .source_first_hop("EndpointRespB")
                .as_deref(),
            Some("RelayNode01")
        );
        assert_eq!(
            nodes["EndpointRespB"]
                .endpoint_last_hop("EndpointInitA")
                .as_deref(),
            Some(format!("RelayNode{hops:02}").as_str())
        );

        for k in 1..=hops {
            let relay_name = format!("RelayNode{k:02}");
            let expected_prev = if k == 1 {
                "EndpointInitA".to_owned()
            } else {
                format!("RelayNode{:02}", k - 1)
            };
            let expected_next = if k == hops {
                "EndpointRespB".to_owned()
            } else {
                format!("RelayNode{:02}", k + 1)
            };

            let knowledge = nodes.get_mut(&relay_name).unwrap().relay_knowledge(now);
            assert_eq!(knowledge.len(), 1, "F3 must visit {relay_name} once");
            assert_eq!(knowledge[0].previous_peer, expected_prev);
            assert_eq!(knowledge[0].next_peer, expected_next);
            assert_ne!(knowledge[0].inbound_handle, knowledge[0].outbound_handle);
            assert_eq!(knowledge[0].state, "active");

            // Full memory dump check: NO build context left, NO unauthorized node names anywhere!
            let mem_dump = nodes[&relay_name].inspect_relay_memory_debug();
            let mem_str = serde_json::to_string(&mem_dump).unwrap();
            assert_eq!(mem_dump["relay_cells"][0]["has_build_ctx"], false);
            assert_eq!(mem_dump["relay_cells"][0]["probe_handles_count"], 0);
            for &other in &members {
                if other == relay_name || other == expected_prev || other == expected_next {
                    continue;
                }
                assert!(
                    !mem_str.contains(other),
                    "MEMORY LEAK on {relay_name} (hops={hops}): found unauthorized node `{other}` in {mem_str}"
                );
            }
            // Interior relays (2 <= k < hops) must NEVER see EndpointInitA or EndpointRespB
            if k >= 2 && k < hops {
                assert!(!mem_str.contains("EndpointInitA"));
                assert!(!mem_str.contains("EndpointRespB"));
            }
        }
    }
}

#[test]
fn four_node_f4_allows_repeats_for_m_3_5_10_and_linear_k_parallel_chains_dedup() {
    // 4-node topology identical to live WAN lab: only 2 relays (X1, X2)!
    // Under F4, non-adjacent repeats allow m = 3, 5, 10 without ever transmitting `visited`.
    let members = ["NodeA", "RelayX1", "RelayX2", "NodeB"];
    let member_vec: Vec<String> = members.iter().map(|s| (*s).to_owned()).collect();

    for hops in [3usize, 5, 10] {
        let mut secrets = BTreeMap::new();
        let mut publics = BTreeMap::new();
        for &n in &members {
            let sk = X25519SecretKey::generate();
            publics.insert(n.to_owned(), sk.public_key());
            secrets.insert(n.to_owned(), sk);
        }
        let mut nodes = BTreeMap::new();
        for &n in &members {
            let id = CascadeIdentity::new(n, secrets.remove(n).unwrap(), publics.clone()).unwrap();
            let uc = UniversalCascade::new_with_model(
                id,
                member_vec.clone(),
                16,
                120.0,
                HopSelectionModel::F4WithRep,
                None,
            )
            .unwrap();
            nodes.insert(n.to_owned(), uc);
        }

        let mut queue: VecDeque<(String, String, MessageType, Value)> = VecDeque::new();
        let mut build_packets = 0usize;
        let mut deliveries = Vec::new();
        let mut ready_count = 0usize;
        let now = 3000.0;

        // Launch K = 2 parallel independent chains of length `hops` (O(K * hops), not O(2^hops)!)
        let k_chains = 2usize;
        let init_acts = nodes
            .get_mut("NodeA")
            .unwrap()
            .start_parallel_chains("NodeB", hops, k_chains, b"wg-type1-init", Map::new(), now)
            .unwrap();
        assert_eq!(init_acts.len(), k_chains);
        for act in init_acts {
            if let CascadeAction::Send {
                peer,
                message_type,
                message,
            } = act
            {
                if message_type == MessageType::CascadeBuild {
                    build_packets += 1;
                }
                assert_eq!(jdump(&message).unwrap().len(), CASCADE_FIXED_WIRE_BYTES);
                queue.push_back(("NodeA".to_owned(), peer, message_type, message));
            }
        }

        while let Some((src, dst, mtype, msg)) = queue.pop_front() {
            let acts = nodes
                .get_mut(&dst)
                .unwrap()
                .receive(&src, mtype, &msg, "", now)
                .unwrap();
            for act in acts {
                match act {
                    CascadeAction::Send {
                        peer,
                        message_type,
                        message,
                    } => {
                        if message_type == MessageType::CascadeBuild {
                            build_packets += 1;
                        }
                        assert_eq!(jdump(&message).unwrap().len(), CASCADE_FIXED_WIRE_BYTES);
                        queue.push_back((dst.clone(), peer, message_type, message));
                    }
                    CascadeAction::Deliver {
                        direction,
                        remote_peer,
                        payload,
                        ..
                    } => deliveries.push((dst.clone(), direction, remote_peer, payload)),
                    CascadeAction::RouteReady { hops: h, .. } => {
                        assert_eq!(h, hops);
                        ready_count += 1;
                    }
                }
            }
        }

        // First-chain-wins deduplication on NodeB: EXACTLY 1 delivery despite K = 2 parallel chains!
        assert_eq!(ready_count, 1, "hops={hops}: exactly one winning chain");
        assert_eq!(
            deliveries.len(),
            1,
            "hops={hops}: NodeB must deduplicate K-1 losing chains"
        );
        assert_eq!(deliveries[0].3, b"wg-type1-init");

        // Linear O(K * hops) build budget (including bounded random A/B rejects in 4-node F4,
        // still strictly linear — far below exponential 2^10 = 1024!).
        assert!(
            build_packets <= k_chains * hops * 4,
            "hops={hops}: build_packets={build_packets} must remain linear O(K*m)"
        );

        // Bidirectional reverse response NodeB -> NodeA works over the m-hop winning chain!
        let back = nodes
            .get_mut("NodeB")
            .unwrap()
            .send_reverse("NodeA", b"wg-type2-resp", Map::new(), now)
            .unwrap();
        for act in back {
            if let CascadeAction::Send {
                peer,
                message_type,
                message,
            } = act
            {
                queue.push_back(("NodeB".to_owned(), peer, message_type, message));
            }
        }
        while let Some((src, dst, mtype, msg)) = queue.pop_front() {
            let acts = nodes
                .get_mut(&dst)
                .unwrap()
                .receive(&src, mtype, &msg, "", now)
                .unwrap();
            for act in acts {
                match act {
                    CascadeAction::Send {
                        peer,
                        message_type,
                        message,
                    } => queue.push_back((dst.clone(), peer, message_type, message)),
                    CascadeAction::Deliver {
                        direction,
                        remote_peer,
                        payload,
                        ..
                    } => deliveries.push((dst.clone(), direction, remote_peer, payload)),
                    CascadeAction::RouteReady { .. } => {}
                }
            }
        }
        assert_eq!(deliveries.len(), 2);
        assert_eq!(deliveries[1].0, "NodeA");
        assert_eq!(deliveries[1].3, b"wg-type2-resp");

        // Total active relay cells across X1 + X2 equals exactly `hops` (losing chain was closed!).
        let active_x1 = nodes.get_mut("RelayX1").unwrap().relay_knowledge(now).len();
        let active_x2 = nodes.get_mut("RelayX2").unwrap().relay_knowledge(now).len();
        assert_eq!(
            active_x1 + active_x2,
            hops,
            "losing chain must be closed so exactly `hops` active relay cells remain"
        );
    }
}

#[test]
fn stochastic_f3_fourteen_nodes_m10_has_zero_repeats_and_linear_k_chains() {
    let members: Vec<String> = std::iter::once("InitA".to_owned())
        .chain((1..=12).map(|i| format!("R{i:02}")))
        .chain(std::iter::once("RespB".to_owned()))
        .collect();

    let mut secrets = BTreeMap::new();
    let mut publics = BTreeMap::new();
    for n in &members {
        let sk = X25519SecretKey::generate();
        publics.insert(n.clone(), sk.public_key());
        secrets.insert(n.clone(), sk);
    }
    let mut nodes = BTreeMap::new();
    for n in &members {
        let id = CascadeIdentity::new(n, secrets.remove(n).unwrap(), publics.clone()).unwrap();
        let uc = UniversalCascade::new_with_model(
            id,
            members.clone(),
            16,
            120.0,
            HopSelectionModel::F3NoRep,
            None,
        )
        .unwrap();
        nodes.insert(n.clone(), uc);
    }

    let now = 4000.0;
    let mut queue = VecDeque::new();
    let mut deliveries = 0usize;
    let init = nodes
        .get_mut("InitA")
        .unwrap()
        .start_parallel_chains("RespB", 10, 2, b"ike-sa-init-m10", Map::new(), now)
        .unwrap();
    for act in init {
        if let CascadeAction::Send {
            peer,
            message_type,
            message,
        } = act
        {
            queue.push_back(("InitA".to_owned(), peer, message_type, message));
        }
    }
    while let Some((src, dst, mtype, msg)) = queue.pop_front() {
        let acts = nodes
            .get_mut(&dst)
            .unwrap()
            .receive(&src, mtype, &msg, "", now)
            .unwrap();
        for act in acts {
            match act {
                CascadeAction::Send {
                    peer,
                    message_type,
                    message,
                } => queue.push_back((dst.clone(), peer, message_type, message)),
                CascadeAction::Deliver { .. } => deliveries += 1,
                CascadeAction::RouteReady { .. } => {}
            }
        }
    }

    assert_eq!(deliveries, 1);
    // In F3 with m = 10, EXACTLY 10 distinct relays each hold 1 active cell (0 repeated relays!)
    let mut distinct_active_relays = 0usize;
    for n in &members {
        let rk = nodes.get_mut(n).unwrap().relay_knowledge(now);
        assert!(
            rk.len() <= 1,
            "F3 must never repeat relay {n}: got {}",
            rk.len()
        );
        distinct_active_relays += rk.len();
    }
    assert_eq!(distinct_active_relays, 10);
}
