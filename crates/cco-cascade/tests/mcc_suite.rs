#![forbid(unsafe_code)]
//! Comprehensive Sans-I/O test suite for MCC Authenticated + Opaque Privacy + SQLite ledger.
//!
//! Covers all scenarios from `test_mcc_e2e.py`, `test_mcc_auth_integration.py`,
//! and `test_mcc_privacy.py` using RFC 5737 documentation addresses only.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::net::Ipv4Addr;

use cco_cascade::mcc::{
    AdmitStatus, EndpointSecurity, IkeInjectionOutcome, MccAction, MccFanout, MccNodeConfig,
    MccNodeMachine, SelectionMode, SelectionPolicy,
};
use cco_crypto::{Ed25519SecretKey, MccCapsulePurpose, X25519SecretKey};
use cco_proto::{
    CanonicalValue, IKE_AUTH, IKE_SA_INIT, IKEV2_FLAG_INITIATOR, IKEV2_FLAG_RESPONSE, MessageType,
    jdump, jload,
};
use cco_trust::{
    NodeKeyRecord, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use tempfile::TempDir;

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

struct MccNetwork {
    dir: TempDir,
    root_sk: Ed25519SecretKey,
    root_path: std::path::PathBuf,
    signing: BTreeMap<String, Ed25519SecretKey>,
    encryption: BTreeMap<String, X25519SecretKey>,
    node_records: BTreeMap<String, NodeKeyRecord>,
    peers: BTreeMap<String, Ipv4Addr>,
    nodes: BTreeMap<String, MccNodeMachine>,
    now_ms: u64,
    injections: Vec<(String, Vec<u8>, String)>,
    rejections: Vec<(String, &'static str)>,
    offers_seen: usize,
    queue: VecDeque<(String, String, MessageType, Vec<u8>)>,
}

impl MccNetwork {
    fn new(names: &[&str], fanout: MccFanout, policy: SelectionPolicy) -> Self {
        let dir = TempDir::new().unwrap();
        let root_sk = Ed25519SecretKey::generate();
        let mut signers = BTreeMap::new();
        signers.insert("test-root".to_owned(), root_sk.public_key());
        let root_path = dir.path().join("root.json");
        fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

        let mut signing = BTreeMap::new();
        let mut encryption = BTreeMap::new();
        let mut node_records = BTreeMap::new();
        let mut peers = BTreeMap::new();

        for (i, &name) in names.iter().enumerate() {
            let esk = Ed25519SecretKey::generate();
            let xsk = X25519SecretKey::generate();
            let ver = esk.public_key();
            node_records.insert(
                name.to_owned(),
                NodeKeyRecord {
                    encryption: xsk.public_key(),
                    verification: ver,
                    key_id: ver.key_id(),
                    revoked: false,
                },
            );
            signing.insert(name.to_owned(), esk);
            encryption.insert(name.to_owned(), xsk);
            // Strictly RFC 5737 TEST-NET-1 documentation addresses
            peers.insert(name.to_owned(), Ipv4Addr::new(192, 0, 2, (i + 10) as u8));
        }

        let reg_bytes = sign_registry_v2(1, &node_records, "test-root", &root_sk).unwrap();
        let verified_reg = verify_registry_bytes(
            &reg_bytes,
            &root_path,
            names.iter().copied(),
            VerifyConstraints::default(),
        )
        .unwrap();

        let now_ms = 1_800_000_000_000u64;
        let now_s = (now_ms / 1000) as i64;
        let mut nodes = BTreeMap::new();
        for (i, &name) in names.iter().enumerate() {
            let sec = EndpointSecurity::new(
                name,
                verified_reg.clone(),
                Ed25519SecretKey::from_bytes(*signing[name].to_bytes_zeroizing()),
                X25519SecretKey::from_bytes(*encryption[name].to_bytes_zeroizing()),
                dir.path().join(format!("{name}.sqlite")),
                now_s,
            )
            .unwrap();
            let cfg = MccNodeConfig {
                peers: peers.clone(),
                fanout,
                policy: policy.clone(),
                deterministic_seed: Some(100 + i as u64),
            };
            nodes.insert(name.to_owned(), MccNodeMachine::new(sec, cfg).unwrap());
        }

        Self {
            dir,
            root_sk,
            root_path,
            signing,
            encryption,
            node_records,
            peers,
            nodes,
            now_ms,
            injections: Vec::new(),
            rejections: Vec::new(),
            offers_seen: 0,
            queue: VecDeque::new(),
        }
    }

    fn restart_node(&mut self, name: &str, fanout: MccFanout, policy: SelectionPolicy) {
        let names: Vec<&str> = self.peers.keys().map(String::as_str).collect();
        let reg_bytes =
            sign_registry_v2(1, &self.node_records, "test-root", &self.root_sk).unwrap();
        let verified_reg = verify_registry_bytes(
            &reg_bytes,
            &self.root_path,
            names,
            VerifyConstraints::default(),
        )
        .unwrap();
        let sec = EndpointSecurity::new(
            name,
            verified_reg,
            Ed25519SecretKey::from_bytes(*self.signing[name].to_bytes_zeroizing()),
            X25519SecretKey::from_bytes(*self.encryption[name].to_bytes_zeroizing()),
            self.dir.path().join(format!("{name}.sqlite")),
            (self.now_ms / 1000) as i64,
        )
        .unwrap();
        let cfg = MccNodeConfig {
            peers: self.peers.clone(),
            fanout,
            policy,
            deterministic_seed: Some(999),
        };
        self.nodes
            .insert(name.to_owned(), MccNodeMachine::new(sec, cfg).unwrap());
    }

    fn enqueue_actions(&mut self, from: &str, actions: Vec<MccAction>, auto_reply: bool) {
        for action in actions {
            match action {
                MccAction::Send {
                    peer,
                    message_type,
                    payload,
                } => {
                    if message_type == MessageType::MccOffer {
                        self.offers_seen += 1;
                    }
                    self.queue
                        .push_back((from.to_owned(), peer, message_type, payload));
                }
                MccAction::DeliverIke { proof } => {
                    let (payload, meta, receipt) = proof.consume();
                    self.injections
                        .push((from.to_owned(), payload.clone(), meta.x2.clone()));
                    let follow = self.nodes.get_mut(from).unwrap().complete_delivery(
                        receipt,
                        IkeInjectionOutcome::Sent,
                        self.now_ms,
                    );
                    self.enqueue_actions(from, follow, auto_reply);

                    if auto_reply && meta.direction == "fwd" {
                        let hdr = cco_proto::parse_ikev2_packet(meta.udp_port, &payload).unwrap();
                        let resp = build_ikev2(
                            meta.udp_port,
                            hdr.exchange_type,
                            hdr.message_id,
                            true,
                            hdr.initiator_spi,
                            b"ike-resp",
                        );
                        let resp_actions = self
                            .nodes
                            .get_mut(from)
                            .unwrap()
                            .send_local_ike(&meta.src, &resp, meta.udp_port, self.now_ms)
                            .unwrap();
                        self.enqueue_actions(from, resp_actions, auto_reply);
                    }
                }
                MccAction::Reject { code } => {
                    self.rejections.push((from.to_owned(), code));
                }
            }
        }
    }

    fn pump_with<F>(&mut self, auto_reply: bool, mut interceptor: F)
    where
        F: FnMut(&str, &str, MessageType, Vec<u8>) -> Option<Vec<u8>>,
    {
        while let Some((src, dst, mtype, payload)) = self.queue.pop_front() {
            let Some(final_payload) = interceptor(&src, &dst, mtype, payload) else {
                continue;
            };
            let actions = self.nodes.get_mut(&dst).unwrap().on_inbound(
                &src,
                mtype,
                &final_payload,
                self.now_ms,
            );
            self.enqueue_actions(&dst, actions, auto_reply);
        }
    }

    fn pump(&mut self, auto_reply: bool) {
        self.pump_with(auto_reply, |_, _, _, p| Some(p));
    }

    fn advance_ms(&mut self, delta_ms: u64, auto_reply: bool) {
        self.now_ms += delta_ms;
        let names: Vec<String> = self.nodes.keys().cloned().collect();
        for name in names {
            let actions = self.nodes.get_mut(&name).unwrap().on_tick(self.now_ms);
            self.enqueue_actions(&name, actions, auto_reply);
        }
        self.pump(auto_reply);
    }
}

#[test]
fn nine_valid_copies_all_four_selection_modes_and_ike_auth_continuation() {
    let policies = [
        SelectionPolicy::first(12_000),
        SelectionPolicy::window(300, 12_000),
        SelectionPolicy::adaptive(3, 150, 12_000),
        SelectionPolicy::wait_all(12_000),
    ];

    for policy in policies {
        for udp_port in [500u16, 4500u16] {
            let mut net = MccNetwork::new(
                &["A", "B", "X1", "X2", "X3", "X4"],
                MccFanout {
                    x1: 3,
                    x2: 3,
                    ike: 1,
                },
                policy.clone(),
            );
            let spi = [1, 2, 3, 4, 5, 6, 7, 8];
            let init = build_ikev2(udp_port, IKE_SA_INIT, 0, false, spi, b"init-payload");
            let start_actions = net
                .nodes
                .get_mut("A")
                .unwrap()
                .send_local_ike("B", &init, udp_port, net.now_ms)
                .unwrap();
            net.enqueue_actions("A", start_actions, true);
            net.pump(true);
            net.advance_ms(500, true);

            assert_eq!(
                net.offers_seen, 9,
                "expected 9 offers for {:?}",
                policy.mode
            );
            let delivered_nodes: Vec<&str> =
                net.injections.iter().map(|(n, _, _)| n.as_str()).collect();
            assert_eq!(delivered_nodes, vec!["B", "A"]);

            // Initiator A MUST NOT know X2 and MUST hold an opaque continuation token.
            assert_eq!(net.injections[1].2, "");
            let (x1, token, _ctx) = net.nodes["A"]
                .initiator_route_summary("B", spi)
                .expect("route must be published on A");
            assert!(!x1.is_empty());
            assert_eq!(token.len(), 64);

            // Continuation: IKE_AUTH over MCC_OPAQUE_FWD -> B -> PRIV_BACK -> A
            let auth = build_ikev2(udp_port, IKE_AUTH, 1, false, spi, b"auth-payload");
            let auth_actions = net
                .nodes
                .get_mut("A")
                .unwrap()
                .send_local_ike("B", &auth, udp_port, net.now_ms)
                .unwrap();
            net.enqueue_actions("A", auth_actions, true);
            net.pump(true);

            let delivered_all: Vec<&str> =
                net.injections.iter().map(|(n, _, _)| n.as_str()).collect();
            assert_eq!(delivered_all, vec!["B", "A", "B", "A"]);
            assert_eq!(net.injections[2].1, auth);
        }
    }
}

#[test]
fn forged_wrapper_substitutions_first_and_last_rejected_in_all_modes() {
    let policies = [
        SelectionPolicy::first(12_000),
        SelectionPolicy::window(200, 12_000),
        SelectionPolicy::adaptive(3, 100, 12_000),
        SelectionPolicy::wait_all(12_000),
    ];

    for policy in policies {
        for bad_count in [1usize, 3usize] {
            for bad_first in [true, false] {
                let mut net = MccNetwork::new(
                    &["A", "B", "X1", "X2", "X3", "X4"],
                    MccFanout {
                        x1: 3,
                        x2: 3,
                        ike: 1,
                    },
                    policy.clone(),
                );
                let spi = [9, 8, 7, 6, 5, 4, 3, 2];
                let init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"authentic");
                let forged_ike = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"tampered-copy");

                let actions = net
                    .nodes
                    .get_mut("A")
                    .unwrap()
                    .send_local_ike("B", &init, 500, net.now_ms)
                    .unwrap();
                net.enqueue_actions("A", actions, true);

                let mut seen_idx = 0usize;
                net.pump_with(true, |_src, _dst, mtype, payload| {
                    if mtype != MessageType::MccOffer {
                        return Some(payload);
                    }
                    let idx = seen_idx;
                    seen_idx += 1;
                    let is_bad = if bad_first {
                        idx < bad_count
                    } else {
                        idx >= 9 - bad_count
                    };
                    if is_bad {
                        let mut val = jload(&payload).unwrap();
                        val["ike_payload"] = serde_json::Value::String(hex::encode(&forged_ike));
                        Some(jdump(&val).unwrap())
                    } else {
                        Some(payload)
                    }
                });
                net.advance_ms(13_000, true);

                let delivered_nodes: Vec<&str> =
                    net.injections.iter().map(|(n, _, _)| n.as_str()).collect();
                assert_eq!(delivered_nodes, vec!["B", "A"]);
                assert_eq!(net.injections[0].1, init);
                assert!(
                    net.rejections
                        .iter()
                        .any(|(_, c)| *c == "contradictory_wrapper")
                );
            }
        }
    }
}

#[test]
fn all_nine_bad_offers_allocate_no_endpoint_state_or_ledger_rows() {
    let mut net = MccNetwork::new(
        &["A", "B", "X1", "X2", "X3", "X4"],
        MccFanout {
            x1: 3,
            x2: 3,
            ike: 1,
        },
        SelectionPolicy::wait_all(5_000),
    );
    let spi = [0xaa; 8];
    let init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"legit");
    let actions = net
        .nodes
        .get_mut("A")
        .unwrap()
        .send_local_ike("B", &init, 500, net.now_ms)
        .unwrap();
    net.enqueue_actions("A", actions, false);
    net.pump_with(false, |_src, _dst, mtype, payload| {
        if mtype == MessageType::MccOffer {
            let mut val = jload(&payload).unwrap();
            val["a_to_b_ke"] = serde_json::Value::String("00".repeat(32));
            return Some(jdump(&val).unwrap());
        }
        Some(payload)
    });
    net.advance_ms(6_000, false);

    assert!(net.injections.is_empty());
    assert_eq!(net.nodes["B"].pending_selection_count(), 0);
    assert_eq!(net.nodes["B"].responder_session_count(), 0);
    assert_eq!(net.nodes["B"].security().ledger_counts().unwrap(), (0, 0));
}

#[test]
fn twenty_seven_copies_and_restart_durable_anti_replay() {
    let fanout = MccFanout {
        x1: 3,
        x2: 3,
        ike: 3,
    };
    let policy = SelectionPolicy::wait_all(5_000);
    let mut net = MccNetwork::new(&["A", "B", "X1", "X2", "X3", "X4"], fanout, policy.clone());
    let spi = [0x42; 8];
    let init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"27-copies");

    let actions = net
        .nodes
        .get_mut("A")
        .unwrap()
        .send_local_ike("B", &init, 500, net.now_ms)
        .unwrap();
    net.enqueue_actions("A", actions, false);

    let mut captured_offer: Option<(String, Vec<u8>)> = None;
    net.pump_with(false, |src, _dst, mtype, payload| {
        if mtype == MessageType::MccOffer && captured_offer.is_none() {
            captured_offer = Some((src.to_owned(), payload.clone()));
        }
        Some(payload)
    });

    assert_eq!(net.offers_seen, 27);
    assert_eq!(net.injections.len(), 1);
    assert_eq!(net.injections[0].0, "B");
    assert_eq!(net.nodes["B"].security().ledger_counts().unwrap(), (1, 27));

    // Restart B from the same durable SQLite ledger and replay a previously valid offer
    net.restart_node("B", fanout, policy);
    let (replay_peer, replay_offer) = captured_offer.unwrap();
    let replay_actions = net.nodes.get_mut("B").unwrap().on_inbound(
        &replay_peer,
        MessageType::MccOffer,
        &replay_offer,
        net.now_ms,
    );
    net.enqueue_actions("B", replay_actions, false);

    // Must NOT inject a second time!
    assert_eq!(net.injections.len(), 1);
    assert_eq!(net.nodes["B"].responder_session_count(), 0);
}

#[test]
fn rejected_injection_fails_over_while_unknown_forbids_retry() {
    let fanout = MccFanout {
        x1: 2,
        x2: 2,
        ike: 1,
    };
    let policy = SelectionPolicy::wait_all(5_000);
    let mut net = MccNetwork::new(&["A", "B", "X1", "X2", "X3"], fanout, policy);
    let spi = [0x11; 8];
    let init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"failover-test");

    let start = net
        .nodes
        .get_mut("A")
        .unwrap()
        .send_local_ike("B", &init, 500, net.now_ms)
        .unwrap();
    net.enqueue_actions("A", start, false);

    // Pump manually until B emits DeliverIke
    let mut first_proof = None;
    while let Some((src, dst, mtype, payload)) = net.queue.pop_front() {
        let actions = net
            .nodes
            .get_mut(&dst)
            .unwrap()
            .on_inbound(&src, mtype, &payload, net.now_ms);
        for act in actions {
            match act {
                MccAction::Send {
                    peer,
                    message_type,
                    payload,
                } => net
                    .queue
                    .push_back((dst.clone(), peer, message_type, payload)),
                MccAction::DeliverIke { proof } => first_proof = Some(proof),
                MccAction::Reject { .. } => {}
            }
        }
    }
    let proof1 = first_proof.expect("B must emit first delivery proof");
    let (_, _, receipt1) = proof1.consume();

    // 1) Confirmed pre-send Rejected -> releases reservation and selects candidate #2
    let retry_actions = net.nodes.get_mut("B").unwrap().complete_delivery(
        receipt1,
        IkeInjectionOutcome::Rejected,
        net.now_ms,
    );
    assert_eq!(retry_actions.len(), 1);
    let MccAction::DeliverIke { proof: proof2 } = retry_actions.into_iter().next().unwrap() else {
        panic!("expected failover DeliverIke");
    };
    let (_, _, receipt2) = proof2.consume();

    // 2) Unknown outcome -> keeps durable claim and MUST NOT emit another candidate!
    let unknown_actions = net.nodes.get_mut("B").unwrap().complete_delivery(
        receipt2,
        IkeInjectionOutcome::Unknown,
        net.now_ms,
    );
    assert!(matches!(
        unknown_actions.as_slice(),
        [MccAction::Reject {
            code: "injection_outcome_unknown"
        }]
    ));
}

#[test]
fn legacy_sibling_messages_and_forged_reverse_bke_rejected() {
    let mut net = MccNetwork::new(
        &["A", "B", "X1", "X2"],
        MccFanout {
            x1: 2,
            x2: 2,
            ike: 1,
        },
        SelectionPolicy::first(5_000),
    );
    for (mtype, expected_code) in [
        (MessageType::ProxyBlob, "legacy_proxy_disabled"),
        (MessageType::PrivDeliver, "legacy_deliver_disabled"),
        (MessageType::MccAccept, "legacy_accept_disabled"),
        (MessageType::I1, "legacy_route_setup_disabled"),
        (MessageType::Error, "unauthenticated_error_ignored"),
    ] {
        let res = net
            .nodes
            .get_mut("B")
            .unwrap()
            .on_inbound("X2", mtype, b"{}", net.now_ms);
        assert!(matches!(res.as_slice(), [MccAction::Reject { code }] if *code == expected_code));
    }

    // Tamper reverse bke on x1-a leg -> rejected, initiator publishes NO route
    let spi = [0x77; 8];
    let init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"rev-check");
    let start = net
        .nodes
        .get_mut("A")
        .unwrap()
        .send_local_ike("B", &init, 500, net.now_ms)
        .unwrap();
    net.enqueue_actions("A", start, true);
    let attacker_pub = X25519SecretKey::generate().public_key().to_hex();
    net.pump_with(true, |_src, _dst, mtype, payload| {
        if mtype == MessageType::PrivBack {
            let mut val = jload(&payload).unwrap();
            if val.get("leg").and_then(|v| v.as_str()) == Some("x1-a") {
                val["sealed_a"]["bke"] = serde_json::Value::String(attacker_pub.clone());
                return Some(jdump(&val).unwrap());
            }
        }
        Some(payload)
    });
    assert!(net.nodes["A"].initiator_route_summary("B", spi).is_none());
    assert!(
        net.rejections
            .iter()
            .any(|(n, c)| n == "A" && *c == "capsule_authentication_failed")
    );
}

#[test]
fn endpoint_security_ledger_invariants_and_relays_cannot_open_endpoint_capsule() {
    let dir = TempDir::new().unwrap();
    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("r".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    let mut esk = BTreeMap::new();
    let mut xsk = BTreeMap::new();
    let mut recs = BTreeMap::new();
    for name in ["A", "B", "X2"] {
        let e = Ed25519SecretKey::generate();
        let x = X25519SecretKey::generate();
        recs.insert(
            name.to_owned(),
            NodeKeyRecord {
                encryption: x.public_key(),
                verification: e.public_key(),
                key_id: e.public_key().key_id(),
                revoked: false,
            },
        );
        esk.insert(name, e);
        xsk.insert(name, x);
    }
    let reg = verify_registry_bytes(
        &sign_registry_v2(1, &recs, "r", &root_sk).unwrap(),
        &root_path,
        ["A", "B", "X2"],
        VerifyConstraints::default(),
    )
    .unwrap();
    let now = 1_800_000_000i64;

    // :memory: SQLite ledger must be rejected (persistent_state_required)
    let err = EndpointSecurity::new(
        "A",
        reg.clone(),
        Ed25519SecretKey::from_bytes(*esk["A"].to_bytes_zeroizing()),
        X25519SecretKey::from_bytes(*xsk["A"].to_bytes_zeroizing()),
        ":memory:",
        now,
    )
    .err()
    .expect(":memory: ledger must fail");
    assert_eq!(err.code(), "persistent_state_required");

    let mut a = EndpointSecurity::new(
        "A",
        reg.clone(),
        Ed25519SecretKey::from_bytes(*esk["A"].to_bytes_zeroizing()),
        X25519SecretKey::from_bytes(*xsk["A"].to_bytes_zeroizing()),
        dir.path().join("A.sqlite"),
        now,
    )
    .unwrap();
    let mut b = EndpointSecurity::new(
        "B",
        reg.clone(),
        Ed25519SecretKey::from_bytes(*esk["B"].to_bytes_zeroizing()),
        X25519SecretKey::from_bytes(*xsk["B"].to_bytes_zeroizing()),
        dir.path().join("B.sqlite"),
        now,
    )
    .unwrap();
    let x2 = EndpointSecurity::new(
        "X2",
        reg.clone(),
        Ed25519SecretKey::from_bytes(*esk["X2"].to_bytes_zeroizing()),
        X25519SecretKey::from_bytes(*xsk["X2"].to_bytes_zeroizing()),
        dir.path().join("X2.sqlite"),
        now,
    )
    .unwrap();

    let mut body = BTreeMap::new();
    body.insert(
        "ike_payload".to_owned(),
        CanonicalValue::String("aabb".to_owned()),
    );
    body.insert(
        "transport_conn".to_owned(),
        CanonicalValue::String("path-0".to_owned()),
    );

    let rec0 = a
        .signed_message(
            "B",
            "ex-1",
            body.clone(),
            0,
            64,
            "forward",
            "initial",
            "0",
            now,
        )
        .unwrap();
    let cap = a
        .seal_to("B", &rec0, "ex-1", MccCapsulePurpose::Endpoint)
        .unwrap();

    // Relay X2 cannot open B's capsule
    assert_eq!(
        x2.open_for_me(&cap, "ex-1", MccCapsulePurpose::Endpoint)
            .unwrap_err()
            .code(),
        "capsule_authentication_failed"
    );
    // Wrong purpose on B fails closed
    assert_eq!(
        b.open_for_me(&cap, "ex-1", MccCapsulePurpose::Hop)
            .unwrap_err()
            .code(),
        "capsule_authentication_failed"
    );

    // 64 copies share identical fingerprint and freshness metadata across distinct transport_conn
    let mut fingerprints = std::collections::BTreeSet::new();
    let mut nonces = std::collections::BTreeSet::new();
    for copy_id in 0..64 {
        let mut b_copy = body.clone();
        b_copy.insert(
            "transport_conn".to_owned(),
            CanonicalValue::String(format!("path-{copy_id}")),
        );
        let rec = a
            .signed_message(
                "B", "ex-1", b_copy, copy_id, 64, "forward", "initial", "0", now,
            )
            .unwrap();
        let v = b
            .verify_signed(&rec, "ex-1", Some("A"), "forward", "initial", now)
            .unwrap();
        fingerprints.insert(v.fingerprint.clone());
        nonces.insert((v.nonce.clone(), v.issued, v.expires));
        assert_eq!(b.admit(&v, now).unwrap(), AdmitStatus::New);
        assert_eq!(b.admit(&v, now).unwrap(), AdmitStatus::Duplicate);
    }
    assert_eq!(fingerprints.len(), 1);
    assert_eq!(nonces.len(), 1);
    assert_eq!(b.ledger_counts().unwrap(), (1, 64));

    // Conflicting semantic body under same exchange fails closed
    let mut bad_body = body;
    bad_body.insert(
        "ike_payload".to_owned(),
        CanonicalValue::String("ccdd".to_owned()),
    );
    assert_eq!(
        a.signed_message("B", "ex-1", bad_body, 0, 64, "forward", "initial", "0", now)
            .unwrap_err()
            .code(),
        "conflicting_message"
    );
}

#[test]
fn selection_policy_validation_rejects_window_zero() {
    let bad = SelectionPolicy {
        mode: SelectionMode::Window,
        window_ms: 0,
        deadline_ms: 5000,
        min_copies: 3,
        quiet_ms: 150,
    };
    assert_eq!(
        bad.validate().unwrap_err().code(),
        "unsupported_selection_mode"
    );
}
