#![forbid(unsafe_code)]
//! Comprehensive test suite for WireGuard Handshake Overlay (`wg_handshake_overlay`).

use std::collections::BTreeMap;
use std::fs;

use cco_cascade::wireguard::{
    WgCaptureAction, WgEndpoint, WgEventKind, WgHandshakeOverlayEngine, WgOverlayEnvelope,
    WgProxyAdapter, WgRouteCache, format_scenarios_csv, run_canonical_27_eve_results,
    run_canonical_27_scenarios, synthetic_wg_packet,
};
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_proto::WireGuardMessageType;
use cco_trust::{
    NodeKeyRecord, VerifyConstraints, build_trust_root_bytes, sign_registry_v2,
    verify_registry_bytes,
};
use tempfile::TempDir;

#[test]
fn canonical_27_scenarios_all_pass_with_zero_direct_control_and_type4_direct_bypass() {
    let rows = run_canonical_27_scenarios();
    assert_eq!(rows.len(), 27);

    let count_suite = |name: &str| rows.iter().filter(|r| r.scenario == name).count();
    assert_eq!(count_suite("bidir12"), 2);
    assert_eq!(count_suite("disjoint5"), 5);
    assert_eq!(count_suite("ring10"), 10);
    assert_eq!(count_suite("reverse5"), 10);

    for row in &rows {
        assert!(
            row.model_ok,
            "failed scenario {}: {}",
            row.conn_id, row.error
        );
        assert_eq!(row.direct_wg_control_packets, 0);
        assert_eq!(row.overlay_control_packets, 2);
        assert_eq!(row.direct_transport_packets, 1);
        assert_eq!(row.injected_control_packets, 2);
    }

    let csv = format_scenarios_csv(&rows);
    assert_eq!(csv.lines().count(), 28); // header + 27 rows

    // Verify JSON output conforms to `schemas/eve-result.schema.json` contract
    let eve_results = run_canonical_27_eve_results();
    assert_eq!(eve_results.len(), 27);
    for item in &eve_results {
        assert_eq!(item.schema_version, 1);
        assert!(item.ok);
        assert_eq!(item.status, "pass");
        assert_eq!(item.wg_up_code, 0);
        assert_eq!(item.direct_wg_control_packets, 0);
        assert!(item.wg_data_packets >= 2);
        assert!(item.criteria.handshake_fresh);
        assert!(item.criteria.useful_traffic_ok);
        assert!(item.criteria.control_types_overlay_only);
        assert!(item.criteria.transport_type4_direct_only);
        assert!(item.criteria.reverse_route_ok);
        assert!(item.criteria.redaction_confirmed);
        assert!(!item.evidence.events.is_empty());
    }
}

#[test]
fn engine_rejects_type4_inside_overlay_duplicates_expired_and_preserves_relay_privacy() {
    let cache = WgRouteCache::new(60.0).unwrap();
    let x1 = WgEndpoint::new("X1", 51820).unwrap();
    let x2 = WgEndpoint::new("X2", 51820).unwrap();
    let a = WgEndpoint::new("User1", 51820).unwrap();
    let b = WgEndpoint::new("User2", 51820).unwrap();
    let mut engine = WgHandshakeOverlayEngine::new(cache, vec![x1, x2], true).unwrap();

    // Type 4 capture must bypass directly
    let data = synthetic_wg_packet(WireGuardMessageType::TransportData, 77);
    let ev = engine.capture(&a, &b, &data, 10.0);
    assert_eq!(ev[0].kind, WgEventKind::DirectBypass);

    // Type 1 initiation goes into overlay
    let init = synthetic_wg_packet(WireGuardMessageType::HandshakeInitiation, 1);
    let ev1 = engine.capture(&a, &b, &init, 10.0);
    assert_eq!(ev1[0].kind, WgEventKind::OverlayFrame);
    assert!(ev1[0].route.is_empty()); // privacy mode hides full route

    // Duplicate at same hop dropped
    let route = engine.cache.get(&a, &b, 10.0).unwrap();
    let msg_id = WgHandshakeOverlayEngine::fingerprint(&init, &a, &b);
    let env0 = WgOverlayEnvelope::new(msg_id.clone(), route.clone(), 0, init.clone()).unwrap();
    assert_eq!(
        engine.forward(&env0, 10.0)[0].kind,
        WgEventKind::DuplicateDrop
    );

    // Relay view hides final endpoint in privacy mode
    let env1 = WgOverlayEnvelope::new(msg_id.clone(), route.clone(), 1, init.clone()).unwrap();
    let view = engine.relay_view(&env1);
    assert_eq!(view.previous_hop.as_ref(), Some(&a));
    assert_eq!(view.final_endpoint, None);

    // Expired route dropped
    assert_eq!(
        engine.forward(&env1, 100.0)[0].kind,
        WgEventKind::ExpiredDrop
    );

    // Smuggling Type 4 inside an OverlayEnvelope MUST be dropped!
    let smuggled = WgOverlayEnvelope::new(msg_id, route, 1, data).unwrap();
    assert_eq!(
        engine.forward(&smuggled, 10.0)[0].kind,
        WgEventKind::InvalidDrop
    );
}

#[test]
fn proxy_adapter_enforces_trust_registry_v2_and_blocks_type4_delivery() {
    let dir = TempDir::new().unwrap();
    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("wg-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    let mut nodes = BTreeMap::new();
    for name in ["User1", "User2"] {
        let esk = Ed25519SecretKey::generate();
        let xsk = X25519SecretKey::generate();
        nodes.insert(
            name.to_owned(),
            NodeKeyRecord {
                encryption: xsk.public_key(),
                verification: esk.public_key(),
                key_id: esk.public_key().key_id(),
                revoked: false,
            },
        );
    }
    let reg_v1 = verify_registry_bytes(
        &sign_registry_v2(1, &nodes, "wg-root", &root_sk).unwrap(),
        &root_path,
        ["User1", "User2"],
        VerifyConstraints::default(),
    )
    .unwrap();
    let adapter = WgProxyAdapter::new(&reg_v1);

    let src = WgEndpoint::new("192.0.2.1", 51820).unwrap();
    let dst = WgEndpoint::new("192.0.2.2", 51820).unwrap();

    // Control type 1 admitted with trust-bound metadata
    let init = synthetic_wg_packet(WireGuardMessageType::HandshakeInitiation, 11);
    let cap = adapter.capture_datagram(&init, &src, &dst, "User1", "User2", "cap-1");
    assert_eq!(cap.action, WgCaptureAction::Overlay);
    let meta = cap.meta.unwrap();
    let req = adapter
        .deliver_protocol_datagram("wireguard", &init, &meta)
        .unwrap();
    assert_eq!(req.registry_version, 1);

    // Unknown node fails closed
    let bad_node = adapter.capture_datagram(&init, &src, &dst, "User1", "Ghost", "cap-2");
    assert_eq!(bad_node.action, WgCaptureAction::Drop);

    // Type 4 capture returns DirectBypass and deliver_protocol_datagram rejects it
    let data = synthetic_wg_packet(WireGuardMessageType::TransportData, 12);
    let cap_data = adapter.capture_datagram(&data, &src, &dst, "User1", "User2", "cap-3");
    assert_eq!(cap_data.action, WgCaptureAction::DirectBypass);
    assert_eq!(
        adapter
            .deliver_protocol_datagram("wireguard", &data, &meta)
            .unwrap_err()
            .code(),
        "transport_type4_forbidden"
    );

    // Stale registry version rejected on delivery
    let reg_v2 = verify_registry_bytes(
        &sign_registry_v2(2, &nodes, "wg-root", &root_sk).unwrap(),
        &root_path,
        ["User1", "User2"],
        VerifyConstraints::default(),
    )
    .unwrap();
    let adapter_v2 = WgProxyAdapter::new(&reg_v2);
    assert_eq!(
        adapter_v2
            .deliver_protocol_datagram("wireguard", &init, &meta)
            .unwrap_err()
            .code(),
        "stale_registry_version"
    );
}
