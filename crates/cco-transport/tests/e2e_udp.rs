#![forbid(unsafe_code)]
//! Level 2 (L2) Verification: Real localhost multi-node UDP E2E tests (4-node and 10-node)
//! plus live Rust <-> Python UDP wire cross-compatibility test (4-step MGMT + LINK_FRAG + AEAD).

use std::collections::BTreeMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cco_cascade::mcc::{
    DeliveredIkeMeta, DeliveryReceipt, EndpointSecurity, IkeInjectionOutcome, LocalDeliveryProof,
    MccFanout, SelectionPolicy,
};
use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_proto::{
    IKE_AUTH, IKE_SA_INIT, IKEV2_FLAG_INITIATOR, IKEV2_FLAG_RESPONSE, MessageType,
    parse_ikev2_packet,
};
use cco_transport::{IkeSink, NodeTransportConfig, OverlayNode, OverlayNodeHandle, PeerEndpoint};
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

struct RecordingAutoReplySink {
    node_name: String,
    delivered: DeliveredLog,
    notify: Arc<Notify>,
    handle_slot: Arc<StdMutex<Option<OverlayNodeHandle>>>,
    auto_reply: bool,
}

impl IkeSink for RecordingAutoReplySink {
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
                        b"live-udp-ike-resp",
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

struct LiveCluster {
    _dir: TempDir,
    handles: BTreeMap<String, OverlayNodeHandle>,
    delivered: DeliveredLog,
    notify: Arc<Notify>,
}

impl LiveCluster {
    async fn start(
        names: &[&str],
        fanout: MccFanout,
        policy: SelectionPolicy,
        preconnect: bool,
    ) -> Self {
        let dir = TempDir::new().unwrap();
        let root_sk = Ed25519SecretKey::generate();
        let mut signers = BTreeMap::new();
        signers.insert("e2e-root".to_owned(), root_sk.public_key());
        let root_path = dir.path().join("root.json");
        fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

        let ports = pick_free_udp_ports(names.len());
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
            let overlay_addr = SocketAddr::from(([127, 0, 0, 1], ports[i]));
            peers.insert(
                name.to_owned(),
                PeerEndpoint {
                    name: name.to_owned(),
                    overlay_addr,
                    // RFC 5737 TEST-NET-2 underlay identities
                    underlay_ip: Ipv4Addr::new(198, 51, 100, (i + 1) as u8),
                },
            );
        }

        let reg_bytes = sign_registry_v2(1, &records, "e2e-root", &root_sk).unwrap();
        let verified_reg = verify_registry_bytes(
            &reg_bytes,
            &root_path,
            names.iter().copied(),
            VerifyConstraints::default(),
        )
        .unwrap();

        let now_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let delivered = Arc::new(StdMutex::new(Vec::new()));
        let notify = Arc::new(Notify::new());
        let mut handles = BTreeMap::new();

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
            let mut cfg = NodeTransportConfig::new(name, peers[name].overlay_addr, peers.clone());
            cfg.fanout = fanout;
            cfg.policy = policy.clone();
            cfg.preconnect = preconnect;
            cfg.deterministic_seed = Some(500 + i as u64);

            let handle_slot = Arc::new(StdMutex::new(None));
            let sink = Arc::new(RecordingAutoReplySink {
                node_name: name.to_owned(),
                delivered: Arc::clone(&delivered),
                notify: Arc::clone(&notify),
                handle_slot: Arc::clone(&handle_slot),
                auto_reply: true,
            });
            let handle = OverlayNode::start(cfg, sec, sink).await.unwrap();
            *handle_slot.lock().unwrap() = Some(handle.clone());
            handles.insert(name.to_owned(), handle);
        }

        Self {
            _dir: dir,
            handles,
            delivered,
            notify,
        }
    }

    async fn wait_for_deliveries(&self, expected: usize, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.delivered.lock().unwrap().len() >= expected {
                return;
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for {expected} deliveries (got {})",
                self.delivered.lock().unwrap().len()
            );
            let _ = tokio::time::timeout(
                remaining.min(Duration::from_millis(50)),
                self.notify.notified(),
            )
            .await;
        }
    }

    async fn shutdown(self) {
        for handle in self.handles.values() {
            handle.shutdown().await;
        }
    }
}

#[tokio::test]
async fn localhost_4_node_udp_mcc_full_ike_sa_init_and_ike_auth_with_lazy_sessions() {
    // preconnect=false exercises the non-blocking session worker (NO_SESSION_NEXT fix)!
    let cluster = LiveCluster::start(
        &["A", "X1", "X2", "B"],
        MccFanout {
            x1: 2,
            x2: 2,
            ike: 1,
        },
        SelectionPolicy::first(12_000),
        false,
    )
    .await;

    let spi = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    let ike_init = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"e2e-4node-init");
    cluster.handles["A"]
        .send_local_ike("B", ike_init.clone(), 500)
        .await
        .unwrap();

    // Expect B to receive IKE_SA_INIT and A to receive B's response over live UDP sockets
    cluster
        .wait_for_deliveries(2, Duration::from_secs(10))
        .await;

    // Verify initiator A published opaque route without learning X2
    let (x1, token, _ctx) = cluster.handles["A"]
        .initiator_route_summary("B", spi)
        .await
        .expect("initiator A must have opaque route after IKE_SA_INIT response");
    assert!(!x1.is_empty());
    assert_eq!(token.len(), 64);

    // Send IKE_AUTH continuation over MCC_OPAQUE_FWD -> B -> PRIV_BACK -> A
    let ike_auth = build_ikev2(500, IKE_AUTH, 1, false, spi, b"e2e-4node-auth");
    cluster.handles["A"]
        .send_local_ike("B", ike_auth.clone(), 500)
        .await
        .unwrap();

    cluster
        .wait_for_deliveries(4, Duration::from_secs(10))
        .await;

    let log = cluster.delivered.lock().unwrap().clone();
    let seq: Vec<(&str, &str)> = log
        .iter()
        .map(|(n, m, _)| (n.as_str(), m.direction.as_str()))
        .collect();
    assert_eq!(
        seq,
        vec![("B", "fwd"), ("A", "back"), ("B", "fwd"), ("A", "back")]
    );
    assert_eq!(log[0].2, ike_init);
    assert_eq!(log[2].2, ike_auth);
    assert_eq!(log[1].1.x2, ""); // X2 remains hidden from initiator A

    cluster.shutdown().await;
}

#[tokio::test]
async fn localhost_10_node_udp_mesh_five_concurrent_ike_routes_100_percent() {
    let names = [
        "User1", "User2", "User3", "User4", "User5", "User6", "User7", "User8", "User9", "User10",
    ];
    let cluster = LiveCluster::start(
        &names,
        MccFanout {
            x1: 3,
            x2: 3,
            ike: 1,
        },
        SelectionPolicy::adaptive(3, 80, 12_000),
        true,
    )
    .await;

    // Allow proactive MGMT preconnect to finish briefly
    tokio::time::sleep(Duration::from_millis(250)).await;

    let pairs = [
        ("User1", "User2", [1u8; 8]),
        ("User3", "User4", [2u8; 8]),
        ("User5", "User6", [3u8; 8]),
        ("User7", "User8", [4u8; 8]),
        ("User9", "User10", [5u8; 8]),
    ];

    for (src, dst, spi) in pairs {
        let init = build_ikev2(4500, IKE_SA_INIT, 0, false, spi, b"ten-node-init");
        cluster.handles[src]
            .send_local_ike(dst, init, 4500)
            .await
            .unwrap();
    }

    // 5 routes * 2 (init -> B, resp -> A) = 10 deliveries
    cluster
        .wait_for_deliveries(10, Duration::from_secs(15))
        .await;

    // Now send IKE_AUTH on all 5 concurrent routes!
    for (src, dst, spi) in pairs {
        assert!(
            cluster.handles[src]
                .initiator_route_summary(dst, spi)
                .await
                .is_some(),
            "route for {src}->{dst} must be ready"
        );
        let auth = build_ikev2(4500, IKE_AUTH, 1, false, spi, b"ten-node-auth");
        cluster.handles[src]
            .send_local_ike(dst, auth, 4500)
            .await
            .unwrap();
    }

    // Total 20 deliveries (5 routes * 4 IKEv2 packets) = 100% success!
    cluster
        .wait_for_deliveries(20, Duration::from_secs(15))
        .await;

    cluster.shutdown().await;
}

#[tokio::test]
async fn rust_python_udp_wire_cross_compatibility_mgmt_and_link_frag() {
    // Check whether Python 3 with `cryptography` is installed on the host.
    let python_exe = if Command::new("python")
        .args(["-c", "import cryptography"])
        .status()
        .is_ok_and(|s| s.success())
    {
        "python"
    } else if Command::new("python3")
        .args(["-c", "import cryptography"])
        .status()
        .is_ok_and(|s| s.success())
    {
        "python3"
    } else {
        // Host has no Python cryptography (e.g. minimal Rust container); skip gracefully.
        return;
    };

    let ports = pick_free_udp_ports(2);
    let rust_port = ports[0];
    let py_port = ports[1];

    // Minimal wire-exact Python peer implementing `node_daemon.py` 4-step MGMT + `link_transport.py` LINK_FRAG.
    let py_script = format!(
        r#"
import base64, json, secrets, socket, sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

def jdump(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

def hkdf_sha256(ikm, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", {py_port}))
sock.settimeout(8.0)

# Signal ready to parent
sys.stdout.write("READY\n")
sys.stdout.flush()

pending = {{}}
session = None
frags = {{}}

while True:
    data, addr = sock.recvfrom(65535)
    msg = json.loads(data.decode("utf-8"))
    t = msg.get("t")
    if t == "LINK_FRAG":
        fid = msg["frag_id"]
        buf = frags.setdefault(fid, {{}})
        buf[int(msg["seq"])] = base64.b64decode(msg["data"])
        if len(buf) < int(msg["total"]):
            continue
        assembled = b"".join(buf[i] for i in range(int(msg["total"])))
        msg = json.loads(assembled.decode("utf-8"))
        t = msg.get("t")

    if t == "MGMT_INIT":
        sid = msg["sid"]
        ni = bytes.fromhex(msg["ni"])
        i_pub = bytes.fromhex(msg["ke"])
        r_priv = x25519.X25519PrivateKey.generate()
        r_pub = r_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        nr = secrets.token_bytes(16)
        pending[sid] = (r_priv, ni, nr, i_pub, f"{{msg['from']}}-PY")
        sock.sendto(jdump({{
            "t": "MGMT_INIT_RESP", "sid": sid, "from": "PY", "to": msg["from"],
            "nr": nr.hex(), "ke": r_pub.hex()
        }}), addr)
    elif t == "MGMT_AUTH":
        sid = msg["sid"]
        r_priv, ni, nr, i_pub, label = pending.pop(sid)
        shared = r_priv.exchange(x25519.X25519PublicKey.from_public_bytes(i_pub))
        kd = hkdf_sha256(shared, ni + nr, b"mgmt|ikev2-like|" + label.encode("utf-8"))
        aad = f"AUTH:{{label}}:{{msg['from']}}->PY:{{sid}}".encode("utf-8")
        AESGCM(kd).decrypt(bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["ct"]), aad)
        aad2 = f"AUTH:{{label}}:PY->{{msg['from']}}:{{sid}}".encode("utf-8")
        n2 = secrets.token_bytes(12)
        c2 = AESGCM(kd).encrypt(n2, b"ID=PY|AUTH=" + secrets.token_bytes(16), aad2)
        sock.sendto(jdump({{
            "t": "MGMT_AUTH_RESP", "sid": sid, "from": "PY", "to": msg["from"],
            "nonce": n2.hex(), "ct": c2.hex()
        }}), addr)
        session = (sid, kd)
    elif t == "MCC_START":
        assert session is not None
        sid, kd = session
        aad = f"MCC_START:{{msg['from']}}->PY:{{sid}}".encode("utf-8")
        pt = AESGCM(kd).decrypt(bytes.fromhex(msg["nonce"]), bytes.fromhex(msg["ct"]), aad)
        parsed = json.loads(pt.decode("utf-8"))
        assert parsed["marker"] == "rust-to-python-frag-ok"
        assert len(parsed["pad"]) == 2000
        sys.stdout.write("VERIFIED_OK\n")
        sys.stdout.flush()
        break
"#
    );

    let child = Command::new(python_exe)
        .args(["-u", "-B", "-c", &py_script])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait briefly for Python UDP socket to bind
    tokio::time::sleep(Duration::from_millis(350)).await;

    // Spin up a real Rust OverlayNode ("RS") talking to "PY"
    let dir = TempDir::new().unwrap();
    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("xcompat-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    let rs_esk = Ed25519SecretKey::generate();
    let rs_xsk = X25519SecretKey::generate();
    let py_esk = Ed25519SecretKey::generate();
    let py_xsk = X25519SecretKey::generate();

    let mut recs = BTreeMap::new();
    recs.insert(
        "RS".to_owned(),
        NodeKeyRecord {
            encryption: rs_xsk.public_key(),
            verification: rs_esk.public_key(),
            key_id: rs_esk.public_key().key_id(),
            revoked: false,
        },
    );
    recs.insert(
        "PY".to_owned(),
        NodeKeyRecord {
            encryption: py_xsk.public_key(),
            verification: py_esk.public_key(),
            key_id: py_esk.public_key().key_id(),
            revoked: false,
        },
    );
    let reg = verify_registry_bytes(
        &sign_registry_v2(1, &recs, "xcompat-root", &root_sk).unwrap(),
        &root_path,
        ["RS", "PY"],
        VerifyConstraints::default(),
    )
    .unwrap();

    let mut peers = BTreeMap::new();
    peers.insert(
        "RS".to_owned(),
        PeerEndpoint {
            name: "RS".to_owned(),
            overlay_addr: SocketAddr::from(([127, 0, 0, 1], rust_port)),
            underlay_ip: Ipv4Addr::new(203, 0, 113, 1),
        },
    );
    peers.insert(
        "PY".to_owned(),
        PeerEndpoint {
            name: "PY".to_owned(),
            overlay_addr: SocketAddr::from(([127, 0, 0, 1], py_port)),
            underlay_ip: Ipv4Addr::new(203, 0, 113, 2),
        },
    );
    let now_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let sec = EndpointSecurity::new(
        "RS",
        reg,
        rs_esk,
        rs_xsk,
        dir.path().join("RS.sqlite"),
        now_s,
    )
    .unwrap();
    let mut cfg = NodeTransportConfig::new("RS", peers["RS"].overlay_addr, peers);
    cfg.preconnect = false;

    let handle = OverlayNode::start(cfg, sec, Arc::new(cco_transport::RelayOnlySink))
        .await
        .unwrap();

    // 1. Live 4-step MGMT handshake Rust -> Python over UDP!
    handle.ensure_session("PY").await.unwrap();
    assert!(handle.has_session("PY").await);

    // 2. Send a >1200 B encrypted hop message forcing LINK_FRAG fragmentation Rust -> Python!
    let big_payload = serde_json::to_vec(&serde_json::json!({
        "marker": "rust-to-python-frag-ok",
        "pad": "z".repeat(2000),
    }))
    .unwrap();
    handle
        .send_secure_message("PY", MessageType::MccStart, big_payload)
        .await
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    handle.shutdown().await;

    assert!(
        output.status.success() && stdout.contains("VERIFIED_OK"),
        "Python peer failed cross-compat verification: stdout={stdout:?} stderr={stderr:?}"
    );
}

#[tokio::test]
async fn nat_roaming_allows_initiator_behind_ephemeral_port_over_4node_mcc() {
    // Nodes X1, X2, B bind to their advertised ports; initiator A binds to an ephemeral
    // NAT-like port that does NOT match A's stale `overlay_addr` in `peers.json`.
    let dir = TempDir::new().unwrap();
    let names = ["A", "X1", "X2", "B"];
    let ports = pick_free_udp_ports(5); // ports[0] is stale/unreachable for A; ports[4] is A's real NAT port

    let root_sk = Ed25519SecretKey::generate();
    let mut signers = BTreeMap::new();
    signers.insert("nat-root".to_owned(), root_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    let mut records = BTreeMap::new();
    let mut secrets = BTreeMap::new();
    let mut peers = BTreeMap::new();
    for (idx, &name) in names.iter().enumerate() {
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
        secrets.insert(name, (esk, xsk));
        peers.insert(
            name.to_owned(),
            PeerEndpoint {
                name: name.to_owned(),
                overlay_addr: SocketAddr::from(([127, 0, 0, 1], ports[idx])),
                underlay_ip: Ipv4Addr::new(198, 51, 100, 10 + idx as u8),
            },
        );
    }
    let reg_bytes = sign_registry_v2(1, &records, "nat-root", &root_sk).unwrap();
    let reg =
        verify_registry_bytes(&reg_bytes, &root_path, names, VerifyConstraints::default()).unwrap();

    let delivered: DeliveredLog = Arc::new(StdMutex::new(Vec::new()));
    let notify = Arc::new(Notify::new());
    let b_slot: Arc<StdMutex<Option<OverlayNodeHandle>>> = Arc::new(StdMutex::new(None));
    let mut handles = BTreeMap::new();

    for &name in &names {
        let (esk, xsk) = secrets.remove(name).unwrap();
        let now_s = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let sec = EndpointSecurity::new(
            name,
            reg.clone(),
            esk,
            xsk,
            dir.path().join(format!("{name}.sqlite")),
            now_s,
        )
        .unwrap();

        let bind_addr = if name == "A" {
            // Simulate A behind NAT with a different source UDP port than configured in peers.json!
            SocketAddr::from(([127, 0, 0, 1], ports[4]))
        } else {
            peers[name].overlay_addr
        };
        let mut cfg = NodeTransportConfig::new(name, bind_addr, peers.clone());
        cfg.preconnect = false;
        cfg.fanout = MccFanout {
            x1: 2,
            x2: 2,
            ike: 1,
        };
        cfg.policy = SelectionPolicy::default();

        let sink: Arc<dyn IkeSink> = match name {
            "A" => Arc::new(RecordingAutoReplySink {
                node_name: "A".to_owned(),
                delivered: Arc::clone(&delivered),
                notify: Arc::clone(&notify),
                handle_slot: Arc::new(StdMutex::new(None)),
                auto_reply: false,
            }),
            "B" => Arc::new(RecordingAutoReplySink {
                node_name: "B".to_owned(),
                delivered: Arc::clone(&delivered),
                notify: Arc::clone(&notify),
                handle_slot: Arc::clone(&b_slot),
                auto_reply: true,
            }),
            _ => Arc::new(cco_transport::RelayOnlySink),
        };

        let h = OverlayNode::start(cfg, sec, sink).await.unwrap();
        if name == "B" {
            *b_slot.lock().unwrap() = Some(h.clone());
        }
        handles.insert(name, h);
    }

    let spi = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44];
    let init_req = build_ikev2(500, IKE_SA_INIT, 0, false, spi, b"nat-init");
    handles["A"]
        .send_local_ike("B", init_req, 500)
        .await
        .unwrap();

    // Wait for B -> X2 -> X1 -> A reply over A's learned NAT endpoint!
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    while delivered.lock().unwrap().len() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for NAT-roamed IKE_SA_INIT roundtrip; got {:?}",
            delivered.lock().unwrap().len()
        );
        let _ = tokio::time::timeout(Duration::from_millis(100), notify.notified()).await;
    }

    let auth_req = build_ikev2(4500, IKE_AUTH, 1, false, spi, b"nat-auth");
    handles["A"]
        .send_local_ike("B", auth_req, 4500)
        .await
        .unwrap();

    let deadline2 = tokio::time::Instant::now() + Duration::from_secs(6);
    while delivered.lock().unwrap().len() < 4 {
        assert!(
            tokio::time::Instant::now() < deadline2,
            "timed out waiting for NAT-roamed IKE_AUTH roundtrip; got {:?}",
            delivered.lock().unwrap().len()
        );
        let _ = tokio::time::timeout(Duration::from_millis(100), notify.notified()).await;
    }

    let log = delivered.lock().unwrap().clone();
    assert_eq!(log.len(), 4);
    assert_eq!(log[0].0, "B");
    assert_eq!(log[1].0, "A");
    assert_eq!(log[2].0, "B");
    assert_eq!(log[3].0, "A");

    for h in handles.values() {
        h.shutdown().await;
    }
}
