#![forbid(unsafe_code)]
//! Sans-I/O test suite for Universal H-hop Privacy Cascade (`universal_cascade.py`).

use std::collections::{BTreeMap, VecDeque};

use cco_cascade::universal::{
    CascadeAction, CascadeIdentity, PeerChooser, UniversalCascade, calculate_copy_budget,
    validate_hop_count,
};
use cco_crypto::X25519SecretKey;
use cco_proto::MessageType;
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
