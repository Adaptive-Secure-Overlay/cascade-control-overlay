#![forbid(unsafe_code)]
//! Universal H-hop Privacy Cascade Sans-I/O state machine (`universal_cascade.py`).
//!
//! Threat model: honest-but-curious intermediate nodes. Each relay sees only its two
//! adjacent peers, a hop-local inbound handle, a distinct outbound handle, and
//! authenticated-encrypted endpoint capsules/packets. It never receives a clear
//! `(source, destination)` pair or a route-wide connection identifier.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cco_crypto::{
    Key256, UNIVERSAL_CASCADE_CAPSULE_AAD, X25519PublicKey, X25519SecretKey, aes256_gcm_decrypt,
    aes256_gcm_encrypt, decode_canonical_hex, decode_canonical_hex_vec,
    derive_universal_cascade_capsule_key, derive_universal_cascade_route_key, random_bytes,
    sha256_hex, universal_cascade_packet_aad,
};
use cco_proto::{MessageType, jdump, jload};
use cco_trust::VerifiedRegistry;
use serde_json::{Map, Value, json};

use crate::error::CascadeError;

/// Universal H-hop Cascade wire version (`universal_cascade.py::CASCADE_VERSION`).
pub const CASCADE_VERSION: u64 = 1;

/// Validates requested hop count against `[minimum, maximum]`.
pub fn validate_hop_count(
    hops: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, CascadeError> {
    if hops < minimum || hops > maximum {
        return Err(CascadeError::new("invalid_hop_count"));
    }
    Ok(hops)
}

/// Computes the physical copy product across fanout levels with an optional hard cap.
pub fn calculate_copy_budget(
    fanouts: &[usize],
    maximum: Option<usize>,
) -> Result<usize, CascadeError> {
    if fanouts.is_empty() {
        return Err(CascadeError::new("invalid_copy_budget"));
    }
    let mut total = 1usize;
    for &f in fanouts {
        if f == 0 {
            return Err(CascadeError::new("invalid_copy_budget"));
        }
        total = total
            .checked_mul(f)
            .ok_or_else(|| CascadeError::new("copy_budget_limit"))?;
        if let Some(cap) = maximum {
            if total > cap {
                return Err(CascadeError::new("copy_budget_limit"));
            }
        }
    }
    Ok(total)
}

/// Output action produced by the Sans-I/O [`UniversalCascade`] state machine.
#[derive(Debug, Clone, PartialEq)]
pub enum CascadeAction {
    /// Send a cascade protocol message to adjacent `peer`.
    Send {
        peer: String,
        message_type: MessageType,
        message: Value,
    },
    /// Deliver decrypted endpoint payload locally (`fwd` on destination or `back` on source).
    Deliver {
        direction: String,
        remote_peer: String,
        payload: Vec<u8>,
        metadata: Map<String, Value>,
        local_route_ref: String,
    },
    /// Notify the initiator that its H-hop route to `remote_peer` is active.
    RouteReady {
        remote_peer: String,
        local_route_ref: String,
        hops: usize,
    },
}

/// Snapshot of the exact routing facts visible to an intermediate relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayKnowledge {
    pub previous_peer: String,
    pub next_peer: String,
    pub inbound_handle: String,
    pub outbound_handle: String,
    pub state: String,
}

/// Current state counts inside a [`UniversalCascade`] instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CascadeCounts {
    pub relay_cells: usize,
    pub source_routes: usize,
    pub endpoint_routes: usize,
    pub dedup_entries: usize,
}

/// Node-local X25519 identity and verified public-key directory (`CascadeIdentity`).
pub struct CascadeIdentity {
    name: String,
    private_key: X25519SecretKey,
    public_keys: BTreeMap<String, X25519PublicKey>,
}

impl CascadeIdentity {
    /// Builds a [`CascadeIdentity`] directly from a verified Trust Registry v2 snapshot.
    pub fn from_verified_registry(
        name: impl Into<String>,
        private_key: X25519SecretKey,
        registry: &VerifiedRegistry,
    ) -> Result<Self, CascadeError> {
        let mut pks = BTreeMap::new();
        for (peer, rec) in registry.nodes() {
            if !rec.revoked {
                pks.insert(peer.clone(), rec.encryption);
            }
        }
        Self::new(name, private_key, pks)
    }

    /// Builds a [`CascadeIdentity`] from an explicit public-key directory.
    pub fn new(
        name: impl Into<String>,
        private_key: X25519SecretKey,
        public_keys: BTreeMap<String, X25519PublicKey>,
    ) -> Result<Self, CascadeError> {
        let name = name.into();
        let own = public_keys
            .get(&name)
            .ok_or_else(|| CascadeError::new("unknown_node"))?;
        if *own != private_key.public_key() {
            return Err(CascadeError::new("private_key_mismatch"));
        }
        Ok(Self {
            name,
            private_key,
            public_keys,
        })
    }

    /// Returns this node's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns this node's X25519 public key in lowercase hex.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        self.private_key.public_key().to_hex()
    }

    /// Checks whether `peer` has a public key in this directory.
    #[must_use]
    pub fn has_peer(&self, peer: &str) -> bool {
        self.public_keys.contains_key(peer)
    }

    /// Seals a JSON object to `recipient` using `universal-cascade-endpoint-v1`.
    pub fn seal_for(&self, recipient: &str, obj: &Value) -> Result<Value, CascadeError> {
        let recipient_pub = self
            .public_keys
            .get(recipient)
            .ok_or_else(|| CascadeError::new("unknown_node"))?;
        let ephemeral = X25519SecretKey::generate();
        let epk = ephemeral.public_key();
        let shared = ephemeral
            .diffie_hellman(recipient_pub)
            .map_err(|_| CascadeError::new("key_agreement_failed"))?;
        let key = derive_universal_cascade_capsule_key(&shared, &epk, recipient_pub)
            .map_err(|_| CascadeError::new("key_agreement_failed"))?;
        let pt = jdump(obj).map_err(|_| CascadeError::new("invalid_json"))?;
        let (nonce, ct) = aes256_gcm_encrypt(&key, &pt, UNIVERSAL_CASCADE_CAPSULE_AAD)
            .map_err(|_| CascadeError::new("encryption_failed"))?;
        Ok(json!({
            "epk": epk.to_hex(),
            "nonce": hex::encode(nonce),
            "ct": hex::encode(ct),
        }))
    }

    /// Attempts to open a capsule addressed to this node; returns `None` if not for us or invalid.
    #[must_use]
    pub fn try_open(&self, capsule: &Value) -> Option<Value> {
        let epk_hex = capsule.get("epk")?.as_str()?;
        let nonce_hex = capsule.get("nonce")?.as_str()?;
        let ct_hex = capsule.get("ct")?.as_str()?;

        let epk = X25519PublicKey::from_hex(epk_hex).ok()?;
        let nonce = decode_canonical_hex::<12>(nonce_hex).ok()?;
        let ct = decode_canonical_hex_vec(ct_hex, 262_144).ok()?;
        let own_pub = self.public_keys.get(&self.name)?;
        let shared = self.private_key.diffie_hellman(&epk).ok()?;
        let key = derive_universal_cascade_capsule_key(&shared, &epk, own_pub).ok()?;
        let pt = aes256_gcm_decrypt(&key, &nonce, &ct, UNIVERSAL_CASCADE_CAPSULE_AAD).ok()?;
        jload(&pt).ok()
    }

    /// Derives the 256-bit end-to-end route key (`universal-cascade-route-v1`).
    pub fn route_key(&self, remote_peer: &str, route_tag: &str) -> Result<Key256, CascadeError> {
        let remote_pub = self
            .public_keys
            .get(remote_peer)
            .ok_or_else(|| CascadeError::new("unknown_node"))?;
        let salt = decode_canonical_hex_vec(route_tag, 64)
            .map_err(|_| CascadeError::new("invalid_route_tag"))?;
        let shared = self
            .private_key
            .diffie_hellman(remote_pub)
            .map_err(|_| CascadeError::new("key_agreement_failed"))?;
        derive_universal_cascade_route_key(&shared, &salt)
            .map_err(|_| CascadeError::new("key_agreement_failed"))
    }
}

#[derive(Debug, Clone)]
struct RelayCell {
    inbound_handle: String,
    previous_peer: String,
    expires_at: f64,
    outbound_handle: String,
    next_peer: String,
    state: String,
    probe_handles: BTreeMap<String, String>,
    build_remaining: usize,
    build_capsule: Value,
    source_guard: Value,
    route_fingerprint: String,
    rejected_peers: BTreeSet<String>,
}

struct EndpointRoute {
    local_handle: String,
    adjacent_peer: String,
    remote_peer: String,
    route_tag: String,
    route_key: Key256,
    expires_at: f64,
    hops: usize,
    state: String,
    next_sequence: u64,
    seen_forward: BTreeSet<u64>,
    seen_reverse: BTreeSet<u64>,
    pending_forward: Vec<(u64, Vec<u8>, Map<String, Value>)>,
    initial_payload_digest: String,
    initial_payload: Vec<u8>,
    initial_metadata: Map<String, Value>,
    last_forward_payload: Vec<u8>,
    last_forward_metadata: Map<String, Value>,
}

impl EndpointRoute {
    fn local_route_ref(&self) -> String {
        self.route_tag.chars().take(16).collect()
    }
}

/// Optional deterministic or custom next-hop chooser `(node, purpose, candidates) -> chosen`.
pub type PeerChooser = Box<dyn FnMut(&str, &str, &[String]) -> String + Send>;

type OpenedPacket = (u64, Vec<u8>, Map<String, Value>);

/// Pure Sans-I/O H-hop privacy cascade state machine (`H >= 2`).
pub struct UniversalCascade {
    identity: CascadeIdentity,
    members: Vec<String>,
    max_hops: usize,
    route_ttl_s: f64,
    chooser: PeerChooser,

    // Relay cells indexed by inbound handle; outbound handle maps to owning inbound handle.
    relay_cells: BTreeMap<String, RelayCell>,
    relay_out_to_in: BTreeMap<String, String>,

    source_routes: BTreeMap<String, EndpointRoute>,
    source_by_remote: BTreeMap<String, String>,

    endpoint_routes: BTreeMap<String, EndpointRoute>,
    endpoint_by_remote: BTreeMap<String, String>,
    endpoint_by_tag: BTreeMap<String, String>,

    seen_deliveries: BTreeMap<String, f64>,
}

impl UniversalCascade {
    /// Creates a new Universal H-hop Cascade state machine.
    pub fn new(
        identity: CascadeIdentity,
        members: Vec<String>,
        max_hops: usize,
        route_ttl_s: f64,
        chooser: Option<PeerChooser>,
    ) -> Result<Self, CascadeError> {
        let mut unique = Vec::new();
        let mut seen = BTreeSet::new();
        for m in members {
            if seen.insert(m.clone()) {
                unique.push(m);
            }
        }
        for peer in &unique {
            if !identity.has_peer(peer) {
                return Err(CascadeError::new("incomplete_public_keys"));
            }
        }
        if !seen.contains(identity.name()) {
            return Err(CascadeError::new("unknown_node"));
        }

        let chooser = chooser.unwrap_or_else(|| {
            Box::new(|_node: &str, _purpose: &str, candidates: &[String]| {
                use rand::seq::SliceRandom;
                candidates
                    .choose(&mut rand::thread_rng())
                    .cloned()
                    .unwrap_or_default()
            })
        });

        Ok(Self {
            identity,
            members: unique,
            max_hops: max_hops.max(2),
            route_ttl_s: route_ttl_s.max(1.0),
            chooser,
            relay_cells: BTreeMap::new(),
            relay_out_to_in: BTreeMap::new(),
            source_routes: BTreeMap::new(),
            source_by_remote: BTreeMap::new(),
            endpoint_routes: BTreeMap::new(),
            endpoint_by_remote: BTreeMap::new(),
            endpoint_by_tag: BTreeMap::new(),
            seen_deliveries: BTreeMap::new(),
        })
    }

    /// Returns this node's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.identity.name()
    }

    fn new_handle() -> String {
        hex::encode(random_bytes::<16>())
    }

    fn valid_handle(value: Option<&Value>) -> Result<String, CascadeError> {
        let handle = value
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_handle"))?;
        decode_canonical_hex::<16>(handle).map_err(|_| CascadeError::new("invalid_handle"))?;
        Ok(handle.to_owned())
    }

    fn select_peer(
        &mut self,
        purpose: &str,
        candidates: &[String],
    ) -> Result<String, CascadeError> {
        if candidates.is_empty() {
            return Err(CascadeError::new("no_candidates"));
        }
        let selected = (self.chooser)(self.identity.name(), purpose, candidates);
        if !candidates.contains(&selected) {
            return Err(CascadeError::new("invalid_chooser_selection"));
        }
        Ok(selected)
    }

    fn base_message(handle: &str, expires_at: f64) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("v".to_owned(), json!(CASCADE_VERSION));
        m.insert("h".to_owned(), json!(handle));
        m.insert("expires_at".to_owned(), json!(expires_at));
        m
    }

    fn check_message(&self, msg: &Value, now_secs: f64) -> Result<(String, f64), CascadeError> {
        if msg.get("v").and_then(Value::as_u64) != Some(CASCADE_VERSION) {
            return Err(CascadeError::new("unsupported_cascade_version"));
        }
        let handle = Self::valid_handle(msg.get("h"))?;
        let expires_at = msg
            .get("expires_at")
            .and_then(Value::as_f64)
            .filter(|t| t.is_finite())
            .ok_or_else(|| CascadeError::new("invalid_expiry"))?;
        if expires_at <= now_secs {
            return Err(CascadeError::new("expired_message"));
        }
        Ok((handle, expires_at))
    }

    fn wire_payload(payload: &[u8], metadata: &Map<String, Value>) -> Value {
        json!({
            "payload": STANDARD.encode(payload),
            "metadata": Value::Object(metadata.clone()),
        })
    }

    fn open_wire_payload(obj: &Value) -> Result<(Vec<u8>, Map<String, Value>), CascadeError> {
        let b64 = obj
            .get("payload")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_payload"))?;
        let payload = STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| CascadeError::new("invalid_endpoint_payload"))?;
        let metadata = obj
            .get("metadata")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        Ok((payload, metadata))
    }

    fn seal_packet(
        route: &EndpointRoute,
        direction: &str,
        sequence: u64,
        payload: &[u8],
        metadata: &Map<String, Value>,
    ) -> Result<Value, CascadeError> {
        let pt = jdump(&Self::wire_payload(payload, metadata))
            .map_err(|_| CascadeError::new("invalid_json"))?;
        let aad = universal_cascade_packet_aad(&route.route_tag, direction, sequence);
        let (nonce, ct) = aes256_gcm_encrypt(&route.route_key, &pt, &aad)
            .map_err(|_| CascadeError::new("encryption_failed"))?;
        Ok(json!({
            "seq": sequence,
            "nonce": hex::encode(nonce),
            "ct": hex::encode(ct),
        }))
    }

    fn open_packet(
        route: &EndpointRoute,
        direction: &str,
        packet: &Value,
    ) -> Result<OpenedPacket, CascadeError> {
        let seq = packet
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| CascadeError::new("packet_authentication_failed"))?;
        let nonce_hex = packet
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("packet_authentication_failed"))?;
        let ct_hex = packet
            .get("ct")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("packet_authentication_failed"))?;
        let nonce = decode_canonical_hex::<12>(nonce_hex)
            .map_err(|_| CascadeError::new("packet_authentication_failed"))?;
        let ct = decode_canonical_hex_vec(ct_hex, 262_144)
            .map_err(|_| CascadeError::new("packet_authentication_failed"))?;
        let aad = universal_cascade_packet_aad(&route.route_tag, direction, seq);
        let pt = aes256_gcm_decrypt(&route.route_key, &nonce, &ct, &aad)
            .map_err(|_| CascadeError::new("packet_authentication_failed"))?;
        let val = jload(&pt).map_err(|_| CascadeError::new("invalid_endpoint_payload"))?;
        let (payload, meta) = Self::open_wire_payload(&val)?;
        Ok((seq, payload, meta))
    }

    /// Initiates a new H-hop route (`hops >= 2`) from this node to `destination`.
    pub fn start_route(
        &mut self,
        destination: &str,
        hops: usize,
        payload: &[u8],
        metadata: Map<String, Value>,
        first_hop: Option<&str>,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        self.cleanup(now_secs);
        let hop_count = validate_hop_count(hops, 2, self.max_hops)?;
        if destination == self.identity.name() || !self.members.iter().any(|m| m == destination) {
            return Err(CascadeError::new("invalid_destination"));
        }

        let candidates: Vec<String> = self
            .members
            .iter()
            .filter(|m| m.as_str() != self.identity.name() && m.as_str() != destination)
            .cloned()
            .collect();
        let selected_first = match first_hop {
            None => self.select_peer("first-hop", &candidates)?,
            Some(explicit) => {
                if !candidates.iter().any(|c| c == explicit) {
                    return Err(CascadeError::new("invalid_first_hop"));
                }
                explicit.to_owned()
            }
        };

        let expires_at = now_secs + self.route_ttl_s;
        let route_tag = Self::new_handle();
        let local_handle = Self::new_handle();
        let route_key = self.identity.route_key(destination, &route_tag)?;

        let route = EndpointRoute {
            local_handle: local_handle.clone(),
            adjacent_peer: selected_first.clone(),
            remote_peer: destination.to_owned(),
            route_tag: route_tag.clone(),
            route_key,
            expires_at,
            hops: hop_count,
            state: "building".to_owned(),
            next_sequence: 1,
            seen_forward: BTreeSet::new(),
            seen_reverse: BTreeSet::new(),
            pending_forward: Vec::new(),
            initial_payload_digest: sha256_hex(payload),
            initial_payload: payload.to_vec(),
            initial_metadata: metadata.clone(),
            last_forward_payload: Vec::new(),
            last_forward_metadata: Map::new(),
        };
        self.source_routes.insert(local_handle.clone(), route);
        self.source_by_remote
            .insert(destination.to_owned(), local_handle.clone());

        let endpoint_obj = json!({
            "v": CASCADE_VERSION,
            "source": self.identity.name(),
            "destination": destination,
            "route_tag": route_tag,
            "hops": hop_count,
            "expires_at": expires_at,
            "initial": Self::wire_payload(payload, &metadata),
        });
        let capsule = self.identity.seal_for(destination, &endpoint_obj)?;
        let source_guard = self.identity.seal_for(
            self.identity.name(),
            &json!({
                "v": CASCADE_VERSION,
                "guard": "source",
                "route_tag": route_tag,
            }),
        )?;

        let mut msg = Self::base_message(&local_handle, expires_at);
        msg.insert("remaining".to_owned(), json!(hop_count));
        msg.insert("capsule".to_owned(), capsule);
        msg.insert("source_guard".to_owned(), source_guard);

        Ok(vec![CascadeAction::Send {
            peer: selected_first,
            message_type: MessageType::CascadeBuild,
            message: Value::Object(msg),
        }])
    }

    /// Sends forward data over an existing source route (queues while `building`).
    pub fn send_forward(
        &mut self,
        destination: &str,
        payload: &[u8],
        metadata: Map<String, Value>,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        self.cleanup(now_secs);
        let handle = self
            .source_by_remote
            .get(destination)
            .cloned()
            .ok_or_else(|| CascadeError::new("no_source_route"))?;
        let route = self
            .source_routes
            .get_mut(&handle)
            .ok_or_else(|| CascadeError::new("no_source_route"))?;
        let seq = route.next_sequence;
        if route.state != "active" {
            let digest = sha256_hex(payload);
            if digest == route.initial_payload_digest
                || route
                    .pending_forward
                    .iter()
                    .any(|(_, p, _)| sha256_hex(p) == digest)
            {
                return Ok(Vec::new());
            }
            route.next_sequence += 1;
            route
                .pending_forward
                .push((seq, payload.to_vec(), metadata));
            return Ok(Vec::new());
        }
        route.next_sequence += 1;
        route.last_forward_payload = payload.to_vec();
        route.last_forward_metadata = metadata.clone();
        Ok(vec![Self::forward_action(route, seq, payload, &metadata)?])
    }

    /// Sends reverse data from destination `B` back to initiator `source`.
    pub fn send_reverse(
        &mut self,
        source: &str,
        payload: &[u8],
        metadata: Map<String, Value>,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        self.cleanup(now_secs);
        let handle = self
            .endpoint_by_remote
            .get(source)
            .cloned()
            .ok_or_else(|| CascadeError::new("no_endpoint_route"))?;
        let route = self
            .endpoint_routes
            .get_mut(&handle)
            .ok_or_else(|| CascadeError::new("no_endpoint_route"))?;
        let seq = route.next_sequence;
        route.next_sequence += 1;
        let packet = Self::seal_packet(route, "back", seq, payload, &metadata)?;
        let mut msg = Self::base_message(&route.local_handle, route.expires_at);
        msg.insert("packet".to_owned(), packet);
        Ok(vec![CascadeAction::Send {
            peer: route.adjacent_peer.clone(),
            message_type: MessageType::CascadeBack,
            message: Value::Object(msg),
        }])
    }

    fn forward_action(
        route: &EndpointRoute,
        sequence: u64,
        payload: &[u8],
        metadata: &Map<String, Value>,
    ) -> Result<CascadeAction, CascadeError> {
        let packet = Self::seal_packet(route, "fwd", sequence, payload, metadata)?;
        let mut msg = Self::base_message(&route.local_handle, route.expires_at);
        msg.insert("packet".to_owned(), packet);
        Ok(CascadeAction::Send {
            peer: route.adjacent_peer.clone(),
            message_type: MessageType::CascadeData,
            message: Value::Object(msg),
        })
    }

    /// Processes an incoming `CASCADE_*` message from adjacent `peer`.
    pub fn receive(
        &mut self,
        peer: &str,
        message_type: MessageType,
        message: &Value,
        delivery_id: &str,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        self.cleanup(now_secs);
        if peer == self.identity.name() || !self.members.iter().any(|m| m == peer) {
            return Err(CascadeError::new("invalid_adjacent_peer"));
        }
        if !message_type.is_cascade_message() {
            return Err(CascadeError::new("unknown_cascade_message"));
        }
        if !delivery_id.is_empty() {
            let dedup_key = format!("{peer}:{}:{delivery_id}", message_type.as_str());
            if self
                .seen_deliveries
                .get(&dedup_key)
                .is_some_and(|&exp| exp > now_secs)
            {
                return Ok(Vec::new());
            }
            self.seen_deliveries
                .insert(dedup_key, now_secs + self.route_ttl_s);
        }

        match message_type {
            MessageType::CascadeBuild => self.receive_build(peer, message, now_secs),
            MessageType::CascadeReject => self.receive_reject(peer, message, now_secs),
            MessageType::CascadeAbort => self.receive_abort(peer, message, now_secs),
            MessageType::CascadeProbe => self.receive_probe(peer, message, now_secs),
            MessageType::CascadeAccept => self.receive_accept(peer, message, now_secs),
            MessageType::CascadeData => self.receive_data(peer, message, now_secs),
            MessageType::CascadeBack => self.receive_back(peer, message, now_secs),
            MessageType::CascadeClose => self.receive_close(peer, message, now_secs),
            _ => Err(CascadeError::new("unknown_cascade_message")),
        }
    }

    fn receive_build(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (inbound_handle, expires_at) = self.check_message(message, now_secs)?;
        let remaining = message
            .get("remaining")
            .and_then(Value::as_u64)
            .map(|v| v as usize)
            .ok_or_else(|| CascadeError::new("invalid_build_message"))?;
        let capsule = message
            .get("capsule")
            .filter(|v| v.is_object())
            .cloned()
            .ok_or_else(|| CascadeError::new("invalid_build_message"))?;
        let source_guard = message
            .get("source_guard")
            .filter(|v| v.is_object())
            .cloned()
            .ok_or_else(|| CascadeError::new("invalid_build_message"))?;

        if remaining < 1 || remaining > self.max_hops {
            return Err(CascadeError::new("invalid_remaining_hops"));
        }
        if self.relay_cells.contains_key(&inbound_handle) {
            return Ok(Vec::new());
        }

        let endpoint_marker = self.identity.try_open(&capsule);
        let source_marker = self.identity.try_open(&source_guard);
        let fingerprint =
            sha256_hex(&jdump(&capsule).map_err(|_| CascadeError::new("invalid_json"))?);
        let already_visited = self
            .relay_cells
            .values()
            .any(|c| c.route_fingerprint == fingerprint);
        let is_destination = endpoint_marker
            .as_ref()
            .and_then(|v| v.get("destination"))
            .and_then(Value::as_str)
            == Some(self.identity.name());
        let is_source = source_marker
            .as_ref()
            .and_then(|v| v.get("guard"))
            .and_then(Value::as_str)
            == Some("source");

        if is_destination || is_source || already_visited {
            let rejected = Self::base_message(&inbound_handle, expires_at);
            return Ok(vec![CascadeAction::Send {
                peer: peer.to_owned(),
                message_type: MessageType::CascadeReject,
                message: Value::Object(rejected),
            }]);
        }

        let cell = RelayCell {
            inbound_handle: inbound_handle.clone(),
            previous_peer: peer.to_owned(),
            expires_at,
            outbound_handle: String::new(),
            next_peer: String::new(),
            state: "building".to_owned(),
            probe_handles: BTreeMap::new(),
            build_remaining: remaining,
            build_capsule: capsule.clone(),
            source_guard,
            route_fingerprint: fingerprint,
            rejected_peers: BTreeSet::new(),
        };
        self.relay_cells.insert(inbound_handle.clone(), cell);

        if remaining > 1 {
            return self.advance_relay(&inbound_handle);
        }

        // Terminal relay (remaining == 1): probe all other members with unique per-peer handles
        let mut actions = Vec::new();
        let candidates: Vec<String> = self
            .members
            .iter()
            .filter(|m| m.as_str() != self.identity.name())
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Err(CascadeError::new("no_probe_candidates"));
        }
        {
            let cell = self.relay_cells.get_mut(&inbound_handle).unwrap();
            cell.state = "probing".to_owned();
            for candidate in candidates {
                let probe_handle = Self::new_handle();
                cell.probe_handles
                    .insert(candidate.clone(), probe_handle.clone());
                self.relay_out_to_in
                    .insert(probe_handle.clone(), inbound_handle.clone());
                let mut probe = Self::base_message(&probe_handle, expires_at);
                probe.insert("capsule".to_owned(), capsule.clone());
                actions.push(CascadeAction::Send {
                    peer: candidate,
                    message_type: MessageType::CascadeProbe,
                    message: Value::Object(probe),
                });
            }
        }
        Ok(actions)
    }

    fn advance_relay(&mut self, inbound_handle: &str) -> Result<Vec<CascadeAction>, CascadeError> {
        let (candidates, remaining, prev_peer, expires_at, capsule, source_guard) = {
            let cell = self
                .relay_cells
                .get(inbound_handle)
                .ok_or_else(|| CascadeError::new("missing_relay_cell"))?;
            let cands: Vec<String> = self
                .members
                .iter()
                .filter(|m| {
                    m.as_str() != self.identity.name()
                        && m.as_str() != cell.previous_peer.as_str()
                        && !cell.rejected_peers.contains(m.as_str())
                })
                .cloned()
                .collect();
            (
                cands,
                cell.build_remaining,
                cell.previous_peer.clone(),
                cell.expires_at,
                cell.build_capsule.clone(),
                cell.source_guard.clone(),
            )
        };

        if candidates.is_empty() {
            let rejected = Self::base_message(inbound_handle, expires_at);
            self.remove_relay_cell(inbound_handle);
            return Ok(vec![CascadeAction::Send {
                peer: prev_peer,
                message_type: MessageType::CascadeReject,
                message: Value::Object(rejected),
            }]);
        }

        let next_peer = self.select_peer(&format!("relay-{remaining}"), &candidates)?;
        let outbound_handle = Self::new_handle();
        if let Some(cell) = self.relay_cells.get_mut(inbound_handle) {
            cell.outbound_handle = outbound_handle.clone();
            cell.next_peer = next_peer.clone();
        }
        self.relay_out_to_in
            .insert(outbound_handle.clone(), inbound_handle.to_owned());

        let mut forwarded = Self::base_message(&outbound_handle, expires_at);
        forwarded.insert("remaining".to_owned(), json!(remaining - 1));
        forwarded.insert("capsule".to_owned(), capsule);
        forwarded.insert("source_guard".to_owned(), source_guard);
        Ok(vec![CascadeAction::Send {
            peer: next_peer,
            message_type: MessageType::CascadeBuild,
            message: Value::Object(forwarded),
        }])
    }

    fn receive_reject(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (handle, _) = self.check_message(message, now_secs)?;
        if let Some(in_handle) = self.relay_out_to_in.get(&handle).cloned() {
            let valid = self
                .relay_cells
                .get(&in_handle)
                .is_some_and(|c| c.next_peer == peer && c.outbound_handle == handle);
            if !valid {
                return Err(CascadeError::new("wrong_neighbor"));
            }
            self.relay_out_to_in.remove(&handle);
            if let Some(cell) = self.relay_cells.get_mut(&in_handle) {
                cell.rejected_peers.insert(peer.to_owned());
                cell.outbound_handle.clear();
                cell.next_peer.clear();
            }
            return self.advance_relay(&in_handle);
        }
        if let Some(source) = self.source_routes.get(&handle) {
            if source.adjacent_peer == peer {
                self.remove_source_route(&handle);
                return Ok(Vec::new());
            }
        }
        Err(CascadeError::new("unknown_route_state"))
    }

    fn rebuild_source(
        &mut self,
        handle: &str,
        payload: &[u8],
        metadata: Map<String, Value>,
        excluded_first_hops: &[&str],
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let Some(route) = self.source_routes.get(handle) else {
            return Ok(Vec::new());
        };
        let destination = route.remote_peer.clone();
        let hops = route.hops;
        let pending = route.pending_forward.clone();
        self.remove_source_route(handle);

        let candidates: Vec<String> = self
            .members
            .iter()
            .filter(|m| {
                m.as_str() != self.identity.name()
                    && m.as_str() != destination.as_str()
                    && !excluded_first_hops.contains(&m.as_str())
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let first_hop = self.select_peer("first-hop-recovery", &candidates)?;
        let actions = self.start_route(
            &destination,
            hops,
            payload,
            metadata,
            Some(&first_hop),
            now_secs,
        )?;
        if let Some(new_handle) = self.source_by_remote.get(&destination).cloned() {
            if let Some(rebuilt) = self.source_routes.get_mut(&new_handle) {
                for (_, queued_payload, queued_meta) in pending {
                    if sha256_hex(&queued_payload) == rebuilt.initial_payload_digest {
                        continue;
                    }
                    let seq = rebuilt.next_sequence;
                    rebuilt.next_sequence += 1;
                    rebuilt
                        .pending_forward
                        .push((seq, queued_payload, queued_meta));
                }
            }
        }
        Ok(actions)
    }

    fn receive_abort(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (handle, _) = self.check_message(message, now_secs)?;
        if let Some(in_handle) = self.relay_out_to_in.get(&handle).cloned() {
            let (prev_peer, expires_at) = {
                let cell = self
                    .relay_cells
                    .get(&in_handle)
                    .ok_or_else(|| CascadeError::new("missing_relay_cell"))?;
                if cell.next_peer != peer {
                    return Err(CascadeError::new("wrong_neighbor"));
                }
                (cell.previous_peer.clone(), cell.expires_at)
            };
            let aborted = Self::base_message(&in_handle, expires_at);
            self.remove_relay_cell(&in_handle);
            return Ok(vec![CascadeAction::Send {
                peer: prev_peer,
                message_type: MessageType::CascadeAbort,
                message: Value::Object(aborted),
            }]);
        }

        let (payload, meta) = {
            let source = self
                .source_routes
                .get(&handle)
                .ok_or_else(|| CascadeError::new("unknown_route_state"))?;
            if source.adjacent_peer != peer {
                return Err(CascadeError::new("wrong_neighbor"));
            }
            if !source.last_forward_payload.is_empty() {
                (
                    source.last_forward_payload.clone(),
                    source.last_forward_metadata.clone(),
                )
            } else {
                (
                    source.initial_payload.clone(),
                    source.initial_metadata.clone(),
                )
            }
        };
        self.rebuild_source(&handle, &payload, meta, &[], now_secs)
    }

    /// Repairs local cascade state after an adjacent hop delivery failure.
    pub fn handle_send_failure(
        &mut self,
        peer: &str,
        message_type: MessageType,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        self.cleanup(now_secs);
        let Ok(handle) = Self::valid_handle(message.get("h")) else {
            return Ok(Vec::new());
        };
        match message_type {
            MessageType::CascadeBuild => {
                if let Some(in_handle) = self.relay_out_to_in.get(&handle).cloned() {
                    if self
                        .relay_cells
                        .get(&in_handle)
                        .is_some_and(|c| c.next_peer == peer)
                    {
                        self.relay_out_to_in.remove(&handle);
                        if let Some(cell) = self.relay_cells.get_mut(&in_handle) {
                            cell.rejected_peers.insert(peer.to_owned());
                            cell.outbound_handle.clear();
                            cell.next_peer.clear();
                        }
                        return self.advance_relay(&in_handle);
                    }
                }
                if let Some(source) = self.source_routes.get(&handle) {
                    if source.adjacent_peer == peer {
                        let p = source.initial_payload.clone();
                        let m = source.initial_metadata.clone();
                        return self.rebuild_source(&handle, &p, m, &[peer], now_secs);
                    }
                }
                Ok(Vec::new())
            }
            MessageType::CascadeProbe => {
                if let Some(in_handle) = self.relay_out_to_in.get(&handle).cloned() {
                    if let Some(cell) = self.relay_cells.get_mut(&in_handle) {
                        if cell.probe_handles.get(peer).map(String::as_str) == Some(&handle) {
                            cell.probe_handles.remove(peer);
                            self.relay_out_to_in.remove(&handle);
                        }
                    }
                }
                Ok(Vec::new())
            }
            MessageType::CascadeData => {
                if let Some(source) = self.source_routes.get(&handle) {
                    if source.adjacent_peer == peer {
                        let (p, m) = message
                            .get("packet")
                            .and_then(|pkt| Self::open_packet(source, "fwd", pkt).ok())
                            .map(|(_, p, m)| (p, m))
                            .unwrap_or_else(|| {
                                if !source.last_forward_payload.is_empty() {
                                    (
                                        source.last_forward_payload.clone(),
                                        source.last_forward_metadata.clone(),
                                    )
                                } else {
                                    (
                                        source.initial_payload.clone(),
                                        source.initial_metadata.clone(),
                                    )
                                }
                            });
                        return self.rebuild_source(&handle, &p, m, &[peer], now_secs);
                    }
                }
                if let Some(in_handle) = self.relay_out_to_in.get(&handle).cloned() {
                    let info = self.relay_cells.get(&in_handle).and_then(|c| {
                        if c.next_peer == peer {
                            Some((c.previous_peer.clone(), c.expires_at))
                        } else {
                            None
                        }
                    });
                    if let Some((prev_peer, expires_at)) = info {
                        let aborted = Self::base_message(&in_handle, expires_at);
                        self.remove_relay_cell(&in_handle);
                        return Ok(vec![CascadeAction::Send {
                            peer: prev_peer,
                            message_type: MessageType::CascadeAbort,
                            message: Value::Object(aborted),
                        }]);
                    }
                }
                Ok(Vec::new())
            }
            MessageType::CascadeAccept | MessageType::CascadeBack => {
                if self
                    .relay_cells
                    .get(&handle)
                    .is_some_and(|c| c.previous_peer == peer)
                {
                    self.remove_relay_cell(&handle);
                }
                if self
                    .endpoint_routes
                    .get(&handle)
                    .is_some_and(|e| e.adjacent_peer == peer)
                {
                    self.remove_endpoint_route(&handle);
                }
                Ok(Vec::new())
            }
            _ => Ok(Vec::new()),
        }
    }

    fn receive_probe(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (handle, expires_at) = self.check_message(message, now_secs)?;
        let Some(capsule) = message.get("capsule") else {
            return Ok(Vec::new());
        };
        let Some(endpoint) = self.identity.try_open(capsule) else {
            // Probe was intended for a different terminal destination — silently ignore.
            return Ok(Vec::new());
        };

        if endpoint.get("v").and_then(Value::as_u64) != Some(CASCADE_VERSION) {
            return Err(CascadeError::new("unsupported_capsule_version"));
        }
        let source = endpoint
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?
            .to_owned();
        let destination = endpoint
            .get("destination")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?;
        if destination != self.identity.name() {
            return Ok(Vec::new());
        }
        if source == self.identity.name() || !self.members.iter().any(|m| m == &source) {
            return Err(CascadeError::new("invalid_endpoint_source"));
        }
        let route_tag = endpoint
            .get("route_tag")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?
            .to_owned();
        let hops_raw = endpoint
            .get("hops")
            .and_then(Value::as_u64)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?
            as usize;
        let hops = validate_hop_count(hops_raw, 2, self.max_hops)?;
        let capsule_expiry = endpoint
            .get("expires_at")
            .and_then(Value::as_f64)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?;
        if capsule_expiry <= now_secs || (capsule_expiry - expires_at).abs() > 1.0 {
            return Err(CascadeError::new("capsule_expiry_mismatch"));
        }
        let initial = endpoint
            .get("initial")
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?;
        let (initial_payload, mut initial_meta) = Self::open_wire_payload(initial)?;

        if let Some(prev_handle) = self.endpoint_by_tag.get(&route_tag).cloned() {
            if let Some(prev) = self.endpoint_routes.get(&prev_handle) {
                if prev.adjacent_peer == peer && prev.local_handle == handle {
                    let mut proof_meta = Map::new();
                    proof_meta.insert("accepted_by".to_owned(), json!(self.identity.name()));
                    let mut accept = Self::base_message(&handle, prev.expires_at);
                    accept.insert(
                        "proof".to_owned(),
                        Self::seal_packet(prev, "accept", 0, b"", &proof_meta)?,
                    );
                    return Ok(vec![CascadeAction::Send {
                        peer: peer.to_owned(),
                        message_type: MessageType::CascadeAccept,
                        message: Value::Object(accept),
                    }]);
                }
            }
            return Ok(Vec::new());
        }

        let route_key = self.identity.route_key(&source, &route_tag)?;
        let route = EndpointRoute {
            local_handle: handle.clone(),
            adjacent_peer: peer.to_owned(),
            remote_peer: source.clone(),
            route_tag: route_tag.clone(),
            route_key,
            expires_at: expires_at.min(capsule_expiry),
            hops,
            state: "active".to_owned(),
            next_sequence: 1,
            seen_forward: BTreeSet::new(),
            seen_reverse: BTreeSet::new(),
            pending_forward: Vec::new(),
            initial_payload_digest: String::new(),
            initial_payload: Vec::new(),
            initial_metadata: Map::new(),
            last_forward_payload: Vec::new(),
            last_forward_metadata: Map::new(),
        };
        let route_ref = route.local_route_ref();
        let mut proof_meta = Map::new();
        proof_meta.insert("accepted_by".to_owned(), json!(self.identity.name()));
        let mut accept = Self::base_message(&handle, route.expires_at);
        accept.insert(
            "proof".to_owned(),
            Self::seal_packet(&route, "accept", 0, b"", &proof_meta)?,
        );

        self.endpoint_routes.insert(handle.clone(), route);
        self.endpoint_by_remote
            .insert(source.clone(), handle.clone());
        self.endpoint_by_tag.insert(route_tag, handle);

        initial_meta.insert("cascade".to_owned(), json!(true));
        initial_meta.insert("cascade_direction".to_owned(), json!("fwd"));
        initial_meta.insert("cascade_remote_peer".to_owned(), json!(source));
        initial_meta.insert("cascade_hops".to_owned(), json!(hops));
        initial_meta.insert("cascade_route_ref".to_owned(), json!(route_ref));

        Ok(vec![
            CascadeAction::Send {
                peer: peer.to_owned(),
                message_type: MessageType::CascadeAccept,
                message: Value::Object(accept),
            },
            CascadeAction::Deliver {
                direction: "fwd".to_owned(),
                remote_peer: source,
                payload: initial_payload,
                metadata: initial_meta,
                local_route_ref: route_ref,
            },
        ])
    }

    fn receive_accept(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (handle, _) = self.check_message(message, now_secs)?;
        let proof = message
            .get("proof")
            .cloned()
            .unwrap_or(Value::Object(Map::new()));

        if let Some(in_handle) = self.relay_out_to_in.get(&handle).cloned() {
            let (prev_peer, expires_at) = {
                let cell = self
                    .relay_cells
                    .get_mut(&in_handle)
                    .ok_or_else(|| CascadeError::new("missing_relay_cell"))?;
                if cell.state == "probing" {
                    if cell.probe_handles.get(peer).map(String::as_str) != Some(&handle) {
                        return Err(CascadeError::new("wrong_probe_handle"));
                    }
                    let stale: Vec<String> = cell
                        .probe_handles
                        .values()
                        .filter(|h| h.as_str() != handle)
                        .cloned()
                        .collect();
                    for h in stale {
                        self.relay_out_to_in.remove(&h);
                    }
                    cell.probe_handles.clear();
                    cell.probe_handles.insert(peer.to_owned(), handle.clone());
                    cell.outbound_handle = handle.clone();
                    cell.next_peer = peer.to_owned();
                } else if cell.next_peer != peer || cell.outbound_handle != handle {
                    return Err(CascadeError::new("wrong_neighbor"));
                }
                cell.state = "active".to_owned();
                (cell.previous_peer.clone(), cell.expires_at)
            };
            let mut accepted = Self::base_message(&in_handle, expires_at);
            accepted.insert("proof".to_owned(), proof);
            return Ok(vec![CascadeAction::Send {
                peer: prev_peer,
                message_type: MessageType::CascadeAccept,
                message: Value::Object(accepted),
            }]);
        }

        let route = self
            .source_routes
            .get_mut(&handle)
            .ok_or_else(|| CascadeError::new("unknown_route_state"))?;
        if route.adjacent_peer != peer {
            return Err(CascadeError::new("wrong_neighbor"));
        }
        let (seq, proof_payload, proof_meta) = Self::open_packet(route, "accept", &proof)?;
        if seq != 0
            || !proof_payload.is_empty()
            || proof_meta.get("accepted_by").and_then(Value::as_str)
                != Some(route.remote_peer.as_str())
        {
            return Err(CascadeError::new("invalid_accept_proof"));
        }

        let already_active = route.state == "active";
        route.state = "active".to_owned();
        let mut actions = Vec::new();
        if !already_active {
            actions.push(CascadeAction::RouteReady {
                remote_peer: route.remote_peer.clone(),
                local_route_ref: route.local_route_ref(),
                hops: route.hops,
            });
        }
        let pending = std::mem::take(&mut route.pending_forward);
        for (pseq, ppayload, pmeta) in pending {
            actions.push(Self::forward_action(route, pseq, &ppayload, &pmeta)?);
        }
        Ok(actions)
    }

    fn receive_data(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (handle, _) = self.check_message(message, now_secs)?;
        let packet = message
            .get("packet")
            .cloned()
            .unwrap_or(Value::Object(Map::new()));

        if let Some(endpoint) = self.endpoint_routes.get_mut(&handle) {
            if endpoint.adjacent_peer != peer {
                return Err(CascadeError::new("wrong_neighbor"));
            }
            let (seq, payload, mut meta) = Self::open_packet(endpoint, "fwd", &packet)?;
            if !endpoint.seen_forward.insert(seq) {
                return Ok(Vec::new());
            }
            let route_ref = endpoint.local_route_ref();
            meta.insert("cascade".to_owned(), json!(true));
            meta.insert("cascade_direction".to_owned(), json!("fwd"));
            meta.insert(
                "cascade_remote_peer".to_owned(),
                json!(endpoint.remote_peer),
            );
            meta.insert("cascade_hops".to_owned(), json!(endpoint.hops));
            meta.insert("cascade_route_ref".to_owned(), json!(route_ref));
            return Ok(vec![CascadeAction::Deliver {
                direction: "fwd".to_owned(),
                remote_peer: endpoint.remote_peer.clone(),
                payload,
                metadata: meta,
                local_route_ref: route_ref,
            }]);
        }

        let cell = self
            .relay_cells
            .get(&handle)
            .ok_or_else(|| CascadeError::new("no_active_relay_cell"))?;
        if cell.previous_peer != peer || cell.state != "active" {
            return Err(CascadeError::new("no_active_relay_cell"));
        }
        let mut forwarded = Self::base_message(&cell.outbound_handle, cell.expires_at);
        forwarded.insert("packet".to_owned(), packet);
        Ok(vec![CascadeAction::Send {
            peer: cell.next_peer.clone(),
            message_type: MessageType::CascadeData,
            message: Value::Object(forwarded),
        }])
    }

    fn receive_back(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (handle, _) = self.check_message(message, now_secs)?;
        let packet = message
            .get("packet")
            .cloned()
            .unwrap_or(Value::Object(Map::new()));

        if let Some(source) = self.source_routes.get_mut(&handle) {
            if source.adjacent_peer != peer {
                return Err(CascadeError::new("wrong_neighbor"));
            }
            let (seq, payload, mut meta) = Self::open_packet(source, "back", &packet)?;
            if !source.seen_reverse.insert(seq) {
                return Ok(Vec::new());
            }
            let route_ref = source.local_route_ref();
            meta.insert("cascade".to_owned(), json!(true));
            meta.insert("cascade_direction".to_owned(), json!("back"));
            meta.insert("cascade_remote_peer".to_owned(), json!(source.remote_peer));
            meta.insert("cascade_hops".to_owned(), json!(source.hops));
            meta.insert("cascade_route_ref".to_owned(), json!(route_ref));
            return Ok(vec![CascadeAction::Deliver {
                direction: "back".to_owned(),
                remote_peer: source.remote_peer.clone(),
                payload,
                metadata: meta,
                local_route_ref: route_ref,
            }]);
        }

        let in_handle = self
            .relay_out_to_in
            .get(&handle)
            .ok_or_else(|| CascadeError::new("no_active_relay_cell"))?;
        let cell = self
            .relay_cells
            .get(in_handle)
            .ok_or_else(|| CascadeError::new("no_active_relay_cell"))?;
        if cell.next_peer != peer || cell.state != "active" {
            return Err(CascadeError::new("no_active_relay_cell"));
        }
        let mut forwarded = Self::base_message(&cell.inbound_handle, cell.expires_at);
        forwarded.insert("packet".to_owned(), packet);
        Ok(vec![CascadeAction::Send {
            peer: cell.previous_peer.clone(),
            message_type: MessageType::CascadeBack,
            message: Value::Object(forwarded),
        }])
    }

    fn receive_close(
        &mut self,
        peer: &str,
        message: &Value,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let (handle, _) = self.check_message(message, now_secs)?;
        if let Some(cell) = self.relay_cells.get(&handle).cloned() {
            if cell.previous_peer == peer {
                let mut actions = Vec::new();
                if !cell.outbound_handle.is_empty() && !cell.next_peer.is_empty() {
                    let forwarded = Self::base_message(&cell.outbound_handle, cell.expires_at);
                    actions.push(CascadeAction::Send {
                        peer: cell.next_peer.clone(),
                        message_type: MessageType::CascadeClose,
                        message: Value::Object(forwarded),
                    });
                }
                self.remove_relay_cell(&handle);
                return Ok(actions);
            }
        }
        if self
            .endpoint_routes
            .get(&handle)
            .is_some_and(|e| e.adjacent_peer == peer)
        {
            self.remove_endpoint_route(&handle);
        }
        Ok(Vec::new())
    }

    /// Closes an established source route to `destination` and emits `CASCADE_CLOSE`.
    pub fn close_source_route(&mut self, destination: &str) -> Vec<CascadeAction> {
        let Some(handle) = self.source_by_remote.get(destination).cloned() else {
            return Vec::new();
        };
        let Some(route) = self.source_routes.get(&handle) else {
            return Vec::new();
        };
        let msg = Self::base_message(&route.local_handle, route.expires_at);
        let peer = route.adjacent_peer.clone();
        self.remove_source_route(&handle);
        vec![CascadeAction::Send {
            peer,
            message_type: MessageType::CascadeClose,
            message: Value::Object(msg),
        }]
    }

    /// Checks whether a source route to `destination` currently exists.
    pub fn has_source_route(
        &mut self,
        destination: &str,
        active_only: bool,
        now_secs: f64,
    ) -> bool {
        self.cleanup(now_secs);
        self.source_by_remote
            .get(destination)
            .and_then(|h| self.source_routes.get(h))
            .is_some_and(|r| !active_only || r.state == "active")
    }

    /// Checks whether an endpoint route from `source` currently exists.
    pub fn has_endpoint_route(&mut self, source: &str, now_secs: f64) -> bool {
        self.cleanup(now_secs);
        self.endpoint_by_remote
            .get(source)
            .and_then(|h| self.endpoint_routes.get(h))
            .is_some()
    }

    /// Expires stale relays, routes, and deduplication records at `now_secs`.
    pub fn cleanup(&mut self, now_secs: f64) {
        let expired_relays: Vec<String> = self
            .relay_cells
            .iter()
            .filter(|(_, c)| c.expires_at <= now_secs)
            .map(|(k, _)| k.clone())
            .collect();
        for h in expired_relays {
            self.remove_relay_cell(&h);
        }
        let expired_sources: Vec<String> = self
            .source_routes
            .iter()
            .filter(|(_, r)| r.expires_at <= now_secs)
            .map(|(k, _)| k.clone())
            .collect();
        for h in expired_sources {
            self.remove_source_route(&h);
        }
        let expired_endpoints: Vec<String> = self
            .endpoint_routes
            .iter()
            .filter(|(_, r)| r.expires_at <= now_secs)
            .map(|(k, _)| k.clone())
            .collect();
        for h in expired_endpoints {
            self.remove_endpoint_route(&h);
        }
        self.seen_deliveries.retain(|_, exp| *exp > now_secs);
    }

    /// Returns the exact route facts observable by this node in its relay role.
    pub fn relay_knowledge(&mut self, now_secs: f64) -> Vec<RelayKnowledge> {
        self.cleanup(now_secs);
        self.relay_cells
            .values()
            .map(|c| RelayKnowledge {
                previous_peer: c.previous_peer.clone(),
                next_peer: c.next_peer.clone(),
                inbound_handle: c.inbound_handle.clone(),
                outbound_handle: c.outbound_handle.clone(),
                state: c.state.clone(),
            })
            .collect()
    }

    /// Returns current state counts for diagnostics and tests.
    pub fn local_counts(&mut self, now_secs: f64) -> CascadeCounts {
        self.cleanup(now_secs);
        CascadeCounts {
            relay_cells: self.relay_cells.len(),
            source_routes: self.source_routes.len(),
            endpoint_routes: self.endpoint_routes.len(),
            dedup_entries: self.seen_deliveries.len(),
        }
    }

    fn remove_relay_cell(&mut self, inbound_handle: &str) {
        if let Some(cell) = self.relay_cells.remove(inbound_handle) {
            if !cell.outbound_handle.is_empty() {
                self.relay_out_to_in.remove(&cell.outbound_handle);
            }
            for h in cell.probe_handles.values() {
                self.relay_out_to_in.remove(h);
            }
        }
    }

    fn remove_source_route(&mut self, handle: &str) {
        if let Some(route) = self.source_routes.remove(handle) {
            if self
                .source_by_remote
                .get(&route.remote_peer)
                .map(String::as_str)
                == Some(handle)
            {
                self.source_by_remote.remove(&route.remote_peer);
            }
        }
    }

    fn remove_endpoint_route(&mut self, handle: &str) {
        if let Some(route) = self.endpoint_routes.remove(handle) {
            if self
                .endpoint_by_remote
                .get(&route.remote_peer)
                .map(String::as_str)
                == Some(handle)
            {
                self.endpoint_by_remote.remove(&route.remote_peer);
            }
            if self
                .endpoint_by_tag
                .get(&route.route_tag)
                .map(String::as_str)
                == Some(handle)
            {
                self.endpoint_by_tag.remove(&route.route_tag);
            }
        }
    }
}
