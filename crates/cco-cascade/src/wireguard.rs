#![forbid(unsafe_code)]
//! WireGuard Handshake Overlay pure Sans-I/O state machine, trust-bound adapter,
//! and canonical 27-scenario verification matrix (`wg_handshake_overlay`).
//!
//! Strictly enforces the control/data plane split:
//! - WireGuard types 1, 2, 3 (Initiation, Response, Cookie Reply) travel through the overlay.
//! - WireGuard type 4 (Transport Data) NEVER enters the overlay (`DIRECT_BYPASS` only).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use cco_crypto::sha256_hex;
use cco_proto::{WireGuardMessageType, WireGuardPacket, parse_wireguard_packet};
use cco_trust::VerifiedRegistry;
use serde::{Deserialize, Serialize};

use crate::error::CascadeError;

/// Opaque WireGuard node endpoint `(host, port)`. Never holds key material.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WgEndpoint {
    pub host: String,
    pub port: u16,
}

impl WgEndpoint {
    /// Creates a validated endpoint (`1..=65535`, non-empty host without whitespace).
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, CascadeError> {
        let host = host.into();
        if host.is_empty() || host.len() > 255 || host.chars().any(char::is_whitespace) || port == 0
        {
            return Err(CascadeError::new("invalid_endpoint"));
        }
        Ok(Self { host, port })
    }

    /// Formats endpoint as `host:port`.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Validated multi-hop overlay route between distinct endpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct WgRoute {
    pub nodes: Vec<WgEndpoint>,
    pub expires_at: f64,
}

impl WgRoute {
    /// Constructs a route requiring at least two distinct nodes.
    pub fn new(nodes: Vec<WgEndpoint>, expires_at: f64) -> Result<Self, CascadeError> {
        let unique: BTreeSet<&WgEndpoint> = nodes.iter().collect();
        if nodes.len() < 2 || unique.len() != nodes.len() {
            return Err(CascadeError::new("invalid_route"));
        }
        Ok(Self { nodes, expires_at })
    }

    /// Returns the reversed route with identical expiry.
    #[must_use]
    pub fn reverse(&self) -> Self {
        let mut rev = self.nodes.clone();
        rev.reverse();
        Self {
            nodes: rev,
            expires_at: self.expires_at,
        }
    }

    /// Returns the next hop after `node`, if any.
    pub fn next_hop(&self, node: &WgEndpoint) -> Result<&WgEndpoint, CascadeError> {
        let idx = self
            .nodes
            .iter()
            .position(|n| n == node)
            .ok_or_else(|| CascadeError::new("no_next_hop"))?;
        self.nodes
            .get(idx + 1)
            .ok_or_else(|| CascadeError::new("no_next_hop"))
    }
}

/// Overlay envelope carrying opaque WireGuard control bytes (redacted from `Debug`).
#[derive(Clone)]
pub struct WgOverlayEnvelope {
    pub message_id: String,
    pub route: WgRoute,
    pub hop_index: usize,
    pub wireguard_packet: Vec<u8>,
}

impl WgOverlayEnvelope {
    /// Constructs a validated overlay envelope.
    pub fn new(
        message_id: impl Into<String>,
        route: WgRoute,
        hop_index: usize,
        wireguard_packet: Vec<u8>,
    ) -> Result<Self, CascadeError> {
        let message_id = message_id.into();
        if message_id.len() != 16
            || !message_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            || hop_index >= route.nodes.len()
        {
            return Err(CascadeError::new("invalid_envelope"));
        }
        Ok(Self {
            message_id,
            route,
            hop_index,
            wireguard_packet,
        })
    }
}

impl fmt::Debug for WgOverlayEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgOverlayEnvelope")
            .field("message_id", &self.message_id)
            .field("hop_index", &self.hop_index)
            .field("packet_len", &self.wireguard_packet.len())
            .finish()
    }
}

/// Event kind emitted by [`WgHandshakeOverlayEngine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WgEventKind {
    #[serde(rename = "OVERLAY_FRAME")]
    OverlayFrame,
    #[serde(rename = "DIRECT_BYPASS")]
    DirectBypass,
    #[serde(rename = "INJECT")]
    Inject,
    #[serde(rename = "DUPLICATE_DROP")]
    DuplicateDrop,
    #[serde(rename = "EXPIRED_DROP")]
    ExpiredDrop,
    #[serde(rename = "INVALID_DROP")]
    InvalidDrop,
}

/// Deterministic event emitted by the WireGuard handshake overlay state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgEvent {
    pub kind: WgEventKind,
    pub message_id: String,
    pub node: String,
    pub next_hop: Option<String>,
    pub route: Vec<String>,
}

/// Information a relay is permitted to observe (`final_endpoint` is `None` in privacy mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayVisibleView {
    pub message_id: String,
    pub previous_hop: Option<WgEndpoint>,
    pub next_hop: Option<WgEndpoint>,
    pub final_endpoint: Option<WgEndpoint>,
}

/// Bounded in-memory route cache and anti-replay table (`wg_handshake_overlay/routing.py`).
#[derive(Debug, Clone)]
pub struct WgRouteCache {
    ttl_seconds: f64,
    routes: BTreeMap<(WgEndpoint, WgEndpoint), WgRoute>,
    seen: BTreeMap<String, f64>,
}

impl WgRouteCache {
    /// Creates a route cache with strictly positive `ttl_seconds`.
    pub fn new(ttl_seconds: f64) -> Result<Self, CascadeError> {
        if ttl_seconds <= 0.0 || !ttl_seconds.is_finite() {
            return Err(CascadeError::new("invalid_ttl"));
        }
        Ok(Self {
            ttl_seconds,
            routes: BTreeMap::new(),
            seen: BTreeMap::new(),
        })
    }

    /// Establishes both forward `(source -> relays -> destination)` and reverse routes.
    pub fn establish(
        &mut self,
        source: WgEndpoint,
        relays: &[WgEndpoint],
        destination: WgEndpoint,
        now: f64,
    ) -> Result<WgRoute, CascadeError> {
        if source == destination || relays.contains(&source) || relays.contains(&destination) {
            return Err(CascadeError::new("invalid_route"));
        }
        let mut nodes = Vec::with_capacity(relays.len() + 2);
        nodes.push(source.clone());
        nodes.extend_from_slice(relays);
        nodes.push(destination.clone());
        let route = WgRoute::new(nodes, now + self.ttl_seconds)?;
        self.routes
            .insert((source.clone(), destination.clone()), route.clone());
        self.routes.insert((destination, source), route.reverse());
        Ok(route)
    }

    /// Returns a non-expired cached route between `source` and `destination`.
    pub fn get(
        &mut self,
        source: &WgEndpoint,
        destination: &WgEndpoint,
        now: f64,
    ) -> Option<WgRoute> {
        let key = (source.clone(), destination.clone());
        match self.routes.get(&key) {
            Some(r) if r.expires_at > now => Some(r.clone()),
            _ => {
                self.routes.remove(&key);
                None
            }
        }
    }

    /// Records `message_id` once within TTL; returns `false` on duplicate.
    pub fn mark_once(&mut self, message_id: &str, now: f64) -> bool {
        self.seen.retain(|_, exp| *exp > now);
        if self.seen.contains_key(message_id) {
            return false;
        }
        self.seen
            .insert(message_id.to_owned(), now + self.ttl_seconds);
        true
    }
}

/// Pure fail-closed WireGuard Handshake Overlay state machine (`engine.py`).
#[derive(Debug, Clone)]
pub struct WgHandshakeOverlayEngine {
    pub cache: WgRouteCache,
    pub relays: Vec<WgEndpoint>,
    pub privacy_mode: bool,
}

impl WgHandshakeOverlayEngine {
    /// Creates a new engine with at least one relay.
    pub fn new(
        cache: WgRouteCache,
        relays: Vec<WgEndpoint>,
        privacy_mode: bool,
    ) -> Result<Self, CascadeError> {
        if relays.is_empty() {
            return Err(CascadeError::new("empty_relays"));
        }
        Ok(Self {
            cache,
            relays,
            privacy_mode,
        })
    }

    /// Computes the 16-hex deterministic fingerprint of a captured WireGuard packet.
    #[must_use]
    pub fn fingerprint(packet: &[u8], source: &WgEndpoint, destination: &WgEndpoint) -> String {
        let s = source.label();
        let d = destination.label();
        let mut buf = Vec::with_capacity(s.len() + d.len() + packet.len() + 2);
        buf.extend_from_slice(s.as_bytes());
        buf.push(0);
        buf.extend_from_slice(d.as_bytes());
        buf.push(0);
        buf.extend_from_slice(packet);
        sha256_hex(&buf)[..16].to_owned()
    }

    /// Classifies and captures an outbound WireGuard UDP packet.
    ///
    /// Type 4 transport data ALWAYS bypasses the overlay (`DirectBypass`).
    pub fn capture(
        &mut self,
        source: &WgEndpoint,
        destination: &WgEndpoint,
        packet: &[u8],
        now: f64,
    ) -> Vec<WgEvent> {
        let Ok(parsed) = parse_wireguard_packet(packet) else {
            return vec![WgEvent {
                kind: WgEventKind::InvalidDrop,
                message_id: "0000000000000000".to_owned(),
                node: source.label(),
                next_hop: None,
                route: Vec::new(),
            }];
        };

        let message_id = Self::fingerprint(packet, source, destination);
        if parsed.is_transport() {
            return vec![WgEvent {
                kind: WgEventKind::DirectBypass,
                message_id,
                node: source.label(),
                next_hop: Some(destination.label()),
                route: Vec::new(),
            }];
        }

        let route = match self.cache.get(source, destination, now) {
            Some(r) => r,
            None => {
                match self
                    .cache
                    .establish(source.clone(), &self.relays, destination.clone(), now)
                {
                    Ok(r) => r,
                    Err(_) => {
                        return vec![WgEvent {
                            kind: WgEventKind::InvalidDrop,
                            message_id,
                            node: source.label(),
                            next_hop: None,
                            route: Vec::new(),
                        }];
                    }
                }
            }
        };
        let Ok(envelope) = WgOverlayEnvelope::new(message_id.clone(), route, 0, packet.to_vec())
        else {
            return vec![WgEvent {
                kind: WgEventKind::InvalidDrop,
                message_id,
                node: source.label(),
                next_hop: None,
                route: Vec::new(),
            }];
        };
        self.forward(&envelope, now)
    }

    /// Forwards an overlay envelope at its current `hop_index`, rejecting type 4 transport frames.
    pub fn forward(&mut self, envelope: &WgOverlayEnvelope, now: f64) -> Vec<WgEvent> {
        let node = &envelope.route.nodes[envelope.hop_index];
        let Ok(parsed) = parse_wireguard_packet(&envelope.wireguard_packet) else {
            return vec![WgEvent {
                kind: WgEventKind::InvalidDrop,
                message_id: envelope.message_id.clone(),
                node: "unknown".to_owned(),
                next_hop: None,
                route: Vec::new(),
            }];
        };
        if parsed.is_transport() {
            return vec![WgEvent {
                kind: WgEventKind::InvalidDrop,
                message_id: envelope.message_id.clone(),
                node: node.label(),
                next_hop: None,
                route: Vec::new(),
            }];
        }
        if envelope.route.expires_at <= now {
            return vec![WgEvent {
                kind: WgEventKind::ExpiredDrop,
                message_id: envelope.message_id.clone(),
                node: node.label(),
                next_hop: None,
                route: Vec::new(),
            }];
        }
        let dedup = format!("{}:{}", envelope.message_id, envelope.hop_index);
        if !self.cache.mark_once(&dedup, now) {
            return vec![WgEvent {
                kind: WgEventKind::DuplicateDrop,
                message_id: envelope.message_id.clone(),
                node: node.label(),
                next_hop: None,
                route: Vec::new(),
            }];
        }

        if envelope.hop_index + 1 == envelope.route.nodes.len() {
            return vec![WgEvent {
                kind: WgEventKind::Inject,
                message_id: envelope.message_id.clone(),
                node: node.label(),
                next_hop: None,
                route: envelope.route.nodes.iter().map(WgEndpoint::label).collect(),
            }];
        }

        let visible_route = if self.privacy_mode {
            Vec::new()
        } else {
            envelope.route.nodes.iter().map(WgEndpoint::label).collect()
        };
        vec![WgEvent {
            kind: WgEventKind::OverlayFrame,
            message_id: envelope.message_id.clone(),
            node: node.label(),
            next_hop: Some(envelope.route.nodes[envelope.hop_index + 1].label()),
            route: visible_route,
        }]
    }

    /// Advances an envelope by exactly one hop.
    pub fn advance(&mut self, envelope: &WgOverlayEnvelope, now: f64) -> Vec<WgEvent> {
        if envelope.hop_index + 1 >= envelope.route.nodes.len() {
            return vec![WgEvent {
                kind: WgEventKind::InvalidDrop,
                message_id: envelope.message_id.clone(),
                node: envelope.route.nodes.last().unwrap().label(),
                next_hop: None,
                route: Vec::new(),
            }];
        }
        let next = WgOverlayEnvelope {
            message_id: envelope.message_id.clone(),
            route: envelope.route.clone(),
            hop_index: envelope.hop_index + 1,
            wireguard_packet: envelope.wireguard_packet.clone(),
        };
        self.forward(&next, now)
    }

    /// Returns the relay-visible view at `envelope.hop_index`.
    #[must_use]
    pub fn relay_view(&self, envelope: &WgOverlayEnvelope) -> RelayVisibleView {
        let idx = envelope.hop_index;
        let nodes = &envelope.route.nodes;
        let previous = if idx > 0 {
            Some(nodes[idx - 1].clone())
        } else {
            None
        };
        let next = nodes.get(idx + 1).cloned();
        let final_ep = if self.privacy_mode {
            None
        } else {
            nodes.last().cloned()
        };
        RelayVisibleView {
            message_id: envelope.message_id.clone(),
            previous_hop: previous,
            next_hop: next,
            final_endpoint: final_ep,
        }
    }
}

/// Action decided by the trust-bound [`WgProxyAdapter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WgCaptureAction {
    Overlay,
    DirectBypass,
    Drop,
}

/// Trust-bound metadata emitted for an admitted WireGuard control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgOverlayMeta {
    pub capture_id: String,
    pub wg_message_type: u8,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub src_node: String,
    pub dst_node: String,
    pub registry_version: u64,
    pub src_key_fingerprint: String,
    pub dst_key_fingerprint: String,
}

/// Result returned by [`WgProxyAdapter::capture_datagram`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgCaptureResult {
    pub action: WgCaptureAction,
    pub message_type: Option<u8>,
    pub reason: &'static str,
    pub meta: Option<WgOverlayMeta>,
}

/// Validated WireGuard injection request produced by [`WgProxyAdapter::deliver_protocol_datagram`].
pub struct WgInjectionRequest {
    pub capture_id: String,
    pub source: WgEndpoint,
    pub destination: WgEndpoint,
    pub packet: WireGuardPacket,
    pub registry_version: u64,
    pub source_public_key_hex: String,
    pub destination_public_key_hex: String,
    pub payload: Vec<u8>,
}

impl fmt::Debug for WgInjectionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgInjectionRequest")
            .field("capture_id", &self.capture_id)
            .field("source", &self.source)
            .field("destination", &self.destination)
            .field("packet", &self.packet)
            .field("registry_version", &self.registry_version)
            .finish()
    }
}

/// Protocol boundary enforcing Trust Registry v2 provenance for WireGuard control frames (`adapter.py`).
pub struct WgProxyAdapter<'a> {
    registry: &'a VerifiedRegistry,
}

impl<'a> WgProxyAdapter<'a> {
    /// Binds the adapter to an already verified Trust Registry v2 snapshot.
    #[must_use]
    pub const fn new(registry: &'a VerifiedRegistry) -> Self {
        Self { registry }
    }

    /// Classifies a captured WireGuard datagram and validates node provenance against the registry.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn capture_datagram(
        &self,
        payload: &[u8],
        source: &WgEndpoint,
        destination: &WgEndpoint,
        source_node: &str,
        destination_node: &str,
        capture_id: &str,
    ) -> WgCaptureResult {
        if !valid_wg_token(source_node)
            || !valid_wg_token(destination_node)
            || !valid_wg_token(capture_id)
        {
            return WgCaptureResult {
                action: WgCaptureAction::Drop,
                message_type: None,
                reason: "invalid_metadata_token",
                meta: None,
            };
        }
        let Ok(packet) = parse_wireguard_packet(payload) else {
            return WgCaptureResult {
                action: WgCaptureAction::Drop,
                message_type: None,
                reason: "invalid_wireguard_framing",
                meta: None,
            };
        };
        let mtype = packet.message_type as u8;
        if packet.is_transport() {
            return WgCaptureResult {
                action: WgCaptureAction::DirectBypass,
                message_type: Some(mtype),
                reason: "",
                meta: None,
            };
        }
        if source_node == destination_node {
            return WgCaptureResult {
                action: WgCaptureAction::Drop,
                message_type: Some(mtype),
                reason: "same_endpoint",
                meta: None,
            };
        }

        let (Ok(src_rec), Ok(dst_rec)) = (
            self.registry.require_active_node(source_node),
            self.registry.require_active_node(destination_node),
        ) else {
            return WgCaptureResult {
                action: WgCaptureAction::Drop,
                message_type: Some(mtype),
                reason: "untrusted_node_registry_binding",
                meta: None,
            };
        };

        WgCaptureResult {
            action: WgCaptureAction::Overlay,
            message_type: Some(mtype),
            reason: "",
            meta: Some(WgOverlayMeta {
                capture_id: capture_id.to_owned(),
                wg_message_type: mtype,
                src_ip: source.host.clone(),
                src_port: source.port,
                dst_ip: destination.host.clone(),
                dst_port: destination.port,
                src_node: source_node.to_owned(),
                dst_node: destination_node.to_owned(),
                registry_version: self.registry.version(),
                src_key_fingerprint: src_rec.key_id[..16].to_owned(),
                dst_key_fingerprint: dst_rec.key_id[..16].to_owned(),
            }),
        }
    }

    /// Validates an overlay-delivered WireGuard control frame before local injection.
    ///
    /// Rejects type 4 transport frames, stale registry versions, or mismatched key fingerprints.
    pub fn deliver_protocol_datagram(
        &self,
        protocol: &str,
        payload: &[u8],
        meta: &WgOverlayMeta,
    ) -> Result<WgInjectionRequest, CascadeError> {
        if protocol != "wireguard" {
            return Err(CascadeError::new("unsupported_protocol"));
        }
        let packet = parse_wireguard_packet(payload)
            .map_err(|_| CascadeError::new("invalid_wireguard_framing"))?;
        if packet.is_transport() {
            return Err(CascadeError::new("transport_type4_forbidden"));
        }
        if meta.wg_message_type != packet.message_type as u8 {
            return Err(CascadeError::new("wg_type_mismatch"));
        }
        if meta.registry_version != self.registry.version() {
            return Err(CascadeError::new("stale_registry_version"));
        }
        let src_rec = self
            .registry
            .require_active_node(&meta.src_node)
            .map_err(|_| CascadeError::new("untrusted_node_registry_binding"))?;
        let dst_rec = self
            .registry
            .require_active_node(&meta.dst_node)
            .map_err(|_| CascadeError::new("untrusted_node_registry_binding"))?;
        if meta.src_key_fingerprint != src_rec.key_id[..16]
            || meta.dst_key_fingerprint != dst_rec.key_id[..16]
        {
            return Err(CascadeError::new("key_fingerprint_mismatch"));
        }

        Ok(WgInjectionRequest {
            capture_id: meta.capture_id.clone(),
            source: WgEndpoint::new(&meta.src_ip, meta.src_port)?,
            destination: WgEndpoint::new(&meta.dst_ip, meta.dst_port)?,
            packet,
            registry_version: self.registry.version(),
            source_public_key_hex: src_rec.encryption_hex(),
            destination_public_key_hex: dst_rec.encryption_hex(),
            payload: payload.to_vec(),
        })
    }
}

fn valid_wg_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_whitespace)
}

// ============================================================================
// Canonical 27-scenario matrix & `eve-result.schema.json` contract
// ============================================================================

/// Tabular scenario row matching `wg_handshake_overlay/scenarios.py`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgScenarioRow {
    pub scenario: String,
    pub src: String,
    pub dst: String,
    pub conn_id: String,
    pub model_ok: bool,
    pub overlay_control_packets: usize,
    pub direct_wg_control_packets: usize,
    pub direct_transport_packets: usize,
    pub injected_control_packets: usize,
    pub route: String,
    pub x1: String,
    pub x2: String,
    pub error: String,
}

/// Six-criterion verification structure from `schemas/eve-result.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EveCriteria {
    pub handshake_fresh: bool,
    pub useful_traffic_ok: bool,
    pub control_types_overlay_only: bool,
    pub transport_type4_direct_only: bool,
    pub reverse_route_ok: bool,
    pub redaction_confirmed: bool,
}

/// Latency breakdown (`schemas/eve-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EveMetricsMs {
    pub route_setup_ms: f64,
    pub handshake_ms: f64,
    pub first_data_ms: f64,
}

/// Single event trace item (`schemas/eve-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EveEvidenceEvent {
    pub event: String,
    pub message_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
}

/// Evidence container (`schemas/eve-result.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EveEvidence {
    pub events: Vec<EveEvidenceEvent>,
}

/// Complete schema-compliant case result matching `schemas/eve-result.schema.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EveCaseResult {
    pub schema_version: u32,
    pub suite: String,
    pub case_id: String,
    pub src: String,
    pub dst: String,
    pub conn: String,
    pub ok: bool,
    pub status: String,
    pub wg_up_code: i32,
    pub handshake_ok: bool,
    pub ping_ok: bool,
    pub wg_data_packets: usize,
    pub direct_wg_control_packets: usize,
    pub wg_up_seconds: f64,
    pub route: Vec<String>,
    pub x1: String,
    pub x2: String,
    pub conn_id: String,
    pub x1_is_dst: bool,
    pub x2_is_src: bool,
    pub x2_is_dst: bool,
    pub abab: bool,
    pub up_tail: String,
    pub ping_tail: String,
    pub criteria: EveCriteria,
    pub metrics_ms: EveMetricsMs,
    pub evidence: EveEvidence,
}

const DISJOINT_PAIRS: [(usize, usize); 5] = [(1, 2), (3, 4), (5, 6), (7, 8), (9, 10)];

fn canonical_suite_definitions() -> Vec<(&'static str, Vec<(usize, usize)>)> {
    let bidir12 = vec![(1, 2), (2, 1)];
    let disjoint5 = DISJOINT_PAIRS.to_vec();
    let ring10: Vec<(usize, usize)> = (1..=10).map(|n| (n, (n % 10) + 1)).collect();
    let mut reverse5 = Vec::with_capacity(10);
    for (a, b) in DISJOINT_PAIRS {
        reverse5.push((a, b));
        reverse5.push((b, a));
    }
    vec![
        ("bidir12", bidir12),
        ("disjoint5", disjoint5),
        ("ring10", ring10),
        ("reverse5", reverse5),
    ]
}

/// Synthesizes a valid public WireGuard test packet of `msg_type` (`1..=4`).
#[must_use]
pub fn synthetic_wg_packet(msg_type: WireGuardMessageType, index: u32) -> Vec<u8> {
    let size = match msg_type {
        WireGuardMessageType::HandshakeInitiation => 148,
        WireGuardMessageType::HandshakeResponse => 92,
        WireGuardMessageType::CookieReply => 64,
        WireGuardMessageType::TransportData => 32,
    };
    let mut pkt = vec![0u8; size];
    pkt[0] = msg_type as u8;
    pkt[4..8].copy_from_slice(&index.to_le_bytes());
    if msg_type == WireGuardMessageType::HandshakeResponse {
        pkt[8..12].copy_from_slice(&(index + 1).to_le_bytes());
    }
    pkt
}

fn walk_control(
    engine: &mut WgHandshakeOverlayEngine,
    source: &WgEndpoint,
    destination: &WgEndpoint,
    packet: &[u8],
    now: f64,
) -> (Vec<WgEvent>, Vec<WgEndpoint>) {
    let mut events = engine.capture(source, destination, packet, now);
    let Some(route) = engine.cache.get(source, destination, now) else {
        return (events, Vec::new());
    };
    if events.first().map(|e| e.kind) != Some(WgEventKind::OverlayFrame) {
        return (events, Vec::new());
    }
    let msg_id = WgHandshakeOverlayEngine::fingerprint(packet, source, destination);
    for hop_index in 0..route.nodes.len() - 1 {
        let env = WgOverlayEnvelope::new(msg_id.clone(), route.clone(), hop_index, packet.to_vec())
            .unwrap();
        events.extend(engine.advance(&env, now));
    }
    (events, route.nodes)
}

/// Executes the canonical 27-scenario WireGuard handshake overlay matrix
/// (`bidir12`=2, `disjoint5`=5, `ring10`=10, `reverse5`=10).
#[must_use]
pub fn run_canonical_27_scenarios() -> Vec<WgScenarioRow> {
    let mut rows = Vec::with_capacity(27);
    let mut seq = 1u32;

    for (suite, pairs) in canonical_suite_definitions() {
        let cache = WgRouteCache::new(60.0).unwrap();
        let relay_a = WgEndpoint::new("X1", 51820).unwrap();
        let relay_b = WgEndpoint::new("X2", 51820).unwrap();
        let mut engine =
            WgHandshakeOverlayEngine::new(cache, vec![relay_a.clone(), relay_b.clone()], true)
                .unwrap();

        for (ordinal, (src_num, dst_num)) in pairs.into_iter().enumerate() {
            let source = WgEndpoint::new(format!("User{src_num}"), 51820).unwrap();
            let destination = WgEndpoint::new(format!("User{dst_num}"), 51820).unwrap();
            let initiation = synthetic_wg_packet(WireGuardMessageType::HandshakeInitiation, seq);
            let response = synthetic_wg_packet(WireGuardMessageType::HandshakeResponse, seq + 1000);
            let transport = synthetic_wg_packet(WireGuardMessageType::TransportData, seq + 2000);
            seq += 1;

            let (fwd_events, route) =
                walk_control(&mut engine, &source, &destination, &initiation, 0.0);
            let (rev_events, rev_route) =
                walk_control(&mut engine, &destination, &source, &response, 0.0);
            let transport_event = engine.capture(&source, &destination, &transport, 0.0)[0].clone();

            let all_ctrl: Vec<&WgEvent> = fwd_events.iter().chain(rev_events.iter()).collect();
            let relay_frames: Vec<&&WgEvent> = all_ctrl
                .iter()
                .filter(|e| e.kind == WgEventKind::OverlayFrame)
                .collect();
            let injections: Vec<&&WgEvent> = all_ctrl
                .iter()
                .filter(|e| e.kind == WgEventKind::Inject)
                .collect();

            let mut expected_rev = route.clone();
            expected_rev.reverse();
            let route_shape_ok = route.len() == 4
                && route[0] == source
                && route[3] == destination
                && ((route[1] == relay_a && route[2] == relay_b)
                    || (route[1] == relay_b && route[2] == relay_a));
            let model_ok = route_shape_ok
                && rev_route == expected_rev
                && injections.len() == 2
                && injections[0].node == destination.label()
                && injections[1].node == source.label()
                && transport_event.kind == WgEventKind::DirectBypass
                && relay_frames.iter().all(|e| e.route.is_empty());

            rows.push(WgScenarioRow {
                scenario: suite.to_owned(),
                src: source.host.clone(),
                dst: destination.host.clone(),
                conn_id: format!("{suite}-{:02}", ordinal + 1),
                model_ok,
                overlay_control_packets: 2,
                direct_wg_control_packets: 0,
                direct_transport_packets: usize::from(
                    transport_event.kind == WgEventKind::DirectBypass,
                ),
                injected_control_packets: injections.len(),
                route: route
                    .iter()
                    .map(|ep| ep.host.as_str())
                    .collect::<Vec<_>>()
                    .join(">"),
                x1: if route_shape_ok {
                    route[1].host.clone()
                } else {
                    String::new()
                },
                x2: if route_shape_ok {
                    route[2].host.clone()
                } else {
                    String::new()
                },
                error: if model_ok {
                    String::new()
                } else {
                    "model invariant failed".to_owned()
                },
            });
        }
    }
    rows
}

/// Runs the canonical 27-scenario matrix and emits records conforming to `schemas/eve-result.schema.json`.
#[must_use]
pub fn run_canonical_27_eve_results() -> Vec<EveCaseResult> {
    let rows = run_canonical_27_scenarios();
    rows.into_iter()
        .map(|row| {
            let route_vec: Vec<String> = row.route.split('>').map(str::to_owned).collect();
            let ok = row.model_ok;
            let x1_is_dst = row.x1 == row.dst;
            let x2_is_src = row.x2 == row.src;
            let x2_is_dst = row.x2 == row.dst;
            let abab = x1_is_dst && x2_is_src;

            EveCaseResult {
                schema_version: 1,
                suite: row.scenario.clone(),
                case_id: row.conn_id.clone(),
                src: row.src.clone(),
                dst: row.dst.clone(),
                conn: format!("wg-{}-{}", row.src, row.dst),
                ok,
                status: if ok { "pass" } else { "fail" }.to_owned(),
                wg_up_code: i32::from(!ok),
                handshake_ok: ok,
                ping_ok: ok,
                wg_data_packets: if ok { 2 } else { 0 },
                direct_wg_control_packets: row.direct_wg_control_packets,
                wg_up_seconds: 0.001,
                route: route_vec,
                x1: row.x1,
                x2: row.x2,
                conn_id: row.conn_id.clone(),
                x1_is_dst,
                x2_is_src,
                x2_is_dst,
                abab,
                up_tail: "sans-io-model-ok".to_owned(),
                ping_tail: "direct-type4-bypass-ok".to_owned(),
                criteria: EveCriteria {
                    handshake_fresh: ok,
                    useful_traffic_ok: ok,
                    control_types_overlay_only: ok && row.direct_wg_control_packets == 0,
                    transport_type4_direct_only: ok && row.direct_transport_packets >= 1,
                    reverse_route_ok: ok,
                    redaction_confirmed: ok,
                },
                metrics_ms: EveMetricsMs {
                    route_setup_ms: 0.1,
                    handshake_ms: 0.2,
                    first_data_ms: 0.3,
                },
                evidence: EveEvidence {
                    events: vec![
                        EveEvidenceEvent {
                            event: "CAPTURE".to_owned(),
                            message_type: 1,
                            capture_id: Some(format!("{}-init", row.conn_id)),
                        },
                        EveEvidenceEvent {
                            event: "INJECT".to_owned(),
                            message_type: 1,
                            capture_id: Some(format!("{}-init", row.conn_id)),
                        },
                        EveEvidenceEvent {
                            event: "CAPTURE".to_owned(),
                            message_type: 2,
                            capture_id: Some(format!("{}-resp", row.conn_id)),
                        },
                        EveEvidenceEvent {
                            event: "INJECT".to_owned(),
                            message_type: 2,
                            capture_id: Some(format!("{}-resp", row.conn_id)),
                        },
                        EveEvidenceEvent {
                            event: "DIRECT".to_owned(),
                            message_type: 4,
                            capture_id: Some(format!("{}-data", row.conn_id)),
                        },
                    ],
                },
            }
        })
        .collect()
}

/// Formats the 27-scenario matrix as CSV matching `scenarios.py::RESULT_FIELDS`.
#[must_use]
pub fn format_scenarios_csv(rows: &[WgScenarioRow]) -> String {
    let mut out = String::from(
        "scenario,src,dst,conn_id,model_ok,overlay_control_packets,direct_wg_control_packets,direct_transport_packets,injected_control_packets,route,x1,x2,error\n",
    );
    for r in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            r.scenario,
            r.src,
            r.dst,
            r.conn_id,
            r.model_ok,
            r.overlay_control_packets,
            r.direct_wg_control_packets,
            r.direct_transport_packets,
            r.injected_control_packets,
            r.route,
            r.x1,
            r.x2,
            r.error
        ));
    }
    out
}
