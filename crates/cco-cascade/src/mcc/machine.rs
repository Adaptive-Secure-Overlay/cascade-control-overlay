#![forbid(unsafe_code)]
//! Pure Sans-I/O MCC Authenticated + Opaque Privacy state machine (`mcc_auth.py` + `mcc_privacy.py`).
//!
//! Performs zero socket I/O and uses explicit caller-provided timestamps (`now_ms: u64`).
//! Every ingress event returns deterministic [`MccAction`] values for the transport/proxy shell.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use cco_crypto::{
    Key256, MccCapsulePurpose, X25519PublicKey, X25519SecretKey, aes256_gcm_decrypt,
    aes256_gcm_encrypt, decode_canonical_hex, derive_mcc_forward_key, derive_priv_b_a_key,
    mcc_a_b_fwd_aad, priv_b_a_aad, random_bytes, sha256_hex,
};
use cco_proto::{
    CanonicalValue, MessageType, WireGuardMessageType, canonical_bytes_from_value, jdump, jload,
    parse_ikev2_packet, parse_strict_json_object, parse_wireguard_packet_rfc,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::CascadeError;
use crate::mcc::proof::{
    DeliveredIkeMeta, DeliveryReceipt, IkeInjectionOutcome, LocalDeliveryProof,
};
use crate::mcc::security::{
    AdmitStatus, CapsuleV2, EndpointSecurity, MAX_COPIES, VerifiedMessage,
    decode_canonical_base64_ct, encode_canonical_base64_ct,
};
use crate::mcc::selection::{SelectionMode, SelectionPolicy};

/// Maximum active MCC exchanges/sessions per node (`mcc_auth.py::MAX_ACTIVE`).
pub const MAX_ACTIVE: usize = 256;

/// Maximum IKE requests per authenticated continuation context (`mcc_auth.py::MAX_REQUESTS`).
pub const MAX_REQUESTS: usize = 128;

/// Maximum raw IKEv2 datagram size accepted into MCC (`mcc_auth.py::MAX_IKE`).
pub const MAX_IKE: usize = 8192;

/// Maximum candidate delivery attempts on pre-send refusal (`mcc_auth.py::MAX_ATTEMPTS`).
pub const MAX_ATTEMPTS: usize = 3;

/// Maximum JSON plaintext accepted from hop envelopes (`mcc_auth.py::MAX_PLAINTEXT`).
pub const MAX_PLAINTEXT: usize = 65_507;

/// Route TTL in milliseconds (`120s`).
pub const ROUTE_TTL_MS: u64 = 120_000;

/// Canonical UDP port marker for WireGuard control-plane handshakes (`type 1/2/3`)
/// transported through the authenticated MCC overlay (`type 4` is strictly forbidden).
pub const WG_OVERLAY_CONTROL_PORT: u16 = 51820;

/// Fanout budget `(x1_fanout, x2_fanout, ike_fanout)` for MCC cascade start copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MccFanout {
    pub x1: usize,
    pub x2: usize,
    pub ike: usize,
}

impl MccFanout {
    /// Total expected equivalent start copies (`x1 * x2 * ike`).
    #[must_use]
    pub const fn expected_copies(self) -> usize {
        self.x1 * self.x2 * self.ike
    }
}

impl Default for MccFanout {
    fn default() -> Self {
        Self {
            x1: 3,
            x2: 3,
            ike: 1,
        }
    }
}

/// Configuration for one MCC node state machine.
#[derive(Debug, Clone)]
pub struct MccNodeConfig {
    /// Ordered directory of active peer names and their underlay IPv4 addresses.
    pub peers: BTreeMap<String, Ipv4Addr>,
    /// Fanout budget when acting as initiator `A`.
    pub fanout: MccFanout,
    /// Selection policy enforced on receiver `B` and signed by initiator `A`.
    pub policy: SelectionPolicy,
    /// Optional deterministic RNG seed for reproducible tests (`None` uses OS entropy).
    pub deterministic_seed: Option<u64>,
}

/// Output actions emitted by the Sans-I/O [`MccNodeMachine`].
#[derive(Debug)]
pub enum MccAction {
    /// Send a hop-encrypted wire message to adjacent `peer`.
    Send {
        peer: String,
        message_type: MessageType,
        payload: Vec<u8>,
    },
    /// Deliver an authenticated IKEv2 datagram to the local IKE daemon using a single-use proof.
    DeliverIke { proof: Box<LocalDeliveryProof> },
    /// Log-safe security rejection with stable reason code.
    Reject { code: &'static str },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MccStartBranch {
    conn_id: String,
    branch_id: String,
    x2: String,
    x2_slot: usize,
    ike_copy: usize,
    capsule: CapsuleV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MccStartMsg {
    auth_mcc: i64,
    opaque_mcc: i64,
    mcc_carry_ike: bool,
    mcc_session_id: String,
    req: String,
    x1: String,
    x1_index: usize,
    x1_fanout: usize,
    x2_fanout: usize,
    ike_fanout: usize,
    total_possible: usize,
    ike_len: usize,
    expires_at: i64,
    branches: Vec<MccStartBranch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MccX2Msg {
    auth_mcc: i64,
    opaque_mcc: i64,
    conn_id: String,
    total_possible: usize,
    capsule: CapsuleV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MccOfferMsg {
    auth_mcc: i64,
    opaque_mcc: i64,
    mcc_session_id: String,
    conn_id: String,
    branch_id: String,
    dst: String,
    x2: String,
    ab_context: String,
    total_possible: usize,
    inline: bool,
    mcc_carry_ike: bool,
    sealed_b: CapsuleV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReverseSealV2 {
    mode: String,
    auth_mcc: i64,
    v: i64,
    conn_id: String,
    bke: String,
    nonce: String,
    ct: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ForwardSealV2 {
    v: i64,
    context: String,
    nonce: String,
    ct: String,
    key_tag: String,
}

struct InitiatorContext {
    dst: String,
    priv_key: X25519SecretKey,
    pub_hex: String,
    initiator_spi: [u8; 8],
    first_request: ([u8; 8], u8, u32),
    first_hops: BTreeSet<String>,
    auth_requests: BTreeMap<String, String>, // msg_id -> sha256(payload)
    forward_key: Option<Key256>,
    created_at_ms: u64,
    initial_messages: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone)]
struct InitiatorRoute {
    context: String,
    dst: String,
    x1: String,
    opaque_token: String,
    created_at_ms: u64,
}

#[derive(Debug, Clone)]
struct X1Selection {
    req: String,
    selected: Vec<String>,
    expires_at_ms: u64,
}

#[derive(Debug, Clone)]
struct X1BranchState {
    req: String,
    x2: String,
    context: String,
    opaque_token: Option<String>,
    created_at_ms: u64,
}

#[derive(Debug, Clone)]
struct X1OpaqueHandle {
    context: String,
    conn_id: String,
    req: String,
    x2: String,
    created_at_ms: u64,
}

#[derive(Debug, Clone)]
struct X2BranchState {
    x1: String,
    dst: String,
    context: String,
    created_at_ms: u64,
}

struct PendingOffer {
    verified: VerifiedMessage,
    peer: String,
    payload: Vec<u8>,
    conn_id: String,
    a_pub: String,
    ike_src_ip: String,
    ike_src_port: u16,
    ike_dst_ip: String,
    ike_dst_port: u16,
    udp_port: u16,
    request_digest: String,
}

struct PendingSelection {
    sender: String,
    expected: usize,
    expires_s: i64,
    deadline_ms: u64,
    quiet_deadline_ms: Option<u64>,
    attempts: usize,
    closed: bool,
    selected: bool,
    offers: Vec<PendingOffer>,
}

#[derive(Debug, Clone)]
struct CachedResponse {
    payload: Vec<u8>,
    src_ip: String,
    dst_ip: String,
    udp_port: u16,
}

struct ResponderSession {
    conn_id: String,
    peer_x2: String,
    src: String,
    a_pub: String,
    bke: String,
    back_key: Key256,
    forward_key: Key256,
    initiator_spi: [u8; 8],
    selected_copy: usize,
    created_at_ms: u64,
    expires_s: i64,
    requests: BTreeMap<String, String>,
    responses: BTreeMap<String, CachedResponse>,
}

struct InFlightDelivery {
    verified: VerifiedMessage,
    is_initial: bool,
    direction_forward: bool,
    sender: String,
    context: String,
    prev_initiator_route: Option<(String, [u8; 8], Option<InitiatorRoute>)>,
}

/// Pure Sans-I/O MCC Authenticated & Opaque Privacy node state machine.
pub struct MccNodeMachine {
    security: EndpointSecurity,
    config: MccNodeConfig,
    rng_state: u64,

    // Initiator A state
    ab_contexts: BTreeMap<String, InitiatorContext>,
    pending_by_digest: BTreeMap<String, (String, u64)>,
    a_routes: BTreeMap<(String, [u8; 8]), InitiatorRoute>,

    // Relay X1 state
    x1_selections: BTreeMap<(String, String), X1Selection>,
    x1_branches: BTreeMap<String, X1BranchState>,
    x1_handles: BTreeMap<String, X1OpaqueHandle>,

    // Relay X2 state
    x2_branches: BTreeMap<String, X2BranchState>,

    // Receiver B state
    b_pending: BTreeMap<String, PendingSelection>,
    b_sessions: BTreeMap<(String, String), ResponderSession>,

    // Active in-flight delivery reservations awaiting complete_delivery()
    inflight: BTreeMap<(String, usize), InFlightDelivery>,
}

impl MccNodeMachine {
    /// Creates a new Sans-I/O MCC node state machine after validating policy and peer directory.
    pub fn new(security: EndpointSecurity, config: MccNodeConfig) -> Result<Self, CascadeError> {
        config.policy.validate()?;
        if !config.peers.contains_key(security.name()) {
            return Err(CascadeError::new("unknown_node"));
        }
        let seed = config
            .deterministic_seed
            .unwrap_or_else(|| u64::from_le_bytes(random_bytes::<8>()));
        Ok(Self {
            security,
            config,
            rng_state: seed.max(1),
            ab_contexts: BTreeMap::new(),
            pending_by_digest: BTreeMap::new(),
            a_routes: BTreeMap::new(),
            x1_selections: BTreeMap::new(),
            x1_branches: BTreeMap::new(),
            x1_handles: BTreeMap::new(),
            x2_branches: BTreeMap::new(),
            b_pending: BTreeMap::new(),
            b_sessions: BTreeMap::new(),
            inflight: BTreeMap::new(),
        })
    }

    /// Borrows this node's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.security.name()
    }

    /// Borrows the underlying [`EndpointSecurity`] and ledger.
    #[must_use]
    pub fn security(&self) -> &EndpointSecurity {
        &self.security
    }

    /// Returns the number of currently pending receiver-side selection buckets.
    #[must_use]
    pub fn pending_selection_count(&self) -> usize {
        self.b_pending.len()
    }

    /// Returns the number of active authenticated receiver-side sessions.
    #[must_use]
    pub fn responder_session_count(&self) -> usize {
        self.b_sessions.len()
    }

    /// Returns the initiator's opaque route token for `(dst, initiator_spi)`, if established.
    ///
    /// Notice that initiator `A` NEVER learns `X2` — only `(x1, opaque_token, context)`.
    #[must_use]
    pub fn initiator_route_summary(
        &self,
        dst: &str,
        initiator_spi: [u8; 8],
    ) -> Option<(String, String, String)> {
        self.a_routes
            .get(&(dst.to_owned(), initiator_spi))
            .map(|r| (r.x1.clone(), r.opaque_token.clone(), r.context.clone()))
    }

    /// Returns candidate offer count for a pending message key (for telemetry/tests).
    #[must_use]
    pub fn total_pending_candidates(&self) -> usize {
        self.b_pending.values().map(|s| s.offers.len()).sum()
    }

    fn next_rand_usize(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        if self.config.deterministic_seed.is_some() {
            // xorshift64* for deterministic test reproducibility
            let mut x = self.rng_state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.rng_state = x;
            (x.wrapping_mul(0x2545_F491_4F6C_DD1D) as usize) % upper
        } else {
            rand::thread_rng().gen_range(0..upper)
        }
    }

    fn pick_candidates(&mut self, pool: &[String], count: usize) -> Vec<String> {
        let mut items = pool.to_vec();
        let take = count.min(items.len());
        for i in 0..take {
            let j = i + self.next_rand_usize(items.len() - i);
            items.swap(i, j);
        }
        items.truncate(take);
        items
    }

    fn prune(&mut self, now_ms: u64) {
        let now_s = (now_ms / 1000) as i64;
        self.x1_selections.retain(|_, s| s.expires_at_ms >= now_ms);
        self.x1_branches
            .retain(|_, b| now_ms.saturating_sub(b.created_at_ms) <= ROUTE_TTL_MS);
        self.x1_handles
            .retain(|_, h| now_ms.saturating_sub(h.created_at_ms) <= ROUTE_TTL_MS);
        self.x2_branches
            .retain(|_, b| now_ms.saturating_sub(b.created_at_ms) <= ROUTE_TTL_MS);
        self.a_routes
            .retain(|_, r| now_ms.saturating_sub(r.created_at_ms) <= ROUTE_TTL_MS);
        self.ab_contexts
            .retain(|_, c| now_ms.saturating_sub(c.created_at_ms) <= ROUTE_TTL_MS);
        self.pending_by_digest.retain(|_, (_, created)| {
            now_ms.saturating_sub(*created) <= self.config.policy.deadline_ms
        });
        self.b_sessions.retain(|_, s| s.expires_s + 5 >= now_s);
        self.b_pending.retain(|_, s| s.expires_s + 5 >= now_s);
    }

    /// Initiates or continues an IKEv2 exchange from local node (`A` -> `dst`, or response `B` -> `dst`).
    pub fn send_local_ike(
        &mut self,
        dst_user: &str,
        payload: &[u8],
        udp_port: u16,
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        self.prune(now_ms);
        let dst_ip = *self
            .config
            .peers
            .get(dst_user)
            .ok_or_else(|| CascadeError::new("invalid_destination"))?;
        let src_ip = *self
            .config
            .peers
            .get(self.security.name())
            .ok_or_else(|| CascadeError::new("unknown_node"))?;
        if dst_user == self.security.name() {
            return Err(CascadeError::new("invalid_destination"));
        }
        if payload.len() < 28 || payload.len() > MAX_IKE {
            return Err(CascadeError::new("ike_size_limit"));
        }
        let hdr = parse_control_handshake(udp_port, payload)?;
        let msg_id = hdr.msg_id_str;

        if hdr.is_response {
            return self.send_local_response(
                dst_user,
                payload,
                &src_ip.to_string(),
                &dst_ip.to_string(),
                udp_port,
                hdr.initiator_spi,
                &msg_id,
                now_ms,
            );
        }

        // Check existing established initiator route for this (dst, initiator_spi).
        if let Some(route) = self
            .a_routes
            .get(&(dst_user.to_owned(), hdr.initiator_spi))
            .cloned()
        {
            let req_key = (hdr.initiator_spi, hdr.exchange_type, hdr.message_id);
            if let Some(ctx) = self.ab_contexts.get(&route.context) {
                if req_key == ctx.first_request {
                    if ctx.auth_requests.get(&msg_id).map(String::as_str)
                        != Some(sha256_hex(payload).as_str())
                    {
                        return Err(CascadeError::new("conflicting_initial_retransmission"));
                    }
                    return Ok(ctx
                        .initial_messages
                        .iter()
                        .map(|(peer, data)| MccAction::Send {
                            peer: peer.clone(),
                            message_type: MessageType::MccStart,
                            payload: data.clone(),
                        })
                        .collect());
                }
            }
            return self.send_opaque_continuation(
                &route,
                payload,
                &src_ip.to_string(),
                &dst_ip.to_string(),
                udp_port,
                &msg_id,
                now_ms,
            );
        }

        self.start_mcc_initial(
            dst_user,
            payload,
            &src_ip.to_string(),
            &dst_ip.to_string(),
            udp_port,
            hdr.initiator_spi,
            hdr.exchange_type,
            hdr.message_id,
            &msg_id,
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_mcc_initial(
        &mut self,
        dst: &str,
        payload: &[u8],
        src_ip: &str,
        dst_ip: &str,
        udp_port: u16,
        initiator_spi: [u8; 8],
        exchange_type: u8,
        ike_msg_id: u32,
        msg_id: &str,
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let now_s = (now_ms / 1000) as i64;
        let all_peers: Vec<String> = self.config.peers.keys().cloned().collect();
        let x1_pool: Vec<String> = all_peers
            .iter()
            .filter(|p| p.as_str() != self.security.name())
            .cloned()
            .collect();
        let x1_count = self.config.fanout.x1.max(1).min(x1_pool.len());
        let x2_count = self
            .config
            .fanout
            .x2
            .max(1)
            .min(all_peers.len().saturating_sub(1));
        let ike_count = self.config.fanout.ike.max(1);
        let expected = x1_count
            .checked_mul(x2_count)
            .and_then(|v| v.checked_mul(ike_count))
            .unwrap_or(usize::MAX);
        if !(1..=MAX_COPIES).contains(&expected) {
            return Err(CascadeError::new("copy_budget_limit"));
        }

        let mut digest_input = Vec::with_capacity(dst.len() + 2 + payload.len());
        digest_input.extend_from_slice(dst.as_bytes());
        digest_input.extend_from_slice(&udp_port.to_be_bytes());
        digest_input.extend_from_slice(payload);
        let digest = sha256_hex(&digest_input);

        if let Some((prev_ctx, _)) = self.pending_by_digest.get(&digest) {
            if let Some(ctx_state) = self.ab_contexts.get(prev_ctx) {
                return Ok(ctx_state
                    .initial_messages
                    .iter()
                    .map(|(peer, data)| MccAction::Send {
                        peer: peer.clone(),
                        message_type: MessageType::MccStart,
                        payload: data.clone(),
                    })
                    .collect());
            }
        }

        let context = hex::encode(random_bytes::<16>());
        let priv_key = X25519SecretKey::generate();
        let pub_hex = priv_key.public_key().to_hex();
        let chosen_x1 = self.pick_candidates(&x1_pool, x1_count);

        let mut actions = Vec::new();
        let mut initial_messages = Vec::new();
        let mut first_hops = BTreeSet::new();
        let expires_at = now_s + (self.config.policy.deadline_ms / 1000).max(1) as i64;

        for (x1_slot, x1) in chosen_x1.iter().enumerate() {
            let mut branches = Vec::new();
            for x2 in all_peers.iter().filter(|p| p.as_str() != x1.as_str()) {
                for x2_slot in 0..x2_count {
                    for ike_index in 0..ike_count {
                        let copy_id = ((x1_slot * x2_count) + x2_slot) * ike_count + ike_index;
                        let conn_id = hex::encode(random_bytes::<16>());
                        let branch_id = hex::encode(random_bytes::<16>());
                        let body = self.build_request_body(
                            payload,
                            src_ip,
                            dst_ip,
                            udp_port,
                            &pub_hex,
                            &conn_id,
                            (x1_count, x2_count, ike_count),
                        )?;
                        let record = self.security.signed_message(
                            dst, &context, body, copy_id, expected, "forward", "initial", msg_id,
                            now_s,
                        )?;
                        let sealed_b_v1 = self.security.seal_to(
                            dst,
                            &record,
                            &context,
                            MccCapsulePurpose::Endpoint,
                        )?;
                        let sealed_b = EndpointSecurity::pack_seal_v2(&sealed_b_v1)?;

                        let inner = build_x2_inner_object(
                            &context, &conn_id, &branch_id, dst, x1, x2, &sealed_b,
                        );
                        let cap_v1 =
                            self.security
                                .seal_to(x2, &inner, &conn_id, MccCapsulePurpose::Hop)?;
                        let capsule = EndpointSecurity::pack_seal_v2(&cap_v1)?;
                        branches.push(MccStartBranch {
                            conn_id,
                            branch_id,
                            x2: x2.clone(),
                            x2_slot,
                            ike_copy: ike_index,
                            capsule,
                        });
                    }
                }
            }
            first_hops.insert(x1.clone());
            // Split into bounded batches <= 28 KiB plaintext (matching mcc_privacy.py)
            let batches = batch_start_branches(
                MccStartMsg {
                    auth_mcc: 1,
                    opaque_mcc: 1,
                    mcc_carry_ike: true,
                    mcc_session_id: context.clone(),
                    req: self.security.name().to_owned(),
                    x1: x1.clone(),
                    x1_index: x1_slot,
                    x1_fanout: x1_count,
                    x2_fanout: x2_count,
                    ike_fanout: ike_count,
                    total_possible: expected,
                    ike_len: payload.len(),
                    expires_at,
                    branches: Vec::new(),
                },
                branches,
            )?;
            for batch in batches {
                let raw = jdump(&batch).map_err(|_| CascadeError::new("invalid_json"))?;
                initial_messages.push((x1.clone(), raw.clone()));
                actions.push(MccAction::Send {
                    peer: x1.clone(),
                    message_type: MessageType::MccStart,
                    payload: raw,
                });
            }
        }

        let mut auth_requests = BTreeMap::new();
        auth_requests.insert(msg_id.to_owned(), sha256_hex(payload));
        self.ab_contexts.insert(
            context.clone(),
            InitiatorContext {
                dst: dst.to_owned(),
                priv_key,
                pub_hex,
                initiator_spi,
                first_request: (initiator_spi, exchange_type, ike_msg_id),
                first_hops,
                auth_requests,
                forward_key: None,
                created_at_ms: now_ms,
                initial_messages,
            },
        );
        self.pending_by_digest.insert(digest, (context, now_ms));
        Ok(actions)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_request_body(
        &self,
        payload: &[u8],
        src_ip: &str,
        dst_ip: &str,
        udp_port: u16,
        a_pub: &str,
        conn_id: &str,
        budget: (usize, usize, usize),
    ) -> Result<BTreeMap<String, CanonicalValue>, CascadeError> {
        if payload.len() < 28 || payload.len() > MAX_IKE {
            return Err(CascadeError::new("ike_size_limit"));
        }
        let mut body = BTreeMap::new();
        body.insert(
            "ike_payload".to_owned(),
            CanonicalValue::String(hex::encode(payload)),
        );
        body.insert(
            "ike_length".to_owned(),
            CanonicalValue::Int(payload.len() as i64),
        );
        body.insert(
            "ike_src_ip".to_owned(),
            CanonicalValue::String(src_ip.to_owned()),
        );
        body.insert(
            "ike_src_port".to_owned(),
            CanonicalValue::Int(udp_port as i64),
        );
        body.insert(
            "ike_dst_ip".to_owned(),
            CanonicalValue::String(dst_ip.to_owned()),
        );
        body.insert(
            "ike_dst_port".to_owned(),
            CanonicalValue::Int(udp_port as i64),
        );
        body.insert("udp_port".to_owned(), CanonicalValue::Int(udp_port as i64));
        body.insert(
            "a_to_b_ke".to_owned(),
            CanonicalValue::String(a_pub.to_owned()),
        );
        body.insert(
            "transport_conn".to_owned(),
            CanonicalValue::String(conn_id.to_owned()),
        );
        body.insert(
            "budget".to_owned(),
            CanonicalValue::Array(vec![
                CanonicalValue::Int(budget.0 as i64),
                CanonicalValue::Int(budget.1 as i64),
                CanonicalValue::Int(budget.2 as i64),
            ]),
        );
        body.insert(
            "selection".to_owned(),
            self.config.policy.to_canonical_value(),
        );
        body.insert(
            "request_digest".to_owned(),
            CanonicalValue::String(sha256_hex(payload)),
        );
        Ok(body)
    }

    /// Processes an inbound authenticated hop message from adjacent `peer`.
    pub fn on_inbound(
        &mut self,
        peer: &str,
        message_type: MessageType,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Vec<MccAction> {
        self.prune(now_ms);
        let result = match message_type {
            MessageType::MccStart => self.handle_mcc_start(peer, plaintext, now_ms),
            MessageType::MccX2 => self.handle_mcc_x2(peer, plaintext, now_ms),
            MessageType::MccOffer => self.handle_mcc_offer(peer, plaintext, now_ms),
            MessageType::PrivBack => self.handle_priv_back(peer, plaintext, now_ms),
            MessageType::MccOpaqueFwd => self.handle_mcc_opaque_fwd(peer, plaintext, now_ms),
            // Legacy sibling endpoints are permanently closed (mcc_auth.py:1025-1058).
            MessageType::ProxyBlob => Err(CascadeError::new("legacy_proxy_disabled")),
            MessageType::PrivDeliver => Err(CascadeError::new("legacy_deliver_disabled")),
            MessageType::PrivFwd => Err(CascadeError::new("legacy_forward_disabled")),
            MessageType::PrivInlineStart | MessageType::PrivInlineX2 => {
                Err(CascadeError::new("legacy_inline_disabled"))
            }
            MessageType::MccAccept => Err(CascadeError::new("legacy_accept_disabled")),
            MessageType::I1 | MessageType::I2 | MessageType::OkX2 => {
                Err(CascadeError::new("legacy_route_setup_disabled"))
            }
            MessageType::LocalConnect => Err(CascadeError::new("legacy_demo_connect_disabled")),
            MessageType::Error => Err(CascadeError::new("unauthenticated_error_ignored")),
            _ => Err(CascadeError::new("unsupported_message_type")),
        };
        match result {
            Ok(actions) => actions,
            Err(err) => vec![MccAction::Reject { code: err.code() }],
        }
    }

    /// Advances selection timers (`window`, `adaptive`, `wait-all`) at timestamp `now_ms`.
    pub fn on_tick(&mut self, now_ms: u64) -> Vec<MccAction> {
        self.prune(now_ms);
        let due_keys: Vec<String> = self
            .b_pending
            .iter()
            .filter(|(_, s)| {
                !s.selected
                    && !s.closed
                    && !s.offers.is_empty()
                    && (now_ms >= s.deadline_ms || s.quiet_deadline_ms.is_some_and(|q| now_ms >= q))
            })
            .map(|(k, _)| k.clone())
            .collect();

        let mut actions = Vec::new();
        for key in due_keys {
            actions.extend(self.select_offer(&key, now_ms));
        }
        actions
    }

    /// Reports the local IKE injection outcome for a consumed [`LocalDeliveryProof`].
    ///
    /// - `Sent`: permanently marks the message as `delivered` in the SQLite ledger.
    /// - `Rejected`: releases the reservation (`failed_delivery`), rolls back provisional
    ///   route state, and if additional verified MCC offers are queued on `B`, selects the next one!
    /// - `Unknown`: retains the durable `in_flight` reservation and FORBIDS retry.
    pub fn complete_delivery(
        &mut self,
        receipt: DeliveryReceipt,
        outcome: IkeInjectionOutcome,
        now_ms: u64,
    ) -> Vec<MccAction> {
        let now_s = (now_ms / 1000) as i64;
        let key = (receipt.message_key.clone(), receipt.copy_id);
        let Some(entry) = self.inflight.remove(&key) else {
            return vec![MccAction::Reject {
                code: "delivery_not_reserved_here",
            }];
        };

        match outcome {
            IkeInjectionOutcome::Sent => {
                if let Err(err) = self.security.delivered(&entry.verified, now_s) {
                    return vec![MccAction::Reject { code: err.code() }];
                }
                if entry.is_initial && entry.direction_forward {
                    if let Some(pending) = self.b_pending.get_mut(&receipt.message_key) {
                        pending.selected = true;
                    }
                }
                Vec::new()
            }
            IkeInjectionOutcome::Rejected => {
                if let Err(err) = self.security.failed_delivery(&entry.verified, now_s) {
                    return vec![MccAction::Reject { code: err.code() }];
                }
                if entry.is_initial && entry.direction_forward {
                    self.b_sessions
                        .remove(&(entry.sender.clone(), entry.context.clone()));
                    if let Some(pending) = self.b_pending.get_mut(&receipt.message_key) {
                        pending.selected = false;
                        if !pending.offers.is_empty() && !pending.closed {
                            return self.select_offer(&receipt.message_key, now_ms);
                        }
                    }
                } else if !entry.direction_forward {
                    if let Some((dst, spi, prev)) = entry.prev_initiator_route {
                        let rkey = (dst, spi);
                        if let Some(prev_route) = prev {
                            self.a_routes.insert(rkey, prev_route);
                        } else {
                            self.a_routes.remove(&rkey);
                            if let Some(ctx) = self.ab_contexts.get_mut(&entry.context) {
                                ctx.forward_key = None;
                            }
                        }
                    }
                }
                Vec::new()
            }
            IkeInjectionOutcome::Unknown => {
                // Keep durable in-flight claim in SQLite; never release or retry!
                vec![MccAction::Reject {
                    code: "injection_outcome_unknown",
                }]
            }
        }
    }

    fn handle_mcc_start(
        &mut self,
        peer: &str,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let _ = parse_strict_json_object(plaintext, MAX_PLAINTEXT)
            .map_err(|_| CascadeError::new("invalid_start"))?;
        let msg: MccStartMsg =
            serde_json::from_slice(plaintext).map_err(|_| CascadeError::new("invalid_start"))?;
        if msg.auth_mcc != 1
            || msg.opaque_mcc != 1
            || !msg.mcc_carry_ike
            || !(1..=MAX_COPIES).contains(&msg.x2_fanout)
            || msg.branches.len() > 576
            || msg.x1 != self.security.name()
            || msg.req != peer
        {
            return Err(CascadeError::new("legacy_or_invalid_start"));
        }
        for b in &msg.branches {
            if b.x2_slot >= msg.x2_fanout {
                return Err(CascadeError::new("invalid_copy_slot"));
            }
        }
        if self.x1_branches.len() + msg.branches.len() > MAX_ACTIVE * 4 {
            return Err(CascadeError::new("relay_capacity"));
        }

        let sel_key = (peer.to_owned(), msg.mcc_session_id.clone());
        let selected_x2 = if let Some(prev) = self.x1_selections.get(&sel_key) {
            if prev.req != peer {
                return Err(CascadeError::new("conflicting_mcc_requester"));
            }
            prev.selected.clone()
        } else {
            if self.x1_selections.len() >= MAX_ACTIVE {
                return Err(CascadeError::new("relay_capacity"));
            }
            let candidates: Vec<String> = self
                .config
                .peers
                .keys()
                .filter(|p| p.as_str() != self.security.name())
                .cloned()
                .collect();
            let chosen = self.pick_candidates(&candidates, msg.x2_fanout);
            self.x1_selections.insert(
                sel_key,
                X1Selection {
                    req: peer.to_owned(),
                    selected: chosen.clone(),
                    expires_at_ms: now_ms + ROUTE_TTL_MS,
                },
            );
            chosen
        };

        let mut actions = Vec::new();
        for (slot_idx, chosen_peer) in selected_x2.iter().enumerate() {
            for branch in msg
                .branches
                .iter()
                .filter(|b| b.x2 == *chosen_peer && b.x2_slot == slot_idx)
            {
                if self.x1_branches.contains_key(&branch.conn_id) {
                    continue;
                }
                self.x1_branches.insert(
                    branch.conn_id.clone(),
                    X1BranchState {
                        req: peer.to_owned(),
                        x2: chosen_peer.clone(),
                        context: msg.mcc_session_id.clone(),
                        opaque_token: None,
                        created_at_ms: now_ms,
                    },
                );
                let out = MccX2Msg {
                    auth_mcc: 1,
                    opaque_mcc: 1,
                    conn_id: branch.conn_id.clone(),
                    total_possible: msg.total_possible,
                    capsule: branch.capsule.clone(),
                };
                let raw = jdump(&out).map_err(|_| CascadeError::new("invalid_json"))?;
                actions.push(MccAction::Send {
                    peer: chosen_peer.clone(),
                    message_type: MessageType::MccX2,
                    payload: raw,
                });
            }
        }
        Ok(actions)
    }

    fn handle_mcc_x2(
        &mut self,
        peer: &str,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let _ = parse_strict_json_object(plaintext, MAX_PLAINTEXT)
            .map_err(|_| CascadeError::new("invalid_x2"))?;
        let msg: MccX2Msg =
            serde_json::from_slice(plaintext).map_err(|_| CascadeError::new("invalid_x2"))?;
        if msg.auth_mcc != 1 || msg.opaque_mcc != 1 {
            return Err(CascadeError::new("legacy_x2"));
        }

        let cap_v1 = EndpointSecurity::expand_seal_v2(&msg.capsule)?;
        let inner = self
            .security
            .open_for_me(&cap_v1, &msg.conn_id, MccCapsulePurpose::Hop)?;

        let inner_auth = inner.get("auth_mcc").and_then(CanonicalValue::as_i64);
        let inner_conn = inner.get("conn_id").and_then(CanonicalValue::as_str);
        let inner_x1 = inner.get("x1").and_then(CanonicalValue::as_str);
        let inner_x2 = inner.get("x2").and_then(CanonicalValue::as_str);
        let inner_dst = inner.get("dst").and_then(CanonicalValue::as_str);
        let inner_ctx = inner.get("mcc_session_id").and_then(CanonicalValue::as_str);
        let inner_ab_ctx = inner.get("ab_context").and_then(CanonicalValue::as_str);
        let inner_branch = inner.get("branch_id").and_then(CanonicalValue::as_str);
        let sealed_b_obj = inner.get("sealed_b").and_then(CanonicalValue::as_object);

        if inner_auth != Some(1)
            || inner_conn != Some(msg.conn_id.as_str())
            || inner_x1 != Some(peer)
            || inner_x2 != Some(self.security.name())
            || inner_dst.is_none_or(|d| !self.config.peers.contains_key(d))
            || inner_ctx.is_none()
            || inner_ab_ctx != inner_ctx
            || inner_branch.is_none()
            || sealed_b_obj.is_none()
        {
            return Err(CascadeError::new("invalid_x2_scope"));
        }
        let dst = inner_dst.unwrap_or_default().to_owned();
        let ctx = inner_ctx.unwrap_or_default().to_owned();
        let branch_id = inner_branch.unwrap_or_default().to_owned();
        let sealed_b = capsule_v2_from_canonical(sealed_b_obj.unwrap())?;

        if let Some(old) = self.x2_branches.get(&msg.conn_id) {
            if old.x1 != peer || old.dst != dst {
                return Err(CascadeError::new("conflicting_relay_branch"));
            }
            return Ok(Vec::new());
        }
        if self.x2_branches.len() >= MAX_ACTIVE * 4 {
            return Err(CascadeError::new("relay_capacity"));
        }
        self.x2_branches.insert(
            msg.conn_id.clone(),
            X2BranchState {
                x1: peer.to_owned(),
                dst: dst.clone(),
                context: ctx.clone(),
                created_at_ms: now_ms,
            },
        );

        let offer = MccOfferMsg {
            auth_mcc: 1,
            opaque_mcc: 1,
            mcc_session_id: ctx.clone(),
            conn_id: msg.conn_id,
            branch_id,
            dst: dst.clone(),
            x2: self.security.name().to_owned(),
            ab_context: ctx,
            total_possible: msg.total_possible,
            inline: true,
            mcc_carry_ike: true,
            sealed_b,
        };
        let raw = jdump(&offer).map_err(|_| CascadeError::new("invalid_json"))?;
        Ok(vec![MccAction::Send {
            peer: dst,
            message_type: MessageType::MccOffer,
            payload: raw,
        }])
    }

    fn handle_mcc_offer(
        &mut self,
        peer: &str,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let now_s = (now_ms / 1000) as i64;
        let outer_map = parse_strict_json_object(plaintext, MAX_PLAINTEXT)
            .map_err(|_| CascadeError::new("invalid_offer"))?;
        let msg: MccOfferMsg =
            serde_json::from_slice(plaintext).map_err(|_| CascadeError::new("invalid_offer"))?;
        if msg.auth_mcc != 1 || msg.opaque_mcc != 1 {
            return Err(CascadeError::new("legacy_offer"));
        }
        if msg.dst != self.security.name() || !self.config.peers.contains_key(peer) {
            return Err(CascadeError::new("invalid_offer_scope"));
        }

        // Open confidential recipient capsule & verify Ed25519 signature BEFORE any state mutation!
        let cap_v1 = EndpointSecurity::expand_seal_v2(&msg.sealed_b)?;
        let record =
            self.security
                .open_for_me(&cap_v1, &msg.mcc_session_id, MccCapsulePurpose::Endpoint)?;
        let verified = self.security.verify_signed(
            &record,
            &msg.mcc_session_id,
            None,
            "forward",
            "initial",
            now_s,
        )?;
        let req = self.validate_verified_request(&verified, true)?;

        if msg.conn_id != req.conn_id || msg.ab_context != verified.context {
            return Err(CascadeError::new("invalid_offer_scope"));
        }
        // Reject contradictory outer wrapper fields if an attacker-controlled relay added them.
        check_no_contradictory_wrapper(&outer_map, &req)?;

        // Check receiver & per-sender pending capacities.
        if !self.b_pending.contains_key(&verified.message_key) {
            if self.b_pending.len() >= MAX_ACTIVE {
                return Err(CascadeError::new("endpoint_capacity"));
            }
            let same_sender = self
                .b_pending
                .values()
                .filter(|s| s.sender == verified.sender)
                .count();
            if same_sender >= MAX_ACTIVE / 4 {
                return Err(CascadeError::new("sender_capacity"));
            }
        }

        match self.security.admit(&verified, now_s)? {
            AdmitStatus::New => {}
            AdmitStatus::Duplicate => return Ok(Vec::new()),
            AdmitStatus::Delivered => {
                return self.replay_cached_response(
                    &verified,
                    &req.conn_id,
                    &req.request_digest,
                    now_ms,
                );
            }
        }

        let offer = PendingOffer {
            verified: verified.clone(),
            peer: peer.to_owned(),
            payload: req.payload,
            conn_id: req.conn_id,
            a_pub: req.a_pub,
            ike_src_ip: req.ike_src_ip,
            ike_src_port: req.ike_src_port,
            ike_dst_ip: req.ike_dst_ip,
            ike_dst_port: req.ike_dst_port,
            udp_port: req.udp_port,
            request_digest: req.request_digest,
        };

        let policy = self.config.policy.clone();
        let message_key = verified.message_key.clone();
        let mut select_now = false;

        let entry = self
            .b_pending
            .entry(message_key.clone())
            .or_insert_with(|| {
                let wait_ms = if policy.mode == SelectionMode::Window {
                    policy.window_ms
                } else {
                    policy.deadline_ms
                };
                PendingSelection {
                    sender: verified.sender.clone(),
                    expected: verified.expected_copies,
                    expires_s: verified.expires,
                    deadline_ms: now_ms.saturating_add(wait_ms),
                    quiet_deadline_ms: None,
                    attempts: 0,
                    closed: false,
                    selected: false,
                    offers: Vec::new(),
                }
            });
        if entry.selected || entry.closed {
            return Ok(Vec::new());
        }
        entry.offers.push(offer);

        match policy.mode {
            SelectionMode::First => select_now = true,
            SelectionMode::WaitAll => {
                if entry.offers.len() >= entry.expected || now_ms >= entry.deadline_ms {
                    select_now = true;
                }
            }
            SelectionMode::Window => {
                if now_ms >= entry.deadline_ms {
                    select_now = true;
                }
            }
            SelectionMode::Adaptive => {
                if entry.offers.len() >= policy.min_copies {
                    if policy.quiet_ms == 0 || now_ms >= entry.deadline_ms {
                        select_now = true;
                    } else {
                        let q = now_ms
                            .saturating_add(policy.quiet_ms)
                            .min(entry.deadline_ms);
                        entry.quiet_deadline_ms = Some(q);
                    }
                }
            }
        }

        if select_now {
            Ok(self.select_offer(&message_key, now_ms))
        } else {
            Ok(Vec::new())
        }
    }

    fn select_offer(&mut self, message_key: &str, now_ms: u64) -> Vec<MccAction> {
        let now_s = (now_ms / 1000) as i64;
        let offer_count = match self.b_pending.get(message_key) {
            Some(s) if !s.selected && !s.closed && !s.offers.is_empty() => s.offers.len(),
            _ => return Vec::new(),
        };
        let pick_idx = if self.config.policy.mode == SelectionMode::First {
            0
        } else {
            self.next_rand_usize(offer_count)
        };

        let (offer, attempts_exceeded) = {
            let state = self.b_pending.get_mut(message_key).unwrap();
            if state.attempts >= MAX_ATTEMPTS {
                state.closed = true;
                return vec![MccAction::Reject {
                    code: "delivery_attempt_limit",
                }];
            }
            state.attempts += 1;
            let chosen = state.offers.remove(pick_idx);
            (chosen, false)
        };
        let _ = attempts_exceeded;

        // Reserve durable delivery claim BEFORE emitting LocalDeliveryProof!
        match self.security.claim_delivery(&offer.verified, now_s) {
            Ok(true) => {}
            Ok(false) => return Vec::new(),
            Err(err) => return vec![MccAction::Reject { code: err.code() }],
        }

        let pair = (
            offer.verified.sender.clone(),
            offer.verified.context.clone(),
        );
        if !self.b_sessions.contains_key(&pair) {
            if self.b_sessions.len() >= MAX_ACTIVE {
                let _ = self.security.failed_delivery(&offer.verified, now_s);
                return vec![MccAction::Reject {
                    code: "endpoint_capacity",
                }];
            }
            let a_pub_key = match X25519PublicKey::from_hex(&offer.a_pub) {
                Ok(k) => k,
                Err(_) => {
                    let _ = self.security.failed_delivery(&offer.verified, now_s);
                    return vec![MccAction::Reject {
                        code: "invalid_endpoint_key",
                    }];
                }
            };
            let b_priv = X25519SecretKey::generate();
            let b_pub_hex = b_priv.public_key().to_hex();
            let Ok(shared) = b_priv.diffie_hellman(&a_pub_key) else {
                let _ = self.security.failed_delivery(&offer.verified, now_s);
                return vec![MccAction::Reject {
                    code: "key_agreement_failed",
                }];
            };
            let Ok(back_key) = derive_priv_b_a_key(&shared, &offer.verified.context) else {
                let _ = self.security.failed_delivery(&offer.verified, now_s);
                return vec![MccAction::Reject {
                    code: "key_agreement_failed",
                }];
            };
            let Ok(forward_key) = derive_mcc_forward_key(&shared, &offer.verified.context) else {
                let _ = self.security.failed_delivery(&offer.verified, now_s);
                return vec![MccAction::Reject {
                    code: "key_agreement_failed",
                }];
            };
            let Ok(hdr) = parse_control_handshake(offer.udp_port, &offer.payload) else {
                let _ = self.security.failed_delivery(&offer.verified, now_s);
                return vec![MccAction::Reject {
                    code: "invalid_ike_message_binding",
                }];
            };
            let mut requests = BTreeMap::new();
            requests.insert(
                offer.verified.message_id.clone(),
                offer.request_digest.clone(),
            );
            self.b_sessions.insert(
                pair,
                ResponderSession {
                    conn_id: offer.conn_id.clone(),
                    peer_x2: offer.peer.clone(),
                    src: offer.verified.sender.clone(),
                    a_pub: offer.a_pub.clone(),
                    bke: b_pub_hex,
                    back_key,
                    forward_key,
                    initiator_spi: hdr.initiator_spi,
                    selected_copy: offer.verified.copy_id,
                    created_at_ms: now_ms,
                    expires_s: offer.verified.expires,
                    requests,
                    responses: BTreeMap::new(),
                },
            );
        }

        if let Some(state) = self.b_pending.get_mut(message_key) {
            state.selected = true;
        }

        let meta = DeliveredIkeMeta {
            src: offer.verified.sender.clone(),
            dst: self.security.name().to_owned(),
            x1: String::new(),
            x2: offer.peer,
            conn_id: offer.conn_id,
            context: offer.verified.context.clone(),
            direction: "fwd".to_owned(),
            ike_src_ip: offer.ike_src_ip,
            ike_src_port: offer.ike_src_port,
            ike_dst_ip: offer.ike_dst_ip,
            ike_dst_port: offer.ike_dst_port,
            udp_port: offer.udp_port,
            opaque_token: String::new(),
            expected_copies: offer.verified.expected_copies,
            copy_id: offer.verified.copy_id,
            message_key: offer.verified.message_key.clone(),
        };

        let proof = LocalDeliveryProof::mint(
            offer.payload,
            meta,
            offer.verified.message_key.clone(),
            offer.verified.copy_id,
        );
        self.inflight.insert(
            (offer.verified.message_key.clone(), offer.verified.copy_id),
            InFlightDelivery {
                verified: offer.verified.clone(),
                is_initial: true,
                direction_forward: true,
                sender: offer.verified.sender,
                context: offer.verified.context,
                prev_initiator_route: None,
            },
        );

        vec![MccAction::DeliverIke {
            proof: Box::new(proof),
        }]
    }

    #[allow(clippy::too_many_arguments)]
    fn send_local_response(
        &mut self,
        dst_user: &str,
        payload: &[u8],
        src_ip: &str,
        dst_ip: &str,
        udp_port: u16,
        initiator_spi: [u8; 8],
        msg_id: &str,
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let now_s = (now_ms / 1000) as i64;
        let matching: Vec<(String, String, u64)> = self
            .b_sessions
            .iter()
            .filter(|((sender, _), st)| {
                sender == dst_user
                    && st.initiator_spi == initiator_spi
                    && st.requests.contains_key(msg_id)
                    && now_s <= st.expires_s + 5
            })
            .map(|((s, c), st)| (s.clone(), c.clone(), st.created_at_ms))
            .collect();
        if matching.is_empty() {
            return Err(CascadeError::new("unbound_local_response"));
        }
        let digests: BTreeSet<&str> = matching
            .iter()
            .filter_map(|(s, c, _)| {
                self.b_sessions
                    .get(&(s.clone(), c.clone()))
                    .and_then(|st| st.requests.get(msg_id).map(String::as_str))
            })
            .collect();
        if digests.len() != 1 {
            return Err(CascadeError::new("unbound_local_response"));
        }
        let (sender, context, _) = matching
            .into_iter()
            .max_by_key(|(_, _, created)| *created)
            .unwrap();

        let (conn_id, peer_x2, bke, a_pub, req_digest) = {
            let st = self
                .b_sessions
                .get(&(sender.clone(), context.clone()))
                .unwrap();
            (
                st.conn_id.clone(),
                st.peer_x2.clone(),
                st.bke.clone(),
                st.a_pub.clone(),
                st.requests[msg_id].clone(),
            )
        };

        let mut body = BTreeMap::new();
        body.insert(
            "ike_payload".to_owned(),
            CanonicalValue::String(hex::encode(payload)),
        );
        body.insert(
            "ike_length".to_owned(),
            CanonicalValue::Int(payload.len() as i64),
        );
        body.insert(
            "ike_src_ip".to_owned(),
            CanonicalValue::String(src_ip.to_owned()),
        );
        body.insert(
            "ike_src_port".to_owned(),
            CanonicalValue::Int(udp_port as i64),
        );
        body.insert(
            "ike_dst_ip".to_owned(),
            CanonicalValue::String(dst_ip.to_owned()),
        );
        body.insert(
            "ike_dst_port".to_owned(),
            CanonicalValue::Int(udp_port as i64),
        );
        body.insert("udp_port".to_owned(), CanonicalValue::Int(udp_port as i64));
        body.insert("bke".to_owned(), CanonicalValue::String(bke.clone()));
        body.insert("a_to_b_ke".to_owned(), CanonicalValue::String(a_pub));
        body.insert(
            "request_digest".to_owned(),
            CanonicalValue::String(req_digest),
        );

        let record = self.security.signed_message(
            &sender, &context, body, 0, 1, "reverse", "response", msg_id, now_s,
        )?;
        let record_bytes =
            canonical_bytes_from_value(&CanonicalValue::Object(record), MAX_PLAINTEXT)
                .map_err(|_| CascadeError::new("json_resource_limit"))?;
        let st = self
            .b_sessions
            .get_mut(&(sender.clone(), context.clone()))
            .unwrap();
        let (nonce, ct) = aes256_gcm_encrypt(&st.back_key, &record_bytes, &priv_b_a_aad(&context))
            .map_err(|_| CascadeError::new("encryption_failed"))?;
        st.responses.insert(
            msg_id.to_owned(),
            CachedResponse {
                payload: payload.to_vec(),
                src_ip: src_ip.to_owned(),
                dst_ip: dst_ip.to_owned(),
                udp_port,
            },
        );

        let sealed_a = ReverseSealV2 {
            mode: "x25519".to_owned(),
            auth_mcc: 1,
            v: 2,
            conn_id: context,
            bke,
            nonce: hex::encode(nonce),
            ct: encode_canonical_base64_ct(&ct)?,
        };
        let out = serde_json::json!({
            "opaque_mcc": 1,
            "leg": "b-x2",
            "conn_id": conn_id,
            "sealed_a": sealed_a,
        });
        let raw = jdump(&out).map_err(|_| CascadeError::new("invalid_json"))?;
        Ok(vec![MccAction::Send {
            peer: peer_x2,
            message_type: MessageType::PrivBack,
            payload: raw,
        }])
    }

    fn replay_cached_response(
        &mut self,
        verified: &VerifiedMessage,
        conn_id: &str,
        request_digest: &str,
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let cached = {
            let Some(st) = self
                .b_sessions
                .get(&(verified.sender.clone(), verified.context.clone()))
            else {
                return Ok(Vec::new());
            };
            if st.requests.get(&verified.message_id).map(String::as_str) != Some(request_digest) {
                return Ok(Vec::new());
            }
            if verified.kind == "initial"
                && (st.conn_id != conn_id || st.selected_copy != verified.copy_id)
            {
                return Ok(Vec::new());
            }
            st.responses.get(&verified.message_id).cloned()
        };
        let Some(resp) = cached else {
            return Ok(Vec::new());
        };
        let hdr = parse_control_handshake(resp.udp_port, &resp.payload)?;
        self.send_local_response(
            &verified.sender,
            &resp.payload,
            &resp.src_ip,
            &resp.dst_ip,
            resp.udp_port,
            hdr.initiator_spi,
            &verified.message_id,
            now_ms,
        )
    }

    fn handle_priv_back(
        &mut self,
        peer: &str,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let now_s = (now_ms / 1000) as i64;
        let _ = parse_strict_json_object(plaintext, MAX_PLAINTEXT)
            .map_err(|_| CascadeError::new("invalid_response"))?;
        let msg: Value = jload(plaintext).map_err(|_| CascadeError::new("invalid_response"))?;
        if msg.get("opaque_mcc").and_then(Value::as_i64) != Some(1) {
            return Err(CascadeError::new("legacy_reverse_disabled"));
        }
        let leg = msg
            .get("leg")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_response_schema"))?;
        let conn = msg
            .get("conn_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_response_schema"))?;
        let sealed_a_val = msg
            .get("sealed_a")
            .ok_or_else(|| CascadeError::new("invalid_response_schema"))?;
        let context = sealed_a_val
            .get("conn_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_response_schema"))?;

        match leg {
            "b-x2" => {
                let x2 = self
                    .x2_branches
                    .get(conn)
                    .ok_or_else(|| CascadeError::new("wrong_reverse_boundary"))?;
                if peer != x2.dst || context != x2.context {
                    return Err(CascadeError::new("wrong_reverse_boundary"));
                }
                let out = serde_json::json!({
                    "opaque_mcc": 1,
                    "leg": "x2-x1",
                    "conn_id": conn,
                    "sealed_a": sealed_a_val,
                });
                let raw = jdump(&out).map_err(|_| CascadeError::new("invalid_json"))?;
                Ok(vec![MccAction::Send {
                    peer: x2.x1.clone(),
                    message_type: MessageType::PrivBack,
                    payload: raw,
                }])
            }
            "x2-x1" => {
                let (req, token) = {
                    let x1 = self
                        .x1_branches
                        .get_mut(conn)
                        .ok_or_else(|| CascadeError::new("wrong_reverse_boundary"))?;
                    if peer != x1.x2 || context != x1.context {
                        return Err(CascadeError::new("wrong_reverse_boundary"));
                    }
                    let token = if let Some(existing) = &x1.opaque_token {
                        existing.clone()
                    } else {
                        let tok = hex::encode(random_bytes::<32>());
                        x1.opaque_token = Some(tok.clone());
                        self.x1_handles.insert(
                            tok.clone(),
                            X1OpaqueHandle {
                                context: context.to_owned(),
                                conn_id: conn.to_owned(),
                                req: x1.req.clone(),
                                x2: x1.x2.clone(),
                                created_at_ms: x1.created_at_ms,
                            },
                        );
                        tok
                    };
                    (x1.req.clone(), token)
                };
                let out = serde_json::json!({
                    "opaque_mcc": 1,
                    "leg": "x1-a",
                    "conn_id": context,
                    "route_token": token,
                    "sealed_a": sealed_a_val,
                });
                let raw = jdump(&out).map_err(|_| CascadeError::new("invalid_json"))?;
                Ok(vec![MccAction::Send {
                    peer: req,
                    message_type: MessageType::PrivBack,
                    payload: raw,
                }])
            }
            "x1-a" => {
                let obj = msg
                    .as_object()
                    .ok_or_else(|| CascadeError::new("invalid_response_schema"))?;
                if obj.len() != 5 || !obj.contains_key("route_token") {
                    return Err(CascadeError::new("invalid_response_schema"));
                }
                let token = obj["route_token"]
                    .as_str()
                    .ok_or_else(|| CascadeError::new("invalid_response_scope"))?;
                decode_canonical_hex::<32>(token)
                    .map_err(|_| CascadeError::new("invalid_response_scope"))?;
                let seal: ReverseSealV2 = serde_json::from_value(sealed_a_val.clone())
                    .map_err(|_| CascadeError::new("invalid_reverse_capsule"))?;
                if seal.mode != "x25519"
                    || seal.auth_mcc != 1
                    || seal.v != 2
                    || seal.conn_id != conn
                    || conn != context
                {
                    return Err(CascadeError::new("invalid_reverse_capsule"));
                }
                let bke_pub = X25519PublicKey::from_hex(&seal.bke)
                    .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
                let nonce = decode_canonical_hex::<12>(&seal.nonce)
                    .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
                let ct = decode_canonical_base64_ct(&seal.ct)?;

                let (
                    dst_name,
                    expected_pub,
                    expected_spi,
                    first_request,
                    expected_digest_map,
                    back_raw,
                    forward_key,
                ) = {
                    let st = self
                        .ab_contexts
                        .get(context)
                        .ok_or_else(|| CascadeError::new("no_pending_request"))?;
                    if !st.first_hops.contains(peer) {
                        return Err(CascadeError::new("no_pending_request"));
                    }
                    let shared = st
                        .priv_key
                        .diffie_hellman(&bke_pub)
                        .map_err(|_| CascadeError::new("key_agreement_failed"))?;
                    let back_key = derive_priv_b_a_key(&shared, context)
                        .map_err(|_| CascadeError::new("key_agreement_failed"))?;
                    let raw = aes256_gcm_decrypt(&back_key, &nonce, &ct, &priv_b_a_aad(context))
                        .map_err(|_| CascadeError::new("capsule_authentication_failed"))?;
                    let fwd_key = derive_mcc_forward_key(&shared, context)
                        .map_err(|_| CascadeError::new("key_agreement_failed"))?;
                    (
                        st.dst.clone(),
                        st.pub_hex.clone(),
                        st.initiator_spi,
                        st.first_request,
                        st.auth_requests.clone(),
                        raw,
                        fwd_key,
                    )
                };

                let record = parse_strict_json_object(&back_raw, MAX_PLAINTEXT)
                    .map_err(|_| CascadeError::new("invalid_json"))?;
                let verified = self.security.verify_signed(
                    &record,
                    context,
                    Some(&dst_name),
                    "reverse",
                    "response",
                    now_s,
                )?;
                if verified.expected_copies != 1 || verified.copy_id != 0 {
                    return Err(CascadeError::new("invalid_response_copy_budget"));
                }
                let body = verified.body_map()?;
                const RESP_FIELDS: [&str; 10] = [
                    "ike_payload",
                    "ike_length",
                    "ike_src_ip",
                    "ike_src_port",
                    "ike_dst_ip",
                    "ike_dst_port",
                    "udp_port",
                    "bke",
                    "a_to_b_ke",
                    "request_digest",
                ];
                if body.len() != RESP_FIELDS.len()
                    || !RESP_FIELDS.iter().all(|f| body.contains_key(*f))
                {
                    return Err(CascadeError::new("invalid_response_body"));
                }
                let parsed = validate_ike_fields(&verified, &body, true)?;
                let hdr = parse_control_handshake(parsed.udp_port, &parsed.payload)?;

                let body_bke = body["bke"].as_str().unwrap_or("");
                let body_apub = body["a_to_b_ke"].as_str().unwrap_or("");
                let body_req_digest = body["request_digest"].as_str().unwrap_or("");
                let dst_ip_expected = self.config.peers[&dst_name].to_string();
                let own_ip_expected = self.config.peers[self.security.name()].to_string();

                if body_bke != seal.bke
                    || body_apub != expected_pub
                    || parsed.ike_src_ip != dst_ip_expected
                    || parsed.ike_dst_ip != own_ip_expected
                    || expected_digest_map
                        .get(&verified.message_id)
                        .map(String::as_str)
                        != Some(body_req_digest)
                    || hdr.initiator_spi != expected_spi
                {
                    return Err(CascadeError::new("response_request_binding"));
                }

                let route_key = (dst_name.clone(), hdr.initiator_spi);
                let existing = self.a_routes.get(&route_key).cloned();
                if let Some(ref ex) = existing {
                    if ex.context != context || ex.x1 != peer || ex.opaque_token != token {
                        return Err(CascadeError::new("late_response_route_change"));
                    }
                } else if (hdr.initiator_spi, hdr.exchange_type, hdr.message_id) != first_request {
                    return Err(CascadeError::new("unrelated_initial_response"));
                }

                if self.security.admit(&verified, now_s)? != AdmitStatus::New {
                    return Ok(Vec::new());
                }
                if !self.security.claim_delivery(&verified, now_s)? {
                    return Ok(Vec::new());
                }

                // Publish authenticated initiator route BEFORE local injection (mcc_auth.py:924).
                let new_route = InitiatorRoute {
                    context: context.to_owned(),
                    dst: dst_name.clone(),
                    x1: peer.to_owned(),
                    opaque_token: token.to_owned(),
                    created_at_ms: existing.as_ref().map_or(now_ms, |e| e.created_at_ms),
                };
                self.a_routes.insert(route_key, new_route);
                if let Some(ctx_st) = self.ab_contexts.get_mut(context) {
                    ctx_st.forward_key = Some(forward_key);
                }

                let meta = DeliveredIkeMeta {
                    src: self.security.name().to_owned(),
                    dst: dst_name,
                    x1: peer.to_owned(),
                    x2: String::new(), // X2 stays strictly hidden from initiator A!
                    conn_id: context.to_owned(),
                    context: context.to_owned(),
                    direction: "back".to_owned(),
                    ike_src_ip: parsed.ike_src_ip,
                    ike_src_port: parsed.ike_src_port,
                    ike_dst_ip: parsed.ike_dst_ip,
                    ike_dst_port: parsed.ike_dst_port,
                    udp_port: parsed.udp_port,
                    opaque_token: token.to_owned(),
                    expected_copies: 1,
                    copy_id: 0,
                    message_key: verified.message_key.clone(),
                };
                let proof =
                    LocalDeliveryProof::mint(parsed.payload, meta, verified.message_key.clone(), 0);
                self.inflight.insert(
                    (verified.message_key.clone(), 0),
                    InFlightDelivery {
                        verified: verified.clone(),
                        is_initial: false,
                        direction_forward: false,
                        sender: verified.sender,
                        context: context.to_owned(),
                        prev_initiator_route: Some((
                            self.ab_contexts[context].dst.clone(),
                            hdr.initiator_spi,
                            existing,
                        )),
                    },
                );
                Ok(vec![MccAction::DeliverIke {
                    proof: Box::new(proof),
                }])
            }
            _ => Err(CascadeError::new("invalid_response_schema")),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn send_opaque_continuation(
        &mut self,
        route: &InitiatorRoute,
        payload: &[u8],
        src_ip: &str,
        dst_ip: &str,
        udp_port: u16,
        msg_id: &str,
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let now_s = (now_ms / 1000) as i64;
        let a_pub = {
            let st = self
                .ab_contexts
                .get(&route.context)
                .ok_or_else(|| CascadeError::new("no_authenticated_continuation_key"))?;
            if st.forward_key.is_none() {
                return Err(CascadeError::new("no_authenticated_continuation_key"));
            }
            if !st.auth_requests.contains_key(msg_id) && st.auth_requests.len() >= MAX_REQUESTS {
                return Err(CascadeError::new("request_capacity"));
            }
            st.pub_hex.clone()
        };

        let body = self.build_request_body(
            payload,
            src_ip,
            dst_ip,
            udp_port,
            &a_pub,
            &route.context,
            (1, 1, 1),
        )?;
        let req_digest = sha256_hex(payload);
        let record = self.security.signed_message(
            &route.dst,
            &route.context,
            body,
            0,
            1,
            "forward",
            "continuation",
            msg_id,
            now_s,
        )?;
        let record_bytes =
            canonical_bytes_from_value(&CanonicalValue::Object(record), MAX_PLAINTEXT)
                .map_err(|_| CascadeError::new("json_resource_limit"))?;

        let st = self.ab_contexts.get_mut(&route.context).unwrap();
        st.auth_requests.insert(msg_id.to_owned(), req_digest);
        let fwd_key = st.forward_key.as_ref().unwrap();
        let (nonce, ct) =
            aes256_gcm_encrypt(fwd_key, &record_bytes, &mcc_a_b_fwd_aad(&route.context))
                .map_err(|_| CascadeError::new("encryption_failed"))?;
        let key_tag = forward_lookup_tag(fwd_key);

        let sealed_fwd = ForwardSealV2 {
            v: 2,
            context: route.context.clone(),
            nonce: hex::encode(nonce),
            ct: encode_canonical_base64_ct(&ct)?,
            key_tag,
        };
        let out = serde_json::json!({
            "opaque_mcc": 1,
            "leg": "a-x1",
            "conn_id": route.context,
            "route_token": route.opaque_token,
            "sealed_fwd": sealed_fwd,
        });
        let raw = jdump(&out).map_err(|_| CascadeError::new("invalid_json"))?;
        Ok(vec![MccAction::Send {
            peer: route.x1.clone(),
            message_type: MessageType::MccOpaqueFwd,
            payload: raw,
        }])
    }

    fn handle_mcc_opaque_fwd(
        &mut self,
        peer: &str,
        plaintext: &[u8],
        now_ms: u64,
    ) -> Result<Vec<MccAction>, CascadeError> {
        let now_s = (now_ms / 1000) as i64;
        let _ = parse_strict_json_object(plaintext, MAX_PLAINTEXT)
            .map_err(|_| CascadeError::new("invalid_continuation"))?;
        let msg: Value = jload(plaintext).map_err(|_| CascadeError::new("invalid_continuation"))?;
        if msg.get("opaque_mcc").and_then(Value::as_i64) != Some(1) {
            return Err(CascadeError::new("invalid_continuation_schema"));
        }
        let leg = msg
            .get("leg")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_continuation_schema"))?;
        let conn = msg
            .get("conn_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_continuation_schema"))?;
        let sealed_val = msg
            .get("sealed_fwd")
            .ok_or_else(|| CascadeError::new("invalid_continuation_schema"))?;
        let context = sealed_val
            .get("context")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_continuation_schema"))?;

        match leg {
            "a-x1" => {
                let obj = msg
                    .as_object()
                    .ok_or_else(|| CascadeError::new("invalid_continuation_schema"))?;
                if obj.len() != 5 || !obj.contains_key("route_token") {
                    return Err(CascadeError::new("invalid_continuation_schema"));
                }
                let token = obj["route_token"]
                    .as_str()
                    .ok_or_else(|| CascadeError::new("invalid_continuation_schema"))?;
                let handle = self
                    .x1_handles
                    .get(token)
                    .ok_or_else(|| CascadeError::new("unknown_continuation_handle"))?;
                if handle.req != peer || handle.context != conn || context != conn {
                    return Err(CascadeError::new("unknown_continuation_handle"));
                }
                let out = serde_json::json!({
                    "opaque_mcc": 1,
                    "leg": "x1-x2",
                    "conn_id": handle.conn_id,
                    "sealed_fwd": sealed_val,
                });
                let raw = jdump(&out).map_err(|_| CascadeError::new("invalid_json"))?;
                Ok(vec![MccAction::Send {
                    peer: handle.x2.clone(),
                    message_type: MessageType::MccOpaqueFwd,
                    payload: raw,
                }])
            }
            "x1-x2" => {
                let x2 = self
                    .x2_branches
                    .get(conn)
                    .ok_or_else(|| CascadeError::new("wrong_continuation_boundary"))?;
                if x2.x1 != peer || x2.context != context {
                    return Err(CascadeError::new("wrong_continuation_boundary"));
                }
                let out = serde_json::json!({
                    "opaque_mcc": 1,
                    "leg": "x2-b",
                    "conn_id": conn,
                    "sealed_fwd": sealed_val,
                });
                let raw = jdump(&out).map_err(|_| CascadeError::new("invalid_json"))?;
                Ok(vec![MccAction::Send {
                    peer: x2.dst.clone(),
                    message_type: MessageType::MccOpaqueFwd,
                    payload: raw,
                }])
            }
            "x2-b" => {
                let obj = msg
                    .as_object()
                    .ok_or_else(|| CascadeError::new("invalid_continuation_schema"))?;
                if obj.len() != 4 {
                    return Err(CascadeError::new("invalid_continuation_schema"));
                }
                let seal: ForwardSealV2 = serde_json::from_value(sealed_val.clone())
                    .map_err(|_| CascadeError::new("invalid_forward_wire_seal"))?;
                if seal.v != 2 {
                    return Err(CascadeError::new("invalid_forward_wire_seal"));
                }

                let matches: Vec<(String, String)> = self
                    .b_sessions
                    .iter()
                    .filter(|((_, ctx), st)| {
                        ctx == &seal.context
                            && st.conn_id == conn
                            && st.peer_x2 == peer
                            && forward_lookup_tag(&st.forward_key) == seal.key_tag
                    })
                    .map(|(k, _)| k.clone())
                    .collect();
                if matches.len() != 1 {
                    return Err(CascadeError::new("no_selected_continuation_route"));
                }
                let session_key = &matches[0];
                let (expected_sender, expected_apub, created_at_ms, req_count, has_msg_fn, raw) = {
                    let st = &self.b_sessions[session_key];
                    let nonce = decode_canonical_hex::<12>(&seal.nonce)
                        .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
                    let ct = decode_canonical_base64_ct(&seal.ct)?;
                    let raw = aes256_gcm_decrypt(
                        &st.forward_key,
                        &nonce,
                        &ct,
                        &mcc_a_b_fwd_aad(&seal.context),
                    )
                    .map_err(|_| CascadeError::new("capsule_authentication_failed"))?;
                    (
                        st.src.clone(),
                        st.a_pub.clone(),
                        st.created_at_ms,
                        st.requests.len(),
                        st.requests.keys().cloned().collect::<BTreeSet<String>>(),
                        raw,
                    )
                };

                let record = parse_strict_json_object(&raw, MAX_PLAINTEXT)
                    .map_err(|_| CascadeError::new("invalid_json"))?;
                let verified = self.security.verify_signed(
                    &record,
                    &seal.context,
                    Some(&expected_sender),
                    "forward",
                    "continuation",
                    now_s,
                )?;
                let req = self.validate_verified_request(&verified, false)?;
                if req.a_pub != expected_apub || req.conn_id != seal.context {
                    return Err(CascadeError::new("changed_continuation_key"));
                }
                if now_ms.saturating_sub(created_at_ms) > ROUTE_TTL_MS {
                    return Err(CascadeError::new("expired_continuation_route"));
                }
                if req_count >= MAX_REQUESTS && !has_msg_fn.contains(&verified.message_id) {
                    return Err(CascadeError::new("request_capacity"));
                }

                match self.security.admit(&verified, now_s)? {
                    AdmitStatus::New => {}
                    AdmitStatus::Duplicate => return Ok(Vec::new()),
                    AdmitStatus::Delivered => {
                        return self.replay_cached_response(
                            &verified,
                            conn,
                            &req.request_digest,
                            now_ms,
                        );
                    }
                }
                if !self.security.claim_delivery(&verified, now_s)? {
                    return Ok(Vec::new());
                }

                if let Some(st) = self.b_sessions.get_mut(session_key) {
                    st.requests
                        .insert(verified.message_id.clone(), req.request_digest.clone());
                }

                let meta = DeliveredIkeMeta {
                    src: verified.sender.clone(),
                    dst: self.security.name().to_owned(),
                    x1: String::new(),
                    x2: peer.to_owned(),
                    conn_id: conn.to_owned(),
                    context: seal.context.clone(),
                    direction: "fwd".to_owned(),
                    ike_src_ip: req.ike_src_ip,
                    ike_src_port: req.ike_src_port,
                    ike_dst_ip: req.ike_dst_ip,
                    ike_dst_port: req.ike_dst_port,
                    udp_port: req.udp_port,
                    opaque_token: String::new(),
                    expected_copies: 1,
                    copy_id: 0,
                    message_key: verified.message_key.clone(),
                };
                let proof =
                    LocalDeliveryProof::mint(req.payload, meta, verified.message_key.clone(), 0);
                self.inflight.insert(
                    (verified.message_key.clone(), 0),
                    InFlightDelivery {
                        verified: verified.clone(),
                        is_initial: false,
                        direction_forward: true,
                        sender: verified.sender,
                        context: seal.context,
                        prev_initiator_route: None,
                    },
                );
                Ok(vec![MccAction::DeliverIke {
                    proof: Box::new(proof),
                }])
            }
            _ => Err(CascadeError::new("invalid_continuation_stage")),
        }
    }

    fn validate_verified_request(
        &self,
        verified: &VerifiedMessage,
        initial: bool,
    ) -> Result<ValidatedRequest, CascadeError> {
        let body = verified.body_map()?;
        const REQ_FIELDS: [&str; 12] = [
            "ike_payload",
            "ike_length",
            "ike_src_ip",
            "ike_src_port",
            "ike_dst_ip",
            "ike_dst_port",
            "udp_port",
            "a_to_b_ke",
            "transport_conn",
            "budget",
            "selection",
            "request_digest",
        ];
        if body.len() != REQ_FIELDS.len() || !REQ_FIELDS.iter().all(|f| body.contains_key(*f)) {
            return Err(CascadeError::new("invalid_protected_body"));
        }
        if body["selection"] != self.config.policy.to_canonical_value() {
            return Err(CascadeError::new("invalid_protected_body"));
        }

        let parsed = validate_ike_fields(verified, &body, false)?;
        let expected_src_ip = self
            .config
            .peers
            .get(&verified.sender)
            .ok_or_else(|| CascadeError::new("unknown_node"))?
            .to_string();
        let expected_dst_ip = self
            .config
            .peers
            .get(self.security.name())
            .ok_or_else(|| CascadeError::new("unknown_node"))?
            .to_string();
        let req_digest = body["request_digest"].as_str().unwrap_or("");
        if parsed.ike_src_ip != expected_src_ip
            || parsed.ike_dst_ip != expected_dst_ip
            || req_digest != sha256_hex(&parsed.payload)
        {
            return Err(CascadeError::new("invalid_request_binding"));
        }

        let CanonicalValue::Array(ref budget) = body["budget"] else {
            return Err(CascadeError::new("invalid_copy_budget"));
        };
        if budget.len() != 3 {
            return Err(CascadeError::new("invalid_copy_budget"));
        }
        let mut nums = [0usize; 3];
        for (idx, item) in budget.iter().enumerate() {
            let Some(v) = item
                .as_i64()
                .filter(|&n| (1..=MAX_COPIES as i64).contains(&n))
            else {
                return Err(CascadeError::new("invalid_copy_budget"));
            };
            nums[idx] = v as usize;
        }
        if nums[0] * nums[1] * nums[2] != verified.expected_copies
            || (!initial && (nums != [1, 1, 1] || verified.expected_copies != 1))
        {
            return Err(CascadeError::new("invalid_copy_budget"));
        }

        let conn_id = body["transport_conn"]
            .as_str()
            .filter(|s| s.len() == 32)
            .ok_or_else(|| CascadeError::new("invalid_transport_binding"))?
            .to_owned();
        let a_pub = body["a_to_b_ke"]
            .as_str()
            .ok_or_else(|| CascadeError::new("invalid_endpoint_key"))?
            .to_owned();
        X25519PublicKey::from_hex(&a_pub).map_err(|_| CascadeError::new("invalid_endpoint_key"))?;

        Ok(ValidatedRequest {
            payload: parsed.payload,
            ike_src_ip: parsed.ike_src_ip,
            ike_src_port: parsed.ike_src_port,
            ike_dst_ip: parsed.ike_dst_ip,
            ike_dst_port: parsed.ike_dst_port,
            udp_port: parsed.udp_port,
            a_pub,
            conn_id,
            request_digest: req_digest.to_owned(),
        })
    }
}

struct ParsedIkeBody {
    payload: Vec<u8>,
    ike_src_ip: String,
    ike_src_port: u16,
    ike_dst_ip: String,
    ike_dst_port: u16,
    udp_port: u16,
}

struct ValidatedRequest {
    payload: Vec<u8>,
    ike_src_ip: String,
    ike_src_port: u16,
    ike_dst_ip: String,
    ike_dst_port: u16,
    udp_port: u16,
    a_pub: String,
    conn_id: String,
    request_digest: String,
}

struct ControlHandshakeHeader {
    initiator_spi: [u8; 8],
    exchange_type: u8,
    message_id: u32,
    is_response: bool,
    msg_id_str: String,
}

fn parse_control_handshake(
    udp_port: u16,
    payload: &[u8],
) -> Result<ControlHandshakeHeader, CascadeError> {
    match udp_port {
        500 | 4500 => {
            let hdr = parse_ikev2_packet(udp_port, payload)
                .map_err(|_| CascadeError::new("invalid_ike_message_binding"))?;
            Ok(ControlHandshakeHeader {
                initiator_spi: hdr.initiator_spi,
                exchange_type: hdr.exchange_type,
                message_id: hdr.message_id,
                is_response: hdr.is_response(),
                msg_id_str: format!("{}:{}", hdr.exchange_type, hdr.message_id),
            })
        }
        WG_OVERLAY_CONTROL_PORT => {
            let wg = parse_wireguard_packet_rfc(payload)
                .map_err(|_| CascadeError::new("invalid_wg_handshake_binding"))?;
            if wg.is_transport() {
                return Err(CascadeError::new("wg_transport_forbidden_in_overlay"));
            }
            match wg.message_type {
                WireGuardMessageType::HandshakeInitiation => {
                    let idx = wg
                        .sender_index
                        .ok_or_else(|| CascadeError::new("invalid_wg_handshake_binding"))?;
                    let le = idx.to_le_bytes();
                    Ok(ControlHandshakeHeader {
                        initiator_spi: [b'W', b'G', 0, 0, le[0], le[1], le[2], le[3]],
                        exchange_type: 1,
                        message_id: idx,
                        is_response: false,
                        msg_id_str: format!("wg:1:{idx}"),
                    })
                }
                WireGuardMessageType::HandshakeResponse | WireGuardMessageType::CookieReply => {
                    let idx = wg
                        .receiver_index
                        .ok_or_else(|| CascadeError::new("invalid_wg_handshake_binding"))?;
                    let le = idx.to_le_bytes();
                    Ok(ControlHandshakeHeader {
                        initiator_spi: [b'W', b'G', 0, 0, le[0], le[1], le[2], le[3]],
                        exchange_type: 1,
                        message_id: idx,
                        is_response: true,
                        msg_id_str: format!("wg:1:{idx}"),
                    })
                }
                WireGuardMessageType::TransportData => {
                    Err(CascadeError::new("wg_transport_forbidden_in_overlay"))
                }
            }
        }
        _ => Err(CascadeError::new("invalid_ike_port")),
    }
}

fn validate_ike_fields(
    verified: &VerifiedMessage,
    body: &BTreeMap<String, CanonicalValue>,
    expected_response: bool,
) -> Result<ParsedIkeBody, CascadeError> {
    let ike_len = body
        .get("ike_length")
        .and_then(CanonicalValue::as_i64)
        .filter(|&n| (28..=MAX_IKE as i64).contains(&n))
        .ok_or_else(|| CascadeError::new("ike_size_limit"))? as usize;
    let payload_hex = body
        .get("ike_payload")
        .and_then(CanonicalValue::as_str)
        .ok_or_else(|| CascadeError::new("ike_length_mismatch"))?;
    let payload = cco_crypto::decode_canonical_hex_vec(payload_hex, MAX_IKE)
        .map_err(|_| CascadeError::new("ike_length_mismatch"))?;
    if payload.len() != ike_len {
        return Err(CascadeError::new("ike_length_mismatch"));
    }

    let get_port = |k: &str| -> Result<u16, CascadeError> {
        let p = body
            .get(k)
            .and_then(CanonicalValue::as_i64)
            .ok_or_else(|| CascadeError::new("invalid_ike_port"))?;
        if p != 500 && p != 4500 && p != i64::from(WG_OVERLAY_CONTROL_PORT) {
            return Err(CascadeError::new("invalid_ike_port"));
        }
        Ok(p as u16)
    };
    let ike_src_port = get_port("ike_src_port")?;
    let ike_dst_port = get_port("ike_dst_port")?;
    let udp_port = get_port("udp_port")?;
    if ike_src_port != udp_port || ike_dst_port != udp_port {
        return Err(CascadeError::new("inconsistent_ike_ports"));
    }

    let get_ip = |k: &str| -> Result<String, CascadeError> {
        let s = body
            .get(k)
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_ike_address"))?;
        let parsed: Ipv4Addr = s
            .parse()
            .map_err(|_| CascadeError::new("invalid_ike_address"))?;
        if parsed.to_string() != s {
            return Err(CascadeError::new("invalid_ike_address"));
        }
        Ok(s.to_owned())
    };
    let ike_src_ip = get_ip("ike_src_ip")?;
    let ike_dst_ip = get_ip("ike_dst_ip")?;

    let hdr = parse_control_handshake(udp_port, &payload)?;
    if hdr.is_response != expected_response || hdr.msg_id_str != verified.message_id {
        return Err(CascadeError::new("invalid_ike_message_binding"));
    }

    Ok(ParsedIkeBody {
        payload,
        ike_src_ip,
        ike_src_port,
        ike_dst_ip,
        ike_dst_port,
        udp_port,
    })
}

fn check_no_contradictory_wrapper(
    outer: &BTreeMap<String, CanonicalValue>,
    req: &ValidatedRequest,
) -> Result<(), CascadeError> {
    if let Some(v) = outer.get("ike_payload") {
        if v.as_str() != Some(hex::encode(&req.payload).as_str()) {
            return Err(CascadeError::new("contradictory_wrapper"));
        }
    }
    if let Some(v) = outer.get("a_to_b_ke") {
        if v.as_str() != Some(req.a_pub.as_str()) {
            return Err(CascadeError::new("contradictory_wrapper"));
        }
    }
    if let Some(v) = outer.get("ike_dst_ip") {
        if v.as_str() != Some(req.ike_dst_ip.as_str()) {
            return Err(CascadeError::new("contradictory_wrapper"));
        }
    }
    if let Some(v) = outer.get("ike_dst_port") {
        if v.as_i64() != Some(req.ike_dst_port as i64) {
            return Err(CascadeError::new("contradictory_wrapper"));
        }
    }
    if let Some(v) = outer.get("udp_port") {
        if v.as_i64() != Some(req.udp_port as i64) {
            return Err(CascadeError::new("contradictory_wrapper"));
        }
    }
    Ok(())
}

fn forward_lookup_tag(key: &Key256) -> String {
    let mut input = Vec::with_capacity(27 + 32);
    input.extend_from_slice(b"mcc-auth-forward-lookup-v1:");
    input.extend_from_slice(key.as_bytes());
    sha256_hex(&input)[..32].to_owned()
}

fn build_x2_inner_object(
    context: &str,
    conn_id: &str,
    branch_id: &str,
    dst: &str,
    x1: &str,
    x2: &str,
    sealed_b: &CapsuleV2,
) -> BTreeMap<String, CanonicalValue> {
    let mut sb = BTreeMap::new();
    sb.insert("v".to_owned(), CanonicalValue::Int(sealed_b.v));
    sb.insert(
        "epk".to_owned(),
        CanonicalValue::String(sealed_b.epk.clone()),
    );
    sb.insert(
        "nonce".to_owned(),
        CanonicalValue::String(sealed_b.nonce.clone()),
    );
    sb.insert("ct".to_owned(), CanonicalValue::String(sealed_b.ct.clone()));

    let mut inner = BTreeMap::new();
    inner.insert("auth_mcc".to_owned(), CanonicalValue::Int(1));
    inner.insert("opaque_mcc".to_owned(), CanonicalValue::Int(1));
    inner.insert("mcc_carry_ike".to_owned(), CanonicalValue::Bool(true));
    inner.insert(
        "mcc_session_id".to_owned(),
        CanonicalValue::String(context.to_owned()),
    );
    inner.insert(
        "ab_context".to_owned(),
        CanonicalValue::String(context.to_owned()),
    );
    inner.insert(
        "conn_id".to_owned(),
        CanonicalValue::String(conn_id.to_owned()),
    );
    inner.insert(
        "branch_id".to_owned(),
        CanonicalValue::String(branch_id.to_owned()),
    );
    inner.insert("dst".to_owned(), CanonicalValue::String(dst.to_owned()));
    inner.insert("x1".to_owned(), CanonicalValue::String(x1.to_owned()));
    inner.insert("x2".to_owned(), CanonicalValue::String(x2.to_owned()));
    inner.insert("sealed_b".to_owned(), CanonicalValue::Object(sb));
    inner
}

fn capsule_v2_from_canonical(
    obj: &BTreeMap<String, CanonicalValue>,
) -> Result<CapsuleV2, CascadeError> {
    if obj.len() != 4 {
        return Err(CascadeError::new("invalid_wire_seal"));
    }
    let v = obj
        .get("v")
        .and_then(CanonicalValue::as_i64)
        .ok_or_else(|| CascadeError::new("invalid_wire_seal"))?;
    let epk = obj
        .get("epk")
        .and_then(CanonicalValue::as_str)
        .ok_or_else(|| CascadeError::new("invalid_wire_seal"))?
        .to_owned();
    let nonce = obj
        .get("nonce")
        .and_then(CanonicalValue::as_str)
        .ok_or_else(|| CascadeError::new("invalid_wire_seal"))?
        .to_owned();
    let ct = obj
        .get("ct")
        .and_then(CanonicalValue::as_str)
        .ok_or_else(|| CascadeError::new("invalid_wire_seal"))?
        .to_owned();
    Ok(CapsuleV2 { v, epk, nonce, ct })
}

fn batch_start_branches(
    base: MccStartMsg,
    branches: Vec<MccStartBranch>,
) -> Result<Vec<MccStartMsg>, CascadeError> {
    const MAX_BATCH_BYTES: usize = 28_000;
    let mut batches = Vec::new();
    let mut current = Vec::new();
    for b in branches {
        let mut trial = base.clone();
        trial.branches = current.clone();
        trial.branches.push(b.clone());
        let size = jdump(&trial)
            .map_err(|_| CascadeError::new("invalid_json"))?
            .len();
        if size > MAX_BATCH_BYTES {
            if current.is_empty() {
                return Err(CascadeError::new("one_capsule_exceeds_link_budget"));
            }
            let mut flush = base.clone();
            flush.branches = current;
            batches.push(flush);

            let mut single = base.clone();
            single.branches = vec![b.clone()];
            if jdump(&single)
                .map_err(|_| CascadeError::new("invalid_json"))?
                .len()
                > MAX_BATCH_BYTES
            {
                return Err(CascadeError::new("one_capsule_exceeds_link_budget"));
            }
            current = vec![b];
        } else {
            current.push(b);
        }
    }
    if !current.is_empty() {
        let mut flush = base;
        flush.branches = current;
        batches.push(flush);
    }
    Ok(batches)
}
