#![forbid(unsafe_code)]
//! Universal H-hop Privacy Cascade Sans-I/O state machine (`H = 2..16+`).
//!
//! Security & privacy invariants (role-limited knowledge):
//! - Initiator `A` knows only its first hop `X1` and destination `B` (never `X2..Xm`).
//! - First relay `X1` knows only `A` and `X2`.
//! - Any interior relay `Xk` (`2 <= k <= m - 1`) knows only `X(k-1)` and `X(k+1)`; neither `A`,
//!   `B`, nor any other relay appears in its wire packets or active memory state.
//! - Last relay `Xm` knows only `X(m-1)` and `B`.
//! - Destination `B` knows only `Xm` and `A`.
//! - Wire frames carry **no plaintext `remaining`, `hops`, `total_hops`, or `visited` fields**;
//!   hop termination uses an opaque SHA-256 hash-chain `(hop_token, stop_tag)` and every wire
//!   message is padded to a constant size ([`CASCADE_FIXED_WIRE_BYTES`]).
//! - Supports both dissertation Chapter 3 next-hop models: [`HopSelectionModel::F3NoRep`]
//!   (simple path without repeats via local capsule fingerprint rejection, zero `visited` field)
//!   and [`HopSelectionModel::F4WithRep`] (stochastic non-adjacent repeats, enabling `m = 3..10+`
//!   even on a 4-node `{A, X1, X2, B}` topology).
//! - Supports `K` parallel independent chains ([`UniversalCascade::start_parallel_chains`]) with
//!   linear `O(K * m)` packet budget instead of exponential `O(2^m)`, first-arrival acceptance
//!   and deduplication on `B`, and automatic `CASCADE_CLOSE` cleanup of losing chains.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cco_crypto::{
    Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, Key256, UNIVERSAL_CASCADE_CAPSULE_AAD,
    X25519PublicKey, X25519SecretKey, aes256_gcm_decrypt, aes256_gcm_encrypt, constant_time_eq,
    decode_canonical_hex, derive_universal_cascade_capsule_key, derive_universal_cascade_route_key,
    random_bytes, sha256, sha256_hex, universal_cascade_packet_aad,
};
use cco_proto::{MessageType, jdump, jload};
use cco_trust::VerifiedRegistry;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::error::CascadeError;

/// Universal H-hop Cascade wire version (v2: opaque hop-token, fixed-size padding, F3/F4, K chains).
pub const CASCADE_VERSION: u64 = 2;

/// Default maximum permitted hop count for `UniversalCascade`.
pub const DEFAULT_MAX_HOPS: usize = 16;

/// Default number of parallel independent chains `K` (`O(K * m)` budget).
pub const DEFAULT_PARALLEL_CHAINS: usize = 2;

/// Maximum permitted parallel independent chains `K`.
pub const MAX_PARALLEL_CHAINS: usize = 16;

/// Fixed plaintext block size for endpoint capsules and data/back packets before AES-256-GCM.
/// Holds all standard WireGuard (`64..148 B`) and IKEv2 (`224..1400 B`) control messages in one
/// uniform size class so ciphertext length never leaks payload type or endpoint name lengths.
pub const CASCADE_BLOCK_PLAINTEXT_BYTES: usize = 2048;

/// Fixed plaintext size for the initiator self-detection guard (`source_guard`).
pub const CASCADE_SOURCE_GUARD_PLAINTEXT_BYTES: usize = 128;

/// Constant serialized JSON byte length for all standard `CASCADE_*` wire messages across every hop.
pub const CASCADE_FIXED_WIRE_BYTES: usize = 3584;

const HOP_STEP_DOMAIN: &[u8] = b"cco-cascade-hop-step-v2\0";
const HOP_STOP_DOMAIN: &[u8] = b"cco-cascade-hop-stop-v2\0";
const CAPSULE_SIG_DOMAIN: &[u8] = b"cco-cascade-capsule-sig-v2\0";
const MAX_PENDING_BACK_PER_CELL: usize = 8;

/// Next-hop selection model matching Chapter 3 of the dissertation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum HopSelectionModel {
    /// Model `F3`: no repeated intermediate relays (enforced locally via capsule fingerprint +
    /// `CASCADE_REJECT` without transmitting any `visited` list).
    #[serde(rename = "f3")]
    #[default]
    F3NoRep,
    /// Model `F4`: stochastic next-hop selection allowing non-adjacent relay repeats (`u -> u`
    /// forbidden, no `visited` list). Supports `m = 3..10+` even on a 4-node `{A, X1, X2, B}` lab.
    #[serde(rename = "f4")]
    F4WithRep,
}

impl HopSelectionModel {
    /// Canonical lowercase identifier (`"f3"` or `"f4"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::F3NoRep => "f3",
            Self::F4WithRep => "f4",
        }
    }
}

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

/// Advances an opaque 32-byte hop token by one SHA-256 hash-chain step.
fn hop_step(token: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 24 + 32];
    buf[..24].copy_from_slice(HOP_STEP_DOMAIN);
    buf[24..].copy_from_slice(token);
    sha256(&buf)
}

/// Computes the terminal stop commitment for a hop token.
fn hop_stop_commitment(token: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 24 + 32];
    buf[..24].copy_from_slice(HOP_STOP_DOMAIN);
    buf[24..].copy_from_slice(token);
    sha256(&buf)
}

/// Generates `(initial_hop_token, stop_tag)` for an exact `hops`-relay cascade (`hops >= 1`).
fn generate_hop_budget(hops: usize) -> ([u8; 32], [u8; 32]) {
    let initial = random_bytes::<32>();
    let mut cur = initial;
    for _ in 1..hops {
        cur = hop_step(&cur);
    }
    let stop_tag = hop_stop_commitment(&cur);
    (initial, stop_tag)
}

/// Returns `true` iff `stop_tag` is reachable from `token` within `max_hops` steps (anti-DoS bound).
fn is_stop_reachable_within(token: &[u8; 32], stop_tag: &[u8; 32], max_hops: usize) -> bool {
    let mut cur = *token;
    for _ in 0..max_hops {
        if constant_time_eq(&hop_stop_commitment(&cur), stop_tag) {
            return true;
        }
        cur = hop_step(&cur);
    }
    false
}

/// Pads arbitrary plaintext bytes into a uniform fixed-size block (`[u16 len][data][random pad]`).
fn pad_plaintext(pt: &[u8], min_block: usize) -> Result<Vec<u8>, CascadeError> {
    let needed = 2usize
        .checked_add(pt.len())
        .ok_or_else(|| CascadeError::new("payload_too_large"))?;
    if pt.len() > u16::MAX as usize {
        return Err(CascadeError::new("payload_too_large"));
    }
    let block_len = if needed <= min_block {
        min_block
    } else {
        needed.div_ceil(min_block) * min_block
    };
    let mut out = vec![0u8; block_len];
    out[..2].copy_from_slice(&(pt.len() as u16).to_be_bytes());
    out[2..2 + pt.len()].copy_from_slice(pt);
    // Random non-zero padding tail prevents plaintext pattern leakage prior to encryption.
    let mut idx = 2 + pt.len();
    while idx < block_len {
        let chunk = random_bytes::<32>();
        let take = (block_len - idx).min(32);
        out[idx..idx + take].copy_from_slice(&chunk[..take]);
        idx += take;
    }
    Ok(out)
}

/// Unpads a length-prefixed block produced by [`pad_plaintext`].
fn unpad_plaintext(padded: &[u8]) -> Result<&[u8], CascadeError> {
    if padded.len() < 2 {
        return Err(CascadeError::new("invalid_padded_plaintext"));
    }
    let real_len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if 2 + real_len > padded.len() {
        return Err(CascadeError::new("invalid_padded_plaintext"));
    }
    Ok(&padded[2..2 + real_len])
}

/// Pads a `CASCADE_*` wire JSON object to exact constant byte length ([`CASCADE_FIXED_WIRE_BYTES`],
/// or next 1024-byte class for oversized certificate-bearing IKEv2 packets).
fn pad_wire_message(mut obj: Map<String, Value>) -> Value {
    obj.remove("pad");
    let base_len = jdump(&Value::Object(obj.clone())).map_or(0, |b| b.len());
    // Adding `"pad":"..."` into a non-empty JSON object adds 9 overhead bytes (`,"pad":""`).
    let overhead = 9usize;
    let target = if base_len + overhead <= CASCADE_FIXED_WIRE_BYTES {
        CASCADE_FIXED_WIRE_BYTES
    } else {
        (base_len + overhead).div_ceil(1024) * 1024
    };
    let pad_len = target.saturating_sub(base_len + overhead);
    obj.insert("pad".to_owned(), Value::String("p".repeat(pad_len)));
    let val = Value::Object(obj);
    debug_assert_eq!(jdump(&val).map(|b| b.len()).unwrap_or(0), target);
    val
}

/// Builds canonical Ed25519 signing transcript for an endpoint capsule.
fn capsule_signature_input(
    source: &str,
    destination: &str,
    route_tag: &str,
    exchange_id: &str,
    hops: usize,
    expires_at_ms: i64,
    payload: &[u8],
) -> Vec<u8> {
    let payload_digest = sha256_hex(payload);
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(CAPSULE_SIG_DOMAIN);
    out.extend_from_slice(
        format!(
            "{source}|{destination}|{route_tag}|{exchange_id}|{hops}|{expires_at_ms}|{payload_digest}"
        )
        .as_bytes(),
    );
    out
}

/// Output action produced by the Sans-I/O [`UniversalCascade`] state machine.
#[derive(Debug, Clone, PartialEq)]
pub enum CascadeAction {
    /// Send a constant-size cascade protocol message to adjacent `peer`.
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

/// Node-local X25519 (+ optional Ed25519) identity and verified public-key directory (`CascadeIdentity`).
pub struct CascadeIdentity {
    name: String,
    private_key: X25519SecretKey,
    public_keys: BTreeMap<String, X25519PublicKey>,
    signing_key: Option<Ed25519SecretKey>,
    verification_keys: BTreeMap<String, Ed25519PublicKey>,
}

impl CascadeIdentity {
    /// Builds a [`CascadeIdentity`] directly from a verified Trust Registry v2 snapshot (X25519 only).
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

    /// Builds a fully authenticated [`CascadeIdentity`] (X25519 encryption + Ed25519 signatures)
    /// directly from a verified Trust Registry v2 snapshot.
    pub fn from_verified_registry_signed(
        name: impl Into<String>,
        private_key: X25519SecretKey,
        signing_key: Ed25519SecretKey,
        registry: &VerifiedRegistry,
    ) -> Result<Self, CascadeError> {
        let name = name.into();
        let mut pks = BTreeMap::new();
        let mut vks = BTreeMap::new();
        for (peer, rec) in registry.nodes() {
            if !rec.revoked {
                pks.insert(peer.clone(), rec.encryption);
                vks.insert(peer.clone(), rec.verification);
            }
        }
        let own_enc = pks
            .get(&name)
            .ok_or_else(|| CascadeError::new("unknown_node"))?;
        if *own_enc != private_key.public_key() {
            return Err(CascadeError::new("private_key_mismatch"));
        }
        let own_ver = vks
            .get(&name)
            .ok_or_else(|| CascadeError::new("unknown_node"))?;
        if *own_ver != signing_key.public_key() {
            return Err(CascadeError::new("private_key_mismatch"));
        }
        Ok(Self {
            name,
            private_key,
            public_keys: pks,
            signing_key: Some(signing_key),
            verification_keys: vks,
        })
    }

    /// Builds a [`CascadeIdentity`] from an explicit X25519 public-key directory.
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
            signing_key: None,
            verification_keys: BTreeMap::new(),
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

    /// Returns `true` when Ed25519 end-to-end signatures are enforced on endpoint capsules.
    #[must_use]
    pub fn has_ed25519_auth(&self) -> bool {
        self.signing_key.is_some() && !self.verification_keys.is_empty()
    }

    fn sign_capsule_bytes(&self, msg: &[u8]) -> Option<String> {
        self.signing_key.as_ref().map(|sk| sk.sign(msg).to_hex())
    }

    fn verify_capsule_signature(
        &self,
        source: &str,
        msg: &[u8],
        sig_hex: Option<&str>,
    ) -> Result<(), CascadeError> {
        if self.verification_keys.is_empty() {
            return Ok(());
        }
        let vk = self
            .verification_keys
            .get(source)
            .ok_or_else(|| CascadeError::new("unknown_signer"))?;
        let sig_str = sig_hex.ok_or_else(|| CascadeError::new("missing_capsule_signature"))?;
        let sig = Ed25519Signature::from_hex(sig_str)
            .map_err(|_| CascadeError::new("invalid_capsule_signature"))?;
        vk.verify_strict(msg, &sig)
            .map_err(|_| CascadeError::new("invalid_capsule_signature"))
    }

    /// Seals a JSON object to `recipient` using `universal-cascade-endpoint-v1` with fixed-block padding.
    pub fn seal_for(
        &self,
        recipient: &str,
        obj: &Value,
        min_block_bytes: usize,
    ) -> Result<Value, CascadeError> {
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
        let raw_pt = jdump(obj).map_err(|_| CascadeError::new("invalid_json"))?;
        let pt = pad_plaintext(&raw_pt, min_block_bytes)?;
        let (nonce, ct) = aes256_gcm_encrypt(&key, &pt, UNIVERSAL_CASCADE_CAPSULE_AAD)
            .map_err(|_| CascadeError::new("encryption_failed"))?;
        Ok(json!({
            "epk": epk.to_hex(),
            "nonce": hex::encode(nonce),
            "ct": STANDARD.encode(ct),
        }))
    }

    /// Attempts to open a padded capsule addressed to this node; returns `None` if not for us or invalid.
    #[must_use]
    pub fn try_open(&self, capsule: &Value) -> Option<Value> {
        let epk_hex = capsule.get("epk")?.as_str()?;
        let nonce_hex = capsule.get("nonce")?.as_str()?;
        let ct_b64 = capsule.get("ct")?.as_str()?;

        let epk = X25519PublicKey::from_hex(epk_hex).ok()?;
        let nonce = decode_canonical_hex::<12>(nonce_hex).ok()?;
        let ct = STANDARD.decode(ct_b64.as_bytes()).ok()?;
        if ct.len() > 262_144 {
            return None;
        }
        let own_pub = self.public_keys.get(&self.name)?;
        let shared = self.private_key.diffie_hellman(&epk).ok()?;
        let key = derive_universal_cascade_capsule_key(&shared, &epk, own_pub).ok()?;
        let padded_pt =
            aes256_gcm_decrypt(&key, &nonce, &ct, UNIVERSAL_CASCADE_CAPSULE_AAD).ok()?;
        let raw_pt = unpad_plaintext(&padded_pt).ok()?;
        jload(raw_pt).ok()
    }

    /// Derives the 256-bit end-to-end route key (`universal-cascade-route-v1`).
    pub fn route_key(&self, remote_peer: &str, route_tag: &str) -> Result<Key256, CascadeError> {
        let remote_pub = self
            .public_keys
            .get(remote_peer)
            .ok_or_else(|| CascadeError::new("unknown_node"))?;
        let salt = cco_crypto::decode_canonical_hex_vec(route_tag, 64)
            .map_err(|_| CascadeError::new("invalid_route_tag"))?;
        let shared = self
            .private_key
            .diffie_hellman(remote_pub)
            .map_err(|_| CascadeError::new("key_agreement_failed"))?;
        derive_universal_cascade_route_key(&shared, &salt)
            .map_err(|_| CascadeError::new("key_agreement_failed"))
    }
}

/// Ephemeral relay build state — scrubbed completely once the cell transitions to `active`.
#[derive(Debug, Clone)]
struct RelayBuildContext {
    next_hop_token: [u8; 32],
    stop_tag: [u8; 32],
    build_capsule: Value,
    source_guard: Value,
    route_fingerprint: String,
    rejected_peers: BTreeSet<String>,
}

/// Role-limited intermediate relay cell.
///
/// Notice: contains **no** total hop count `m`, **no** position index `k`, **no** `visited` list,
/// and **no** endpoint identities (`A`/`B`). Once `active`, `build_ctx` is dropped (`None`),
/// leaving ONLY `(inbound_handle, previous_peer, outbound_handle, next_peer, expires_at)`.
#[derive(Debug, Clone)]
struct RelayCell {
    inbound_handle: String,
    previous_peer: String,
    expires_at: f64,
    outbound_handle: String,
    next_peer: String,
    state: String,
    probe_handles: BTreeMap<String, String>,
    build_ctx: Option<RelayBuildContext>,
    /// Buffered reverse packets if `CASCADE_BACK` overtakes `CASCADE_ACCEPT` on UDP.
    pending_back: Vec<Value>,
}

struct EndpointRoute {
    local_handle: String,
    adjacent_peer: String,
    remote_peer: String,
    route_tag: String,
    exchange_id: String,
    chain_group_id: Option<String>,
    route_key: Key256,
    expires_at: f64,
    hops: usize,
    state: String,
    next_sequence: u64,
    seen_forward: BTreeSet<u64>,
    seen_reverse: BTreeSet<u64>,
    pending_forward: Vec<(u64, Vec<u8>, Map<String, Value>)>,
    pending_back: Vec<Value>,
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

/// Pure Sans-I/O H-hop privacy cascade state machine (`H = 2..max_hops`).
pub struct UniversalCascade {
    identity: CascadeIdentity,
    members: Vec<String>,
    max_hops: usize,
    route_ttl_s: f64,
    hop_model: HopSelectionModel,
    chooser: PeerChooser,

    // Relay cells indexed by inbound handle; outbound handle maps to owning inbound handle.
    relay_cells: BTreeMap<String, RelayCell>,
    relay_out_to_in: BTreeMap<String, String>,

    // Source routes (`A` side) + parallel chain groups (`K` independent chains -> first winner).
    source_routes: BTreeMap<String, EndpointRoute>,
    source_by_remote: BTreeMap<String, String>,
    pending_groups: BTreeMap<String, Vec<String>>,

    // Endpoint routes (`B` side) + exchange deduplication for `K` parallel chains.
    endpoint_routes: BTreeMap<String, EndpointRoute>,
    endpoint_by_remote: BTreeMap<String, String>,
    endpoint_by_tag: BTreeMap<String, String>,
    seen_exchanges: BTreeMap<String, (String, f64)>,

    seen_deliveries: BTreeMap<String, f64>,
}

impl UniversalCascade {
    /// Creates a new Universal H-hop Cascade state machine (defaults to [`HopSelectionModel::F3NoRep`]).
    pub fn new(
        identity: CascadeIdentity,
        members: Vec<String>,
        max_hops: usize,
        route_ttl_s: f64,
        chooser: Option<PeerChooser>,
    ) -> Result<Self, CascadeError> {
        Self::new_with_model(
            identity,
            members,
            max_hops,
            route_ttl_s,
            HopSelectionModel::F3NoRep,
            chooser,
        )
    }

    /// Creates a new Universal H-hop Cascade state machine with an explicit next-hop model (`F3` or `F4`).
    pub fn new_with_model(
        identity: CascadeIdentity,
        members: Vec<String>,
        max_hops: usize,
        route_ttl_s: f64,
        hop_model: HopSelectionModel,
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
            hop_model,
            chooser,
            relay_cells: BTreeMap::new(),
            relay_out_to_in: BTreeMap::new(),
            source_routes: BTreeMap::new(),
            source_by_remote: BTreeMap::new(),
            pending_groups: BTreeMap::new(),
            endpoint_routes: BTreeMap::new(),
            endpoint_by_remote: BTreeMap::new(),
            endpoint_by_tag: BTreeMap::new(),
            seen_exchanges: BTreeMap::new(),
            seen_deliveries: BTreeMap::new(),
        })
    }

    /// Returns this node's name.
    #[must_use]
    pub fn name(&self) -> &str {
        self.identity.name()
    }

    /// Returns the configured hop selection model (`F3` or `F4`).
    #[must_use]
    pub const fn hop_model(&self) -> HopSelectionModel {
        self.hop_model
    }

    /// Returns configured maximum permitted hop count.
    #[must_use]
    pub const fn max_hops(&self) -> usize {
        self.max_hops
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
        // Rounded integer milliseconds ensures constant numeric encoding length across hops.
        let exp_ms = (expires_at * 1000.0).round() as i64;
        m.insert("exp_ms".to_owned(), json!(exp_ms));
        m
    }

    fn check_message(&self, msg: &Value, now_secs: f64) -> Result<(String, f64), CascadeError> {
        if msg.get("v").and_then(Value::as_u64) != Some(CASCADE_VERSION) {
            return Err(CascadeError::new("unsupported_cascade_version"));
        }
        let handle = Self::valid_handle(msg.get("h"))?;
        let exp_ms = msg
            .get("exp_ms")
            .and_then(Value::as_i64)
            .ok_or_else(|| CascadeError::new("invalid_expiry"))?;
        let expires_at = (exp_ms as f64) / 1000.0;
        if !expires_at.is_finite() || expires_at <= now_secs {
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
        let raw_pt = jdump(&Self::wire_payload(payload, metadata))
            .map_err(|_| CascadeError::new("invalid_json"))?;
        let pt = pad_plaintext(&raw_pt, CASCADE_BLOCK_PLAINTEXT_BYTES)?;
        let aad = universal_cascade_packet_aad(&route.route_tag, direction, sequence);
        let (nonce, ct) = aes256_gcm_encrypt(&route.route_key, &pt, &aad)
            .map_err(|_| CascadeError::new("encryption_failed"))?;
        Ok(json!({
            "seq": sequence,
            "nonce": hex::encode(nonce),
            "ct": STANDARD.encode(ct),
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
        let ct_b64 = packet
            .get("ct")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("packet_authentication_failed"))?;
        let nonce = decode_canonical_hex::<12>(nonce_hex)
            .map_err(|_| CascadeError::new("packet_authentication_failed"))?;
        let ct = STANDARD
            .decode(ct_b64.as_bytes())
            .map_err(|_| CascadeError::new("packet_authentication_failed"))?;
        if ct.len() > 262_144 {
            return Err(CascadeError::new("packet_authentication_failed"));
        }
        let aad = universal_cascade_packet_aad(&route.route_tag, direction, seq);
        let padded_pt = aes256_gcm_decrypt(&route.route_key, &nonce, &ct, &aad)
            .map_err(|_| CascadeError::new("packet_authentication_failed"))?;
        let raw_pt = unpad_plaintext(&padded_pt)
            .map_err(|_| CascadeError::new("invalid_endpoint_payload"))?;
        let val = jload(raw_pt).map_err(|_| CascadeError::new("invalid_endpoint_payload"))?;
        let (payload, meta) = Self::open_wire_payload(&val)?;
        Ok((seq, payload, meta))
    }

    /// Initiates a single H-hop route (`hops >= 2`) from this node to `destination`.
    pub fn start_route(
        &mut self,
        destination: &str,
        hops: usize,
        payload: &[u8],
        metadata: Map<String, Value>,
        first_hop: Option<&str>,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        let exchange_id = Self::new_handle();
        let (action, _handle) = self.start_single_chain(
            destination,
            hops,
            payload,
            metadata,
            first_hop,
            &exchange_id,
            None,
            now_secs,
        )?;
        Ok(vec![action])
    }

    /// Initiates `parallel_chains` (`K >= 1`) independent H-hop chains to `destination` with a
    /// linear `O(K * hops)` packet budget.
    ///
    /// Destination `B` accepts and delivers ONLY the first chain to arrive for this exchange
    /// (deduplicating the remaining `K - 1` chains silently), and initiator `A` sends
    /// `CASCADE_CLOSE` on the remaining losing chains once the winning `CASCADE_ACCEPT` arrives.
    pub fn start_parallel_chains(
        &mut self,
        destination: &str,
        hops: usize,
        parallel_chains: usize,
        payload: &[u8],
        metadata: Map<String, Value>,
        now_secs: f64,
    ) -> Result<Vec<CascadeAction>, CascadeError> {
        self.cleanup(now_secs);
        let hop_count = validate_hop_count(hops, 2, self.max_hops)?;
        if parallel_chains == 0 || parallel_chains > MAX_PARALLEL_CHAINS {
            return Err(CascadeError::new("invalid_parallel_chains"));
        }
        if destination == self.identity.name() || !self.members.iter().any(|m| m == destination) {
            return Err(CascadeError::new("invalid_destination"));
        }

        let candidates: Vec<String> = self
            .members
            .iter()
            .filter(|m| m.as_str() != self.identity.name() && m.as_str() != destination)
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Err(CascadeError::new("no_candidates"));
        }

        let exchange_id = Self::new_handle();
        let group_id = (parallel_chains > 1).then(Self::new_handle);

        // Pick diverse first hops across the K parallel chains whenever available.
        let mut remaining_first = candidates.clone();
        let mut chosen_firsts = Vec::with_capacity(parallel_chains);
        for idx in 0..parallel_chains {
            if remaining_first.is_empty() {
                remaining_first = candidates.clone();
            }
            let picked = self.select_peer(&format!("first-hop-{idx}"), &remaining_first)?;
            if let Some(pos) = remaining_first.iter().position(|x| x == &picked) {
                remaining_first.remove(pos);
            }
            chosen_firsts.push(picked);
        }

        let mut actions = Vec::with_capacity(parallel_chains);
        let mut handles = Vec::with_capacity(parallel_chains);
        for first in chosen_firsts {
            let (act, handle) = self.start_single_chain(
                destination,
                hop_count,
                payload,
                metadata.clone(),
                Some(&first),
                &exchange_id,
                group_id.clone(),
                now_secs,
            )?;
            actions.push(act);
            handles.push(handle);
        }

        if let Some(gid) = group_id {
            self.pending_groups.insert(gid, handles);
        }
        Ok(actions)
    }

    #[allow(clippy::too_many_arguments)]
    fn start_single_chain(
        &mut self,
        destination: &str,
        hops: usize,
        payload: &[u8],
        metadata: Map<String, Value>,
        first_hop: Option<&str>,
        exchange_id: &str,
        chain_group_id: Option<String>,
        now_secs: f64,
    ) -> Result<(CascadeAction, String), CascadeError> {
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
        let exp_ms = (expires_at * 1000.0).round() as i64;
        let expires_at_norm = (exp_ms as f64) / 1000.0;
        let route_tag = Self::new_handle();
        let local_handle = Self::new_handle();
        let route_key = self.identity.route_key(destination, &route_tag)?;

        let route = EndpointRoute {
            local_handle: local_handle.clone(),
            adjacent_peer: selected_first.clone(),
            remote_peer: destination.to_owned(),
            route_tag: route_tag.clone(),
            exchange_id: exchange_id.to_owned(),
            chain_group_id,
            route_key,
            expires_at: expires_at_norm,
            hops: hop_count,
            state: "building".to_owned(),
            next_sequence: 1,
            seen_forward: BTreeSet::new(),
            seen_reverse: BTreeSet::new(),
            pending_forward: Vec::new(),
            pending_back: Vec::new(),
            initial_payload_digest: sha256_hex(payload),
            initial_payload: payload.to_vec(),
            initial_metadata: metadata.clone(),
            last_forward_payload: Vec::new(),
            last_forward_metadata: Map::new(),
        };
        self.source_routes.insert(local_handle.clone(), route);
        // Point `source_by_remote` to this route unless an active route already exists,
        // or if we are intentionally starting a fresh exchange.
        let keep_existing_active = self
            .source_by_remote
            .get(destination)
            .and_then(|h| self.source_routes.get(h))
            .is_some_and(|r| r.state == "active" && r.exchange_id == exchange_id);
        if !keep_existing_active {
            self.source_by_remote
                .insert(destination.to_owned(), local_handle.clone());
        }

        let mut endpoint_map = Map::new();
        endpoint_map.insert("v".to_owned(), json!(CASCADE_VERSION));
        endpoint_map.insert("source".to_owned(), json!(self.identity.name()));
        endpoint_map.insert("destination".to_owned(), json!(destination));
        endpoint_map.insert("route_tag".to_owned(), json!(route_tag));
        endpoint_map.insert("exchange_id".to_owned(), json!(exchange_id));
        endpoint_map.insert("hops".to_owned(), json!(hop_count));
        endpoint_map.insert("exp_ms".to_owned(), json!(exp_ms));
        endpoint_map.insert("initial".to_owned(), Self::wire_payload(payload, &metadata));

        let sig_input = capsule_signature_input(
            self.identity.name(),
            destination,
            &route_tag,
            exchange_id,
            hop_count,
            exp_ms,
            payload,
        );
        if let Some(sig_hex) = self.identity.sign_capsule_bytes(&sig_input) {
            endpoint_map.insert("sig".to_owned(), json!(sig_hex));
        }

        let capsule = self.identity.seal_for(
            destination,
            &Value::Object(endpoint_map),
            CASCADE_BLOCK_PLAINTEXT_BYTES,
        )?;
        let source_guard = self.identity.seal_for(
            self.identity.name(),
            &json!({
                "v": CASCADE_VERSION,
                "guard": "source",
                "route_tag": route_tag,
            }),
            CASCADE_SOURCE_GUARD_PLAINTEXT_BYTES,
        )?;

        let (hop_token, stop_tag) = generate_hop_budget(hop_count);
        let mut msg = Self::base_message(&local_handle, expires_at_norm);
        msg.insert("hop_token".to_owned(), json!(hex::encode(hop_token)));
        msg.insert("stop_tag".to_owned(), json!(hex::encode(stop_tag)));
        msg.insert("capsule".to_owned(), capsule);
        msg.insert("source_guard".to_owned(), source_guard);

        Ok((
            CascadeAction::Send {
                peer: selected_first,
                message_type: MessageType::CascadeBuild,
                message: pad_wire_message(msg),
            },
            local_handle,
        ))
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
            message: pad_wire_message(msg),
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
            message: pad_wire_message(msg),
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
        let hop_token_hex = message
            .get("hop_token")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_build_message"))?;
        let stop_tag_hex = message
            .get("stop_tag")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_build_message"))?;
        let hop_token = decode_canonical_hex::<32>(hop_token_hex)
            .map_err(|_| CascadeError::new("invalid_build_message"))?;
        let stop_tag = decode_canonical_hex::<32>(stop_tag_hex)
            .map_err(|_| CascadeError::new("invalid_build_message"))?;

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

        // Anti-DoS bound check without exposing or storing any hop counter.
        if !is_stop_reachable_within(&hop_token, &stop_tag, self.max_hops) {
            return Err(CascadeError::new("invalid_remaining_hops"));
        }
        if self.relay_cells.contains_key(&inbound_handle) {
            return Ok(Vec::new());
        }

        let endpoint_marker = self.identity.try_open(&capsule);
        let source_marker = self.identity.try_open(&source_guard);
        let fingerprint =
            sha256_hex(&jdump(&capsule).map_err(|_| CascadeError::new("invalid_json"))?);
        let already_visited = self.hop_model == HopSelectionModel::F3NoRep
            && self.relay_cells.values().any(|c| {
                c.build_ctx
                    .as_ref()
                    .is_some_and(|ctx| ctx.route_fingerprint == fingerprint)
            });
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
                message: pad_wire_message(rejected),
            }]);
        }

        let is_terminal = constant_time_eq(&hop_stop_commitment(&hop_token), &stop_tag);
        let next_hop_token = hop_step(&hop_token);

        let cell = RelayCell {
            inbound_handle: inbound_handle.clone(),
            previous_peer: peer.to_owned(),
            expires_at,
            outbound_handle: String::new(),
            next_peer: String::new(),
            state: "building".to_owned(),
            probe_handles: BTreeMap::new(),
            build_ctx: Some(RelayBuildContext {
                next_hop_token,
                stop_tag,
                build_capsule: capsule.clone(),
                source_guard,
                route_fingerprint: fingerprint,
                rejected_peers: BTreeSet::new(),
            }),
            pending_back: Vec::new(),
        };
        self.relay_cells.insert(inbound_handle.clone(), cell);

        if !is_terminal {
            return self.advance_relay(&inbound_handle);
        }

        // Terminal relay (`stop_commitment(hop_token) == stop_tag`): probe all other members
        // with distinct per-peer handles without knowing which peer is `B`.
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
                    message: pad_wire_message(probe),
                });
            }
        }
        Ok(actions)
    }

    fn advance_relay(&mut self, inbound_handle: &str) -> Result<Vec<CascadeAction>, CascadeError> {
        let (candidates, next_hop_token, stop_tag, prev_peer, expires_at, capsule, source_guard) = {
            let cell = self
                .relay_cells
                .get(inbound_handle)
                .ok_or_else(|| CascadeError::new("missing_relay_cell"))?;
            let ctx = cell
                .build_ctx
                .as_ref()
                .ok_or_else(|| CascadeError::new("missing_relay_cell"))?;
            let cands: Vec<String> = match self.hop_model {
                HopSelectionModel::F3NoRep => self
                    .members
                    .iter()
                    .filter(|m| {
                        m.as_str() != self.identity.name()
                            && m.as_str() != cell.previous_peer.as_str()
                            && !ctx.rejected_peers.contains(m.as_str())
                    })
                    .cloned()
                    .collect(),
                HopSelectionModel::F4WithRep => {
                    // Exact F4 model: forbid self-transitions (`u -> u`) and already-rejected
                    // peers for this hop; non-adjacent repeats (`u -> v -> u`) are allowed.
                    self.members
                        .iter()
                        .filter(|m| {
                            m.as_str() != self.identity.name()
                                && !ctx.rejected_peers.contains(m.as_str())
                        })
                        .cloned()
                        .collect()
                }
            };
            (
                cands,
                ctx.next_hop_token,
                ctx.stop_tag,
                cell.previous_peer.clone(),
                cell.expires_at,
                ctx.build_capsule.clone(),
                ctx.source_guard.clone(),
            )
        };

        if candidates.is_empty() {
            let rejected = Self::base_message(inbound_handle, expires_at);
            self.remove_relay_cell(inbound_handle);
            return Ok(vec![CascadeAction::Send {
                peer: prev_peer,
                message_type: MessageType::CascadeReject,
                message: pad_wire_message(rejected),
            }]);
        }

        let next_peer = self.select_peer("relay-next", &candidates)?;
        let outbound_handle = Self::new_handle();
        if let Some(cell) = self.relay_cells.get_mut(inbound_handle) {
            cell.outbound_handle = outbound_handle.clone();
            cell.next_peer = next_peer.clone();
        }
        self.relay_out_to_in
            .insert(outbound_handle.clone(), inbound_handle.to_owned());

        let mut forwarded = Self::base_message(&outbound_handle, expires_at);
        forwarded.insert("hop_token".to_owned(), json!(hex::encode(next_hop_token)));
        forwarded.insert("stop_tag".to_owned(), json!(hex::encode(stop_tag)));
        forwarded.insert("capsule".to_owned(), capsule);
        forwarded.insert("source_guard".to_owned(), source_guard);
        Ok(vec![CascadeAction::Send {
            peer: next_peer,
            message_type: MessageType::CascadeBuild,
            message: pad_wire_message(forwarded),
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
                if let Some(ref mut ctx) = cell.build_ctx {
                    ctx.rejected_peers.insert(peer.to_owned());
                }
                cell.outbound_handle.clear();
                cell.next_peer.clear();
            }
            return self.advance_relay(&in_handle);
        }
        if let Some(source) = self.source_routes.get(&handle) {
            if source.adjacent_peer == peer {
                let maybe_group = source.chain_group_id.clone();
                let should_rebuild = if let Some(ref gid) = maybe_group {
                    // Only rebuild if this was the last surviving chain in its parallel group.
                    self.pending_groups
                        .get(gid)
                        .is_none_or(|hs| hs.iter().filter(|h| h.as_str() != handle).count() == 0)
                } else {
                    false
                };
                if should_rebuild {
                    let payload = source.initial_payload.clone();
                    let meta = source.initial_metadata.clone();
                    return self.rebuild_source(&handle, &payload, meta, &[peer], now_secs);
                }
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
                message: pad_wire_message(aborted),
            }]);
        }

        let (payload, meta, other_alive) = {
            let source = self
                .source_routes
                .get(&handle)
                .ok_or_else(|| CascadeError::new("unknown_route_state"))?;
            if source.adjacent_peer != peer {
                return Err(CascadeError::new("wrong_neighbor"));
            }
            let other_alive = source.chain_group_id.as_ref().is_some_and(|gid| {
                self.pending_groups
                    .get(gid)
                    .is_some_and(|hs| hs.iter().any(|h| h != &handle))
            });
            let (p, m) = if !source.last_forward_payload.is_empty() {
                (
                    source.last_forward_payload.clone(),
                    source.last_forward_metadata.clone(),
                )
            } else {
                (
                    source.initial_payload.clone(),
                    source.initial_metadata.clone(),
                )
            };
            (p, m, other_alive)
        };
        if other_alive {
            self.remove_source_route(&handle);
            return Ok(Vec::new());
        }
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
                            if let Some(ref mut ctx) = cell.build_ctx {
                                ctx.rejected_peers.insert(peer.to_owned());
                            }
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
                            message: pad_wire_message(aborted),
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
        let exchange_id = endpoint
            .get("exchange_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?
            .to_owned();
        let hops_raw = endpoint
            .get("hops")
            .and_then(Value::as_u64)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?
            as usize;
        let hops = validate_hop_count(hops_raw, 2, self.max_hops)?;
        let capsule_exp_ms = endpoint
            .get("exp_ms")
            .and_then(Value::as_i64)
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?;
        let capsule_expiry = (capsule_exp_ms as f64) / 1000.0;
        if capsule_expiry <= now_secs || (capsule_expiry - expires_at).abs() > 1.0 {
            return Err(CascadeError::new("capsule_expiry_mismatch"));
        }
        let initial = endpoint
            .get("initial")
            .ok_or_else(|| CascadeError::new("invalid_endpoint_capsule"))?;
        let (initial_payload, mut initial_meta) = Self::open_wire_payload(initial)?;

        // Fail-closed Ed25519 signature verification when verification keys are pinned.
        let sig_input = capsule_signature_input(
            &source,
            destination,
            &route_tag,
            &exchange_id,
            hops,
            capsule_exp_ms,
            &initial_payload,
        );
        self.identity.verify_capsule_signature(
            &source,
            &sig_input,
            endpoint.get("sig").and_then(Value::as_str),
        )?;

        // Idempotent re-accept for exact same (route_tag, handle, peer).
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
                        message: pad_wire_message(accept),
                    }]);
                }
            }
            return Ok(Vec::new());
        }

        // First-chain-wins deduplication across `K` parallel chains!
        // Losing parallel chains are silently ignored so their terminal `Xm` never learns `B`.
        if self
            .seen_exchanges
            .get(&exchange_id)
            .is_some_and(|(_, exp)| *exp > now_secs)
        {
            return Ok(Vec::new());
        }

        let route_key = self.identity.route_key(&source, &route_tag)?;
        let route_exp = expires_at.min(capsule_expiry);
        let route = EndpointRoute {
            local_handle: handle.clone(),
            adjacent_peer: peer.to_owned(),
            remote_peer: source.clone(),
            route_tag: route_tag.clone(),
            exchange_id: exchange_id.clone(),
            chain_group_id: None,
            route_key,
            expires_at: route_exp,
            hops,
            state: "active".to_owned(),
            next_sequence: 1,
            seen_forward: BTreeSet::new(),
            seen_reverse: BTreeSet::new(),
            pending_forward: Vec::new(),
            pending_back: Vec::new(),
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

        self.seen_exchanges
            .insert(exchange_id, (handle.clone(), route_exp));
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
                message: pad_wire_message(accept),
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
            let (prev_peer, expires_at, buffered_back) = {
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
                    cell.outbound_handle = handle.clone();
                    cell.next_peer = peer.to_owned();
                } else if cell.next_peer != peer || cell.outbound_handle != handle {
                    return Err(CascadeError::new("wrong_neighbor"));
                }
                cell.state = "active".to_owned();
                // Scrub ephemeral build context immediately: active relay holds ONLY neighbors + handles!
                cell.build_ctx = None;
                let back = std::mem::take(&mut cell.pending_back);
                (cell.previous_peer.clone(), cell.expires_at, back)
            };
            let mut actions = Vec::with_capacity(1 + buffered_back.len());
            let mut accepted = Self::base_message(&in_handle, expires_at);
            accepted.insert("proof".to_owned(), proof);
            actions.push(CascadeAction::Send {
                peer: prev_peer.clone(),
                message_type: MessageType::CascadeAccept,
                message: pad_wire_message(accepted),
            });
            for pkt in buffered_back {
                let mut forwarded = Self::base_message(&in_handle, expires_at);
                forwarded.insert("packet".to_owned(), pkt);
                actions.push(CascadeAction::Send {
                    peer: prev_peer.clone(),
                    message_type: MessageType::CascadeBack,
                    message: pad_wire_message(forwarded),
                });
            }
            return Ok(actions);
        }

        let (remote_peer, group_id, already_active, pending_fwd, pending_back) = {
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
            let pending_fwd = std::mem::take(&mut route.pending_forward);
            let pending_back = std::mem::take(&mut route.pending_back);
            (
                route.remote_peer.clone(),
                route.chain_group_id.take(),
                already_active,
                pending_fwd,
                pending_back,
            )
        };

        // Mark this winning chain as the active source route to `remote_peer`.
        self.source_by_remote
            .insert(remote_peer.clone(), handle.clone());

        let mut actions = Vec::new();
        let mut inherited_pending = pending_fwd;

        // Cleanly close all losing parallel chains (`K - 1`) from the same group and salvage
        // any queued forward packets onto the winning active chain.
        if let Some(gid) = group_id {
            if let Some(group_handles) = self.pending_groups.remove(&gid) {
                for sibling_h in group_handles {
                    if sibling_h == handle {
                        continue;
                    }
                    if let Some(sibling) = self.source_routes.remove(&sibling_h) {
                        for (_, pp, pm) in sibling.pending_forward {
                            inherited_pending.push((0, pp, pm));
                        }
                        let close_msg =
                            Self::base_message(&sibling.local_handle, sibling.expires_at);
                        actions.push(CascadeAction::Send {
                            peer: sibling.adjacent_peer,
                            message_type: MessageType::CascadeClose,
                            message: pad_wire_message(close_msg),
                        });
                    }
                }
            }
        }

        if let Some(route) = self.source_routes.get_mut(&handle) {
            if !already_active {
                actions.push(CascadeAction::RouteReady {
                    remote_peer: route.remote_peer.clone(),
                    local_route_ref: route.local_route_ref(),
                    hops: route.hops,
                });
            }
            for (pseq, ppayload, pmeta) in inherited_pending {
                let seq = if pseq == 0 {
                    let s = route.next_sequence;
                    route.next_sequence += 1;
                    s
                } else {
                    pseq
                };
                actions.push(Self::forward_action(route, seq, &ppayload, &pmeta)?);
            }
            for pkt in pending_back {
                if let Ok((seq, payload, mut meta)) = Self::open_packet(route, "back", &pkt) {
                    if route.seen_reverse.insert(seq) {
                        let route_ref = route.local_route_ref();
                        meta.insert("cascade".to_owned(), json!(true));
                        meta.insert("cascade_direction".to_owned(), json!("back"));
                        meta.insert("cascade_remote_peer".to_owned(), json!(route.remote_peer));
                        meta.insert("cascade_hops".to_owned(), json!(route.hops));
                        meta.insert("cascade_route_ref".to_owned(), json!(route_ref));
                        actions.push(CascadeAction::Deliver {
                            direction: "back".to_owned(),
                            remote_peer: route.remote_peer.clone(),
                            payload,
                            metadata: meta,
                            local_route_ref: route_ref,
                        });
                    }
                }
            }
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
            message: pad_wire_message(forwarded),
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
            if source.state != "active" {
                // UDP reordering guard: buffer until CASCADE_ACCEPT activates the route.
                if source.pending_back.len() < MAX_PENDING_BACK_PER_CELL {
                    source.pending_back.push(packet);
                }
                return Ok(Vec::new());
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
            .cloned()
            .ok_or_else(|| CascadeError::new("no_active_relay_cell"))?;
        let cell = self
            .relay_cells
            .get_mut(&in_handle)
            .ok_or_else(|| CascadeError::new("no_active_relay_cell"))?;
        if cell.state != "active" {
            // UDP reordering guard: `CASCADE_BACK` arrived before `CASCADE_ACCEPT`.
            let valid_pending_peer = (cell.state == "probing"
                && cell.probe_handles.get(peer).map(String::as_str) == Some(&handle))
                || (cell.state == "building"
                    && cell.next_peer == peer
                    && cell.outbound_handle == handle);
            if valid_pending_peer {
                if cell.pending_back.len() < MAX_PENDING_BACK_PER_CELL {
                    cell.pending_back.push(packet);
                }
                return Ok(Vec::new());
            }
            return Err(CascadeError::new("no_active_relay_cell"));
        }
        if cell.next_peer != peer {
            return Err(CascadeError::new("no_active_relay_cell"));
        }
        let mut forwarded = Self::base_message(&cell.inbound_handle, cell.expires_at);
        forwarded.insert("packet".to_owned(), packet);
        Ok(vec![CascadeAction::Send {
            peer: cell.previous_peer.clone(),
            message_type: MessageType::CascadeBack,
            message: pad_wire_message(forwarded),
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
                        message: pad_wire_message(forwarded),
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
            message: pad_wire_message(msg),
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

    /// Returns the first-hop relay (`X1`) for an active or building source route to `destination`.
    /// Initiator `A` NEVER knows `X2..Xm`.
    #[must_use]
    pub fn source_first_hop(&self, destination: &str) -> Option<String> {
        self.source_by_remote
            .get(destination)
            .and_then(|h| self.source_routes.get(h))
            .map(|r| r.adjacent_peer.clone())
    }

    /// Returns the last-hop relay (`Xm`) for an active endpoint route from `source`.
    /// Destination `B` NEVER knows `X1..X(m-1)`.
    #[must_use]
    pub fn endpoint_last_hop(&self, source: &str) -> Option<String> {
        self.endpoint_by_remote
            .get(source)
            .and_then(|h| self.endpoint_routes.get(h))
            .map(|r| r.adjacent_peer.clone())
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
        self.seen_exchanges.retain(|_, (_, exp)| *exp > now_secs);
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

    /// Full diagnostic dump of everything stored in this node's relay memory cells
    /// (used exclusively by negative knowledge-leakage audit tests).
    #[must_use]
    pub fn inspect_relay_memory_debug(&self) -> Value {
        let cells: Vec<Value> = self
            .relay_cells
            .values()
            .map(|c| {
                json!({
                    "inbound_handle": c.inbound_handle,
                    "previous_peer": c.previous_peer,
                    "outbound_handle": c.outbound_handle,
                    "next_peer": c.next_peer,
                    "state": c.state,
                    "has_build_ctx": c.build_ctx.is_some(),
                    "probe_handles_count": c.probe_handles.len(),
                })
            })
            .collect();
        json!({
            "node": self.identity.name(),
            "relay_cells": cells,
            "source_routes_count": self.source_routes.len(),
            "endpoint_routes_count": self.endpoint_routes.len(),
        })
    }

    /// Returns current state counts for diagnostics and tests.
    pub fn local_counts(&mut self, now_secs: f64) -> CascadeCounts {
        self.cleanup(now_secs);
        CascadeCounts {
            relay_cells: self.relay_cells.len(),
            source_routes: self.source_routes.len(),
            endpoint_routes: self.endpoint_routes.len(),
            dedup_entries: self.seen_deliveries.len() + self.seen_exchanges.len(),
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
            if let Some(ref gid) = route.chain_group_id {
                if let Some(hs) = self.pending_groups.get_mut(gid) {
                    hs.retain(|h| h != handle);
                    if hs.is_empty() {
                        self.pending_groups.remove(gid);
                    }
                }
            }
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
