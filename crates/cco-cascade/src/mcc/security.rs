#![forbid(unsafe_code)]
//! Endpoint-authenticated MCC records, X25519 recipient capsules, and durable SQLite
//! at-most-once anti-replay ledger (1-to-1 with `mcc_e2e.py`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cco_crypto::{
    Ed25519SecretKey, Ed25519Signature, MCC_ENDPOINT_MESSAGE_DOMAIN, MccCapsulePurpose,
    X25519PublicKey, X25519SecretKey, aes256_gcm_decrypt, aes256_gcm_encrypt, decode_canonical_hex,
    decode_canonical_hex_vec, derive_mcc_capsule_key, mcc_capsule_aad, random_bytes, sha256,
    sha256_hex, validate_context_token,
};
use cco_proto::{
    CanonicalValue, canonical_bytes_from_value, canonical_object_bytes, parse_strict_json_object,
};
use cco_trust::VerifiedRegistry;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::error::CascadeError;

/// MCC record protocol version (`mcc_e2e.py::VERSION`).
pub const MCC_VERSION: i64 = 1;

/// Maximum signed record lifetime in seconds (`mcc_e2e.py::MAX_LIFETIME`).
pub const MAX_LIFETIME: i64 = 120;

/// Allowed clock skew in seconds (`mcc_e2e.py::CLOCK_SKEW`).
pub const CLOCK_SKEW: i64 = 5;

/// Maximum active exchanges tracked in signer cache and SQLite ledger (`mcc_e2e.py::MAX_EXCHANGES`).
pub const MAX_EXCHANGES: usize = 1024;

/// Maximum copies per exchange (`mcc_e2e.py::MAX_COPIES`).
pub const MAX_COPIES: usize = 64;

/// Maximum local delivery attempts per message (`mcc_e2e.py::MAX_DELIVERY_ATTEMPTS`).
pub const MAX_DELIVERY_ATTEMPTS: i64 = 3;

/// Maximum canonical JSON bytes for signed body (`mcc_e2e.py::MAX_BODY_BYTES`).
pub const MAX_BODY_BYTES: usize = 65_536;

/// Maximum plaintext bytes for a recipient capsule (`mcc_e2e.py::MAX_SEAL_PLAINTEXT`).
pub const MAX_SEAL_PLAINTEXT: usize = 524_288;

/// Maximum ciphertext bytes on the wire in v2 base64 capsules (`mcc_auth.py::MAX_WIRE_CIPHERTEXT`).
pub const MAX_WIRE_CIPHERTEXT: usize = 65_507;

/// Hard upper bound on SQLite ledger file size (`mcc_e2e.py::MAX_LEDGER_BYTES`).
pub const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;

static NEXT_OWNER_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Hex-encoded X25519 recipient capsule (`mcc_e2e.py` v1 core format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleV1 {
    pub v: i64,
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

/// Base64-encoded X25519 recipient capsule (`mcc_auth.py` v2 compact wire format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleV2 {
    pub v: i64,
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

/// Outcome of admitting a verified message into the SQLite anti-replay ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitStatus {
    /// First time this `(message_key, copy_id)` was admitted.
    New,
    /// This `copy_id` was already admitted while the exchange is active.
    Duplicate,
    /// This exchange is already `in_flight` or `delivered`.
    Delivered,
}

/// Cryptographically verified MCC endpoint message bound to the verifying [`EndpointSecurity`].
///
/// Immutable after verification; `owner_token` prevents forging a `VerifiedMessage` or
/// passing one between different endpoint instances.
#[derive(Debug, Clone)]
pub struct VerifiedMessage {
    pub sender: String,
    pub receiver: String,
    pub key_id: String,
    pub context: String,
    pub direction: String,
    pub kind: String,
    pub message_id: String,
    pub nonce: String,
    pub issued: i64,
    pub expires: i64,
    pub expected_copies: usize,
    pub copy_id: usize,
    pub fingerprint: String,
    pub message_key: String,
    canonical: Vec<u8>,
    body_bytes: Vec<u8>,
    owner_token: u64,
}

impl VerifiedMessage {
    /// Returns an independent freshly parsed copy of the verified JSON body.
    pub fn body_map(&self) -> Result<BTreeMap<String, CanonicalValue>, CascadeError> {
        parse_strict_json_object(&self.body_bytes, MAX_BODY_BYTES)
            .map_err(|_| CascadeError::new("invalid_json"))
    }

    /// Returns canonical signed bytes verified under Ed25519.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

#[derive(Debug, Clone)]
struct SignCacheEntry {
    semantic_digest: [u8; 32],
    nonce_hex: String,
    issued: i64,
    expires: i64,
}

/// Node-local MCC cryptographic identity and durable SQLite anti-replay ledger.
pub struct EndpointSecurity {
    name: String,
    key_id: String,
    registry: VerifiedRegistry,
    signing: Ed25519SecretKey,
    encryption: X25519SecretKey,
    state_path: PathBuf,
    owner_token: u64,
    sign_cache: BTreeMap<String, SignCacheEntry>,
    claims: BTreeMap<(String, usize), i64>,
}

impl EndpointSecurity {
    /// Initializes endpoint security against an already verified Trust Registry v2 and durable SQLite file.
    ///
    /// Rejects in-memory or empty `state_path`, reused signing/encryption private keys,
    /// key mismatches against the verified registry, or revoked own key.
    pub fn new(
        name: impl Into<String>,
        registry: VerifiedRegistry,
        signing: Ed25519SecretKey,
        encryption: X25519SecretKey,
        state_path: impl Into<PathBuf>,
        now_secs: i64,
    ) -> Result<Self, CascadeError> {
        let name = name.into();
        validate_token(&name, 128)?;

        if signing.ct_eq_bytes(&encryption.to_bytes_zeroizing()) {
            return Err(CascadeError::new("private_key_reused"));
        }

        let own = registry
            .require_active_node(&name)
            .map_err(|e| CascadeError::new(e.code()))?;
        if own.verification != signing.public_key() || own.encryption != encryption.public_key() {
            return Err(CascadeError::new("private_key_mismatch"));
        }
        let key_id = own.key_id.clone();

        let state_path = state_path.into();
        let path_str = state_path.to_string_lossy();
        if path_str.is_empty() || path_str == ":memory:" {
            return Err(CascadeError::new("persistent_state_required"));
        }
        ensure_private_file(&state_path, true)?;

        let sec = Self {
            name,
            key_id,
            registry,
            signing,
            encryption,
            state_path,
            owner_token: NEXT_OWNER_TOKEN.fetch_add(1, Ordering::Relaxed),
            sign_cache: BTreeMap::new(),
            claims: BTreeMap::new(),
        };
        sec.initialize_ledger(now_secs)?;
        Ok(sec)
    }

    /// Returns this node's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns this node's Ed25519 `key_id`.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the verified trust registry pinned to this endpoint.
    #[must_use]
    pub fn registry(&self) -> &VerifiedRegistry {
        &self.registry
    }

    /// Returns the path of the durable SQLite replay ledger.
    #[must_use]
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// Builds a verified [`crate::universal::CascadeIdentity`] (both X25519 encryption and
    /// Ed25519 end-to-end signing keys) backed by this endpoint's pinned Trust Registry v2.
    pub fn build_cascade_identity(
        &self,
    ) -> Result<crate::universal::CascadeIdentity, CascadeError> {
        let enc_bytes = self.encryption.to_bytes_zeroizing();
        let sig_bytes = self.signing.to_bytes_zeroizing();
        crate::universal::CascadeIdentity::from_verified_registry_signed(
            self.name.clone(),
            X25519SecretKey::from_bytes(*enc_bytes),
            Ed25519SecretKey::from_bytes(*sig_bytes),
            &self.registry,
        )
    }

    /// Replaces the verified registry (e.g. after an atomic trust-store update).
    pub fn update_registry(&mut self, registry: VerifiedRegistry) -> Result<(), CascadeError> {
        let own = registry
            .require_active_node(&self.name)
            .map_err(|e| CascadeError::new(e.code()))?;
        if own.verification != self.signing.public_key()
            || own.encryption != self.encryption.public_key()
        {
            return Err(CascadeError::new("private_key_mismatch"));
        }
        self.key_id = own.key_id.clone();
        self.registry = registry;
        Ok(())
    }

    /// Seals a canonical JSON object into a v1 X25519/HKDF/AES-256-GCM capsule for `recipient`.
    pub fn seal_to(
        &self,
        recipient: &str,
        obj: &BTreeMap<String, CanonicalValue>,
        context: &str,
        purpose: MccCapsulePurpose,
    ) -> Result<CapsuleV1, CascadeError> {
        validate_token(recipient, 128)?;
        let target = self
            .registry
            .require_active_node(recipient)
            .map_err(|e| CascadeError::new(e.code()))?
            .encryption;
        let aad = mcc_capsule_aad(context, purpose)
            .map_err(|_| CascadeError::new("invalid_identifier"))?;
        let plaintext = canonical_object_bytes(obj, MAX_SEAL_PLAINTEXT)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;

        let ephemeral = X25519SecretKey::generate();
        let epk = ephemeral.public_key();
        let shared = ephemeral
            .diffie_hellman(&target)
            .map_err(|_| CascadeError::new("key_agreement_failed"))?;
        let key = derive_mcc_capsule_key(&shared, &epk, &target, &aad)
            .map_err(|_| CascadeError::new("key_agreement_failed"))?;
        let (nonce, ct) = aes256_gcm_encrypt(&key, &plaintext, &aad)
            .map_err(|_| CascadeError::new("key_agreement_failed"))?;

        Ok(CapsuleV1 {
            v: MCC_VERSION,
            epk: epk.to_hex(),
            nonce: hex::encode(nonce),
            ct: hex::encode(ct),
        })
    }

    /// Opens and authenticates a v1 recipient capsule addressed to this node.
    pub fn open_for_me(
        &self,
        seal: &CapsuleV1,
        context: &str,
        purpose: MccCapsulePurpose,
    ) -> Result<BTreeMap<String, CanonicalValue>, CascadeError> {
        self.registry
            .require_active_node(&self.name)
            .map_err(|e| CascadeError::new(e.code()))?;
        if seal.v != MCC_VERSION {
            return Err(CascadeError::new("invalid_capsule"));
        }
        let epk =
            X25519PublicKey::from_hex(&seal.epk).map_err(|_| CascadeError::new("invalid_hex"))?;
        let nonce = decode_canonical_hex::<12>(&seal.nonce)
            .map_err(|_| CascadeError::new("invalid_hex"))?;
        let ct = decode_canonical_hex_vec(&seal.ct, MAX_SEAL_PLAINTEXT + 16)
            .map_err(|_| CascadeError::new("invalid_hex"))?;
        if ct.len() < 16 {
            return Err(CascadeError::new("invalid_capsule"));
        }

        let aad = mcc_capsule_aad(context, purpose)
            .map_err(|_| CascadeError::new("invalid_identifier"))?;
        let own_pub = self.encryption.public_key();
        let shared = self
            .encryption
            .diffie_hellman(&epk)
            .map_err(|_| CascadeError::new("capsule_authentication_failed"))?;
        let key = derive_mcc_capsule_key(&shared, &epk, &own_pub, &aad)
            .map_err(|_| CascadeError::new("capsule_authentication_failed"))?;
        let plaintext = aes256_gcm_decrypt(&key, &nonce, &ct, &aad)
            .map_err(|_| CascadeError::new("capsule_authentication_failed"))?;

        parse_strict_json_object(&plaintext, MAX_SEAL_PLAINTEXT)
            .map_err(|_| CascadeError::new("invalid_json"))
    }

    /// Packs a v1 hex capsule into a compact v2 base64 wire capsule (`mcc_auth.py::_auth_pack_seal`).
    pub fn pack_seal_v2(seal: &CapsuleV1) -> Result<CapsuleV2, CascadeError> {
        if seal.v != 1 {
            return Err(CascadeError::new("invalid_core_seal"));
        }
        decode_canonical_hex::<32>(&seal.epk)
            .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
        decode_canonical_hex::<12>(&seal.nonce)
            .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
        let raw_ct = decode_canonical_hex_vec(&seal.ct, MAX_WIRE_CIPHERTEXT)
            .map_err(|_| CascadeError::new("wire_ciphertext_size"))?;
        if raw_ct.len() < 16 {
            return Err(CascadeError::new("wire_ciphertext_size"));
        }
        Ok(CapsuleV2 {
            v: 2,
            epk: seal.epk.clone(),
            nonce: seal.nonce.clone(),
            ct: STANDARD.encode(&raw_ct),
        })
    }

    /// Expands a compact v2 base64 wire capsule back into a v1 capsule (`mcc_auth.py::_auth_expand_seal`).
    pub fn expand_seal_v2(seal: &CapsuleV2) -> Result<CapsuleV1, CascadeError> {
        if seal.v != 2 {
            return Err(CascadeError::new("invalid_wire_seal"));
        }
        decode_canonical_hex::<32>(&seal.epk)
            .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
        decode_canonical_hex::<12>(&seal.nonce)
            .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
        let raw_ct = decode_canonical_base64_ct(&seal.ct)?;
        Ok(CapsuleV1 {
            v: 1,
            epk: seal.epk.clone(),
            nonce: seal.nonce.clone(),
            ct: hex::encode(raw_ct),
        })
    }

    /// Produces an Ed25519-signed MCC endpoint record (`mcc_e2e.py::signed_message`).
    ///
    /// Copies belonging to the same logical message share `(nonce, issued, expires)` via
    /// the bounded signing cache; attempting to sign a conflicting body under the same
    /// message identity fails closed with `conflicting_message`.
    #[allow(clippy::too_many_arguments)]
    pub fn signed_message(
        &mut self,
        recipient: &str,
        context: &str,
        body: BTreeMap<String, CanonicalValue>,
        copy_id: usize,
        expected_copies: usize,
        direction: &str,
        kind: &str,
        message_id: &str,
        now_secs: i64,
    ) -> Result<BTreeMap<String, CanonicalValue>, CascadeError> {
        validate_token(recipient, 128)?;
        self.registry
            .require_active_node(recipient)
            .map_err(|e| CascadeError::new(e.code()))?;
        self.registry
            .require_active_node(&self.name)
            .map_err(|e| CascadeError::new(e.code()))?;
        validate_token(context, 256)?;
        validate_labels(direction, kind, message_id)?;
        if !(1..=MAX_COPIES).contains(&expected_copies) || copy_id >= expected_copies {
            return Err(CascadeError::new("invalid_integer"));
        }
        validate_clock(now_secs)?;

        // Validate body size bounds.
        let _ = canonical_object_bytes(&body, MAX_BODY_BYTES)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;

        let mut base = BTreeMap::new();
        base.insert(
            "domain".to_owned(),
            CanonicalValue::String(MCC_ENDPOINT_MESSAGE_DOMAIN.to_owned()),
        );
        base.insert("version".to_owned(), CanonicalValue::Int(MCC_VERSION));
        base.insert(
            "sender".to_owned(),
            CanonicalValue::String(self.name.clone()),
        );
        base.insert(
            "receiver".to_owned(),
            CanonicalValue::String(recipient.to_owned()),
        );
        base.insert(
            "key_id".to_owned(),
            CanonicalValue::String(self.key_id.clone()),
        );
        base.insert(
            "context".to_owned(),
            CanonicalValue::String(context.to_owned()),
        );
        base.insert(
            "direction".to_owned(),
            CanonicalValue::String(direction.to_owned()),
        );
        base.insert("kind".to_owned(), CanonicalValue::String(kind.to_owned()));
        base.insert(
            "message_id".to_owned(),
            CanonicalValue::String(message_id.to_owned()),
        );
        base.insert(
            "expected_copies".to_owned(),
            CanonicalValue::Int(expected_copies as i64),
        );
        base.insert("copy_id".to_owned(), CanonicalValue::Int(copy_id as i64));
        base.insert("body".to_owned(), CanonicalValue::Object(body.clone()));

        let _ = canonical_object_bytes(&base, MAX_BODY_BYTES + 4096)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;

        let msg_key = compute_message_key(&base)?;
        let semantic_digest = compute_semantic_digest(&base)?;

        self.sign_cache
            .retain(|_, entry| entry.expires + CLOCK_SKEW >= now_secs);

        let cached = if let Some(existing) = self.sign_cache.get(&msg_key) {
            if existing.semantic_digest != semantic_digest {
                return Err(CascadeError::new("conflicting_message"));
            }
            if existing.issued > now_secs + CLOCK_SKEW {
                return Err(CascadeError::new("clock_rollback"));
            }
            existing.clone()
        } else {
            if self.sign_cache.len() >= MAX_EXCHANGES {
                return Err(CascadeError::new("signer_capacity"));
            }
            let entry = SignCacheEntry {
                semantic_digest,
                nonce_hex: hex::encode(random_bytes::<16>()),
                issued: now_secs,
                expires: now_secs + MAX_LIFETIME,
            };
            self.sign_cache.insert(msg_key, entry.clone());
            entry
        };

        base.insert("nonce".to_owned(), CanonicalValue::String(cached.nonce_hex));
        base.insert("issued".to_owned(), CanonicalValue::Int(cached.issued));
        base.insert("expires".to_owned(), CanonicalValue::Int(cached.expires));

        let canonical = canonical_object_bytes(&base, MAX_BODY_BYTES + 4096)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;
        let signature = self.signing.sign(&canonical).to_hex();

        let mut record = BTreeMap::new();
        record.insert("signed".to_owned(), CanonicalValue::Object(base));
        record.insert("signature".to_owned(), CanonicalValue::String(signature));
        Ok(record)
    }

    /// Verifies an Ed25519-signed MCC endpoint record (`mcc_e2e.py::verify_signed`).
    pub fn verify_signed(
        &self,
        record: &BTreeMap<String, CanonicalValue>,
        context: &str,
        expected_sender: Option<&str>,
        direction: &str,
        kind: &str,
        now_secs: i64,
    ) -> Result<VerifiedMessage, CascadeError> {
        if record.len() != 2 || !record.contains_key("signed") || !record.contains_key("signature")
        {
            return Err(CascadeError::new("invalid_signed_record"));
        }
        let signed = record
            .get("signed")
            .and_then(CanonicalValue::as_object)
            .ok_or_else(|| CascadeError::new("invalid_signed_record"))?;

        const REQUIRED_FIELDS: [&str; 15] = [
            "domain",
            "version",
            "sender",
            "receiver",
            "key_id",
            "context",
            "direction",
            "kind",
            "message_id",
            "nonce",
            "issued",
            "expires",
            "expected_copies",
            "copy_id",
            "body",
        ];
        if signed.len() != REQUIRED_FIELDS.len()
            || !REQUIRED_FIELDS.iter().all(|f| signed.contains_key(*f))
        {
            return Err(CascadeError::new("invalid_signed_record"));
        }

        if signed.get("domain").and_then(CanonicalValue::as_str)
            != Some(MCC_ENDPOINT_MESSAGE_DOMAIN)
            || signed.get("version").and_then(CanonicalValue::as_i64) != Some(MCC_VERSION)
        {
            return Err(CascadeError::new("invalid_signed_record"));
        }

        validate_token(context, 256)?;
        let sender = signed
            .get("sender")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_identifier"))?;
        let receiver = signed
            .get("receiver")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_identifier"))?;
        validate_token(sender, 128)?;
        validate_token(receiver, 128)?;

        let rec_dir = signed
            .get("direction")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_direction"))?;
        let rec_kind = signed
            .get("kind")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_identifier"))?;
        let rec_msg_id = signed
            .get("message_id")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_identifier"))?;
        let rec_ctx = signed
            .get("context")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_identifier"))?;
        validate_labels(rec_dir, rec_kind, rec_msg_id)?;

        if receiver != self.name || rec_ctx != context || rec_dir != direction || rec_kind != kind {
            return Err(CascadeError::new("wrong_message_scope"));
        }
        if let Some(exp) = expected_sender {
            if sender != exp {
                return Err(CascadeError::new("unexpected_sender"));
            }
        }

        self.registry
            .require_active_node(&self.name)
            .map_err(|e| CascadeError::new(e.code()))?;
        let sender_rec = self
            .registry
            .require_active_node(sender)
            .map_err(|e| CascadeError::new(e.code()))?;

        let key_id = signed
            .get("key_id")
            .and_then(CanonicalValue::as_str)
            .unwrap_or("");
        if key_id != sender_rec.key_id {
            return Err(CascadeError::new("unknown_key"));
        }

        let nonce = signed
            .get("nonce")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_hex"))?;
        decode_canonical_hex::<16>(nonce).map_err(|_| CascadeError::new("invalid_hex"))?;

        let issued = signed
            .get("issued")
            .and_then(CanonicalValue::as_i64)
            .ok_or_else(|| CascadeError::new("invalid_integer"))?;
        let expires = signed
            .get("expires")
            .and_then(CanonicalValue::as_i64)
            .ok_or_else(|| CascadeError::new("invalid_integer"))?;
        check_freshness(issued, expires, now_secs)?;

        let expected_copies = signed
            .get("expected_copies")
            .and_then(CanonicalValue::as_i64)
            .filter(|&v| (1..=MAX_COPIES as i64).contains(&v))
            .ok_or_else(|| CascadeError::new("invalid_integer"))?
            as usize;
        let copy_id = signed
            .get("copy_id")
            .and_then(CanonicalValue::as_i64)
            .filter(|&v| v >= 0 && (v as usize) < expected_copies)
            .ok_or_else(|| CascadeError::new("invalid_integer"))? as usize;

        let body_obj = signed
            .get("body")
            .and_then(CanonicalValue::as_object)
            .ok_or_else(|| CascadeError::new("invalid_json_object"))?;
        let body_bytes = canonical_object_bytes(body_obj, MAX_BODY_BYTES)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;
        let canonical = canonical_object_bytes(signed, MAX_BODY_BYTES + 4096)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;

        let sig_hex = record
            .get("signature")
            .and_then(CanonicalValue::as_str)
            .ok_or_else(|| CascadeError::new("invalid_hex"))?;
        let signature =
            Ed25519Signature::from_hex(sig_hex).map_err(|_| CascadeError::new("invalid_hex"))?;
        sender_rec
            .verification
            .verify_strict(&canonical, &signature)
            .map_err(|_| CascadeError::new("bad_signature"))?;

        let fingerprint = compute_fingerprint(signed)?;
        let message_key = compute_message_key(signed)?;

        Ok(VerifiedMessage {
            sender: sender.to_owned(),
            receiver: receiver.to_owned(),
            key_id: key_id.to_owned(),
            context: rec_ctx.to_owned(),
            direction: rec_dir.to_owned(),
            kind: rec_kind.to_owned(),
            message_id: rec_msg_id.to_owned(),
            nonce: nonce.to_owned(),
            issued,
            expires,
            expected_copies,
            copy_id,
            fingerprint,
            message_key,
            canonical,
            body_bytes,
            owner_token: self.owner_token,
        })
    }

    /// Admits a verified message into the durable SQLite replay ledger.
    pub fn admit(
        &mut self,
        verified: &VerifiedMessage,
        now_secs: i64,
    ) -> Result<AdmitStatus, CascadeError> {
        self.check_verified_ownership(verified, now_secs)?;
        self.with_tx(now_secs, |conn| {
            let row = fetch_message_row(conn, verified, false)?;
            if let Some(existing) = row {
                if existing.status != "active" {
                    return Ok(AdmitStatus::Delivered);
                }
            } else {
                let total: i64 = conn
                    .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                    .map_err(|_| CascadeError::new("state_unavailable"))?;
                if total as usize >= MAX_EXCHANGES {
                    return Err(CascadeError::new("receiver_capacity"));
                }
                conn.execute(
                    "INSERT INTO messages(message_key,fingerprint,expires,expected,status) VALUES (?1,?2,?3,?4,'active')",
                    params![
                        verified.message_key,
                        verified.fingerprint,
                        verified.expires,
                        verified.expected_copies as i64,
                    ],
                )
                .map_err(|_| CascadeError::new("state_unavailable"))?;
            }

            let seen: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM copies WHERE message_key=?1 AND copy_id=?2",
                    params![verified.message_key, verified.copy_id as i64],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| CascadeError::new("state_unavailable"))?;
            if seen.is_some() {
                return Ok(AdmitStatus::Duplicate);
            }

            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM copies WHERE message_key=?1",
                    params![verified.message_key],
                    |r| r.get(0),
                )
                .map_err(|_| CascadeError::new("state_unavailable"))?;
            if count as usize >= verified.expected_copies || count as usize >= MAX_COPIES {
                return Err(CascadeError::new("copy_capacity"));
            }
            conn.execute(
                "INSERT INTO copies(message_key, copy_id) VALUES (?1,?2)",
                params![verified.message_key, verified.copy_id as i64],
            )
            .map_err(|_| CascadeError::new("state_unavailable"))?;
            Ok(AdmitStatus::New)
        })
    }

    /// Durably reserves delivery (`active -> in_flight`) BEFORE local IKE injection.
    ///
    /// Returning `Ok(false)` forbids injection (already reserved/delivered or attempt limit hit).
    pub fn claim_delivery(
        &mut self,
        verified: &VerifiedMessage,
        now_secs: i64,
    ) -> Result<bool, CascadeError> {
        self.check_verified_ownership(verified, now_secs)?;
        let claimed = self.with_tx(now_secs, |conn| {
            let row = fetch_message_row(conn, verified, true)?
                .ok_or_else(|| CascadeError::new("unadmitted_message"))?;
            let copy_exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM copies WHERE message_key=?1 AND copy_id=?2",
                    params![verified.message_key, verified.copy_id as i64],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| CascadeError::new("state_unavailable"))?;
            if copy_exists.is_none() {
                return Err(CascadeError::new("unadmitted_copy"));
            }
            if row.status != "active" || row.attempts >= MAX_DELIVERY_ATTEMPTS {
                return Ok(false);
            }
            conn.execute(
                "UPDATE messages SET status='in_flight', reserved_copy=?1, attempts=attempts+1 WHERE message_key=?2",
                params![verified.copy_id as i64, verified.message_key],
            )
            .map_err(|_| CascadeError::new("state_unavailable"))?;
            Ok(true)
        })?;
        if claimed {
            self.prune_claims(now_secs);
            self.claims.insert(
                (verified.message_key.clone(), verified.copy_id),
                verified.expires,
            );
        }
        Ok(claimed)
    }

    /// Marks an `in_flight` delivery as permanently `delivered`.
    pub fn delivered(
        &mut self,
        verified: &VerifiedMessage,
        now_secs: i64,
    ) -> Result<(), CascadeError> {
        self.check_verified_ownership(verified, now_secs)?;
        self.with_tx(now_secs, |conn| {
            let row = fetch_message_row(conn, verified, true)?
                .ok_or_else(|| CascadeError::new("unadmitted_message"))?;
            if row.status == "delivered" {
                return Ok(());
            }
            if row.status != "in_flight" || row.reserved_copy != Some(verified.copy_id as i64) {
                return Err(CascadeError::new("delivery_not_reserved"));
            }
            conn.execute(
                "UPDATE messages SET status='delivered' WHERE message_key=?1",
                params![verified.message_key],
            )
            .map_err(|_| CascadeError::new("state_unavailable"))?;
            Ok(())
        })?;
        self.claims
            .remove(&(verified.message_key.clone(), verified.copy_id));
        Ok(())
    }

    /// Releases a reservation ONLY when local injection failed BEFORE any packet left the host.
    ///
    /// Fails closed with `delivery_not_reserved_here` if this process instance did not create
    /// the reservation (e.g., after restart).
    pub fn failed_delivery(
        &mut self,
        verified: &VerifiedMessage,
        now_secs: i64,
    ) -> Result<(), CascadeError> {
        self.check_verified_ownership(verified, now_secs)?;
        self.prune_claims(now_secs);
        let key = (verified.message_key.clone(), verified.copy_id);
        if !self.claims.contains_key(&key) {
            return Err(CascadeError::new("delivery_not_reserved_here"));
        }
        self.with_tx(now_secs, |conn| {
            let row = fetch_message_row(conn, verified, true)?
                .ok_or_else(|| CascadeError::new("unadmitted_message"))?;
            if row.status != "in_flight" || row.reserved_copy != Some(verified.copy_id as i64) {
                return Err(CascadeError::new("delivery_not_reserved"));
            }
            conn.execute(
                "UPDATE messages SET status='active', reserved_copy=NULL WHERE message_key=?1",
                params![verified.message_key],
            )
            .map_err(|_| CascadeError::new("state_unavailable"))?;
            Ok(())
        })?;
        self.claims.remove(&key);
        Ok(())
    }

    /// Returns `(messages_count, copies_count)` stored in the durable SQLite ledger.
    pub fn ledger_counts(&self) -> Result<(usize, usize), CascadeError> {
        let conn = self.connect()?;
        let msgs: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        let copies: i64 = conn
            .query_row("SELECT COUNT(*) FROM copies", [], |r| r.get(0))
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        Ok((msgs as usize, copies as usize))
    }

    fn prune_claims(&mut self, now_secs: i64) {
        self.claims
            .retain(|_, expires| *expires + CLOCK_SKEW >= now_secs);
    }

    fn check_verified_ownership(
        &self,
        verified: &VerifiedMessage,
        now_secs: i64,
    ) -> Result<(), CascadeError> {
        if verified.owner_token != self.owner_token || verified.receiver != self.name {
            return Err(CascadeError::new("unverified_message"));
        }
        let sender = self
            .registry
            .require_active_node(&verified.sender)
            .map_err(|e| CascadeError::new(e.code()))?;
        self.registry
            .require_active_node(&self.name)
            .map_err(|e| CascadeError::new(e.code()))?;
        if verified.key_id != sender.key_id {
            return Err(CascadeError::new("unknown_key"));
        }
        check_freshness(verified.issued, verified.expires, now_secs)
    }

    fn connect(&self) -> Result<Connection, CascadeError> {
        ensure_private_file(&self.state_path, false)?;
        let size = fs::metadata(&self.state_path)
            .map_err(|_| CascadeError::new("state_unavailable"))?
            .len();
        if size > MAX_LEDGER_BYTES {
            return Err(CascadeError::new("state_resource_limit"));
        }
        let conn = Connection::open(&self.state_path)
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        conn.busy_timeout(std::time::Duration::from_secs(1))
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        conn.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| CascadeError::new("state_unavailable"))?;
        let page_size_raw: i64 = conn
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        let page_size =
            u64::try_from(page_size_raw).map_err(|_| CascadeError::new("state_unavailable"))?;
        let max_pages = (MAX_LEDGER_BYTES / page_size.max(512)).max(1);
        conn.execute_batch(&format!("PRAGMA max_page_count={max_pages};"))
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        Ok(conn)
    }

    fn initialize_ledger(&self, now_secs: i64) -> Result<(), CascadeError> {
        validate_clock(now_secs)?;
        let conn = self.connect()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        let result = (|| {
            let user_ver: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .map_err(|_| CascadeError::new("state_unavailable"))?;
            let table_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| CascadeError::new("state_unavailable"))?;
            if user_ver == 0 && table_count == 0 {
                conn.execute_batch(
                    "CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, owner TEXT NOT NULL, key_id TEXT NOT NULL, last_seen INTEGER NOT NULL);
                     CREATE TABLE messages (message_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, expires INTEGER NOT NULL, expected INTEGER NOT NULL CHECK(expected BETWEEN 1 AND 64), status TEXT NOT NULL CHECK(status IN ('active','in_flight','delivered')), reserved_copy INTEGER, attempts INTEGER NOT NULL DEFAULT 0);
                     CREATE TABLE copies (message_key TEXT NOT NULL REFERENCES messages(message_key) ON DELETE CASCADE, copy_id INTEGER NOT NULL CHECK(copy_id BETWEEN 0 AND 63), PRIMARY KEY(message_key, copy_id));",
                )
                .map_err(|_| CascadeError::new("state_unavailable"))?;
                conn.execute(
                    "INSERT INTO meta VALUES (1, 'mcc-replay/v1', ?1, ?2, ?3)",
                    params![self.name, self.key_id, now_secs],
                )
                .map_err(|_| CascadeError::new("state_unavailable"))?;
                conn.execute_batch("PRAGMA user_version=1;")
                    .map_err(|_| CascadeError::new("state_unavailable"))?;
            } else if user_ver != 1 {
                return Err(CascadeError::new("invalid_state_schema"));
            }
            self.check_meta(&conn, now_secs, false)?;
            Ok(())
        })();
        match result {
            Ok(()) => conn
                .execute_batch("COMMIT;")
                .map_err(|_| CascadeError::new("state_unavailable")),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        }
    }

    fn check_meta(
        &self,
        conn: &Connection,
        now_secs: i64,
        update: bool,
    ) -> Result<(), CascadeError> {
        validate_clock(now_secs)?;
        let row: Option<(String, String, String, i64)> = conn
            .query_row(
                "SELECT schema, owner, key_id, last_seen FROM meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        let Some((schema, owner, kid, last_seen)) = row else {
            return Err(CascadeError::new("state_identity_mismatch"));
        };
        if schema != "mcc-replay/v1" || owner != self.name || kid != self.key_id {
            return Err(CascadeError::new("state_identity_mismatch"));
        }
        if now_secs + CLOCK_SKEW < last_seen {
            return Err(CascadeError::new("clock_rollback"));
        }
        if update {
            let next_seen = now_secs.max(last_seen);
            conn.execute(
                "UPDATE meta SET last_seen=?1 WHERE id=1",
                params![next_seen],
            )
            .map_err(|_| CascadeError::new("state_unavailable"))?;
            conn.execute(
                "DELETE FROM messages WHERE expires < ?1",
                params![now_secs - CLOCK_SKEW],
            )
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        }
        Ok(())
    }

    fn with_tx<T, F>(&self, now_secs: i64, f: F) -> Result<T, CascadeError>
    where
        F: FnOnce(&Connection) -> Result<T, CascadeError>,
    {
        let conn = self.connect()?;
        conn.execute_batch("BEGIN IMMEDIATE;")
            .map_err(|_| CascadeError::new("state_unavailable"))?;
        let res = (|| {
            self.check_meta(&conn, now_secs, true)?;
            f(&conn)
        })();
        match res {
            Ok(val) => {
                conn.execute_batch("COMMIT;")
                    .map_err(|_| CascadeError::new("state_unavailable"))?;
                Ok(val)
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                Err(e)
            }
        }
    }
}

struct MessageRow {
    status: String,
    reserved_copy: Option<i64>,
    attempts: i64,
}

fn fetch_message_row(
    conn: &Connection,
    verified: &VerifiedMessage,
    required: bool,
) -> Result<Option<MessageRow>, CascadeError> {
    let row: Option<(String, i64, i64, String, Option<i64>, i64)> = conn
        .query_row(
            "SELECT fingerprint, expires, expected, status, reserved_copy, attempts FROM messages WHERE message_key=?1",
            params![verified.message_key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()
        .map_err(|_| CascadeError::new("state_unavailable"))?;
    let Some((fp, exp, expected, status, reserved_copy, attempts)) = row else {
        return if required {
            Err(CascadeError::new("unadmitted_message"))
        } else {
            Ok(None)
        };
    };
    if fp != verified.fingerprint
        || exp != verified.expires
        || expected != verified.expected_copies as i64
    {
        return Err(CascadeError::new("conflicting_message"));
    }
    Ok(Some(MessageRow {
        status,
        reserved_copy,
        attempts,
    }))
}

fn compute_message_key(signed: &BTreeMap<String, CanonicalValue>) -> Result<String, CascadeError> {
    let mut identity = BTreeMap::new();
    for key in [
        "sender",
        "receiver",
        "key_id",
        "context",
        "direction",
        "kind",
        "message_id",
    ] {
        let val = signed
            .get(key)
            .ok_or_else(|| CascadeError::new("invalid_signed_record"))?;
        identity.insert(key.to_owned(), val.clone());
    }
    let bytes = canonical_object_bytes(&identity, MAX_BODY_BYTES)
        .map_err(|_| CascadeError::new("json_resource_limit"))?;
    Ok(sha256_hex(&bytes))
}

fn without_transport_conn(
    body: &BTreeMap<String, CanonicalValue>,
) -> BTreeMap<String, CanonicalValue> {
    let mut stripped = body.clone();
    stripped.remove("transport_conn");
    stripped
}

fn compute_fingerprint(signed: &BTreeMap<String, CanonicalValue>) -> Result<String, CascadeError> {
    let mut protected = BTreeMap::new();
    for (k, v) in signed {
        if k == "copy_id" {
            continue;
        }
        if k == "body" {
            let body = v
                .as_object()
                .ok_or_else(|| CascadeError::new("invalid_json_object"))?;
            protected.insert(
                k.clone(),
                CanonicalValue::Object(without_transport_conn(body)),
            );
        } else {
            protected.insert(k.clone(), v.clone());
        }
    }
    let bytes =
        canonical_bytes_from_value(&CanonicalValue::Object(protected), MAX_BODY_BYTES + 4096)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;
    Ok(sha256_hex(&bytes))
}

fn compute_semantic_digest(
    base: &BTreeMap<String, CanonicalValue>,
) -> Result<[u8; 32], CascadeError> {
    let mut semantic = BTreeMap::new();
    for (k, v) in base {
        if k == "copy_id" {
            continue;
        }
        if k == "body" {
            let body = v
                .as_object()
                .ok_or_else(|| CascadeError::new("invalid_json_object"))?;
            semantic.insert(
                k.clone(),
                CanonicalValue::Object(without_transport_conn(body)),
            );
        } else {
            semantic.insert(k.clone(), v.clone());
        }
    }
    let bytes =
        canonical_bytes_from_value(&CanonicalValue::Object(semantic), MAX_BODY_BYTES + 4096)
            .map_err(|_| CascadeError::new("json_resource_limit"))?;
    Ok(sha256(&bytes))
}

pub(crate) fn validate_token(value: &str, maximum: usize) -> Result<(), CascadeError> {
    if value.len() > maximum || validate_context_token(value).is_err() {
        return Err(CascadeError::new("invalid_identifier"));
    }
    Ok(())
}

fn validate_labels(direction: &str, kind: &str, message_id: &str) -> Result<(), CascadeError> {
    if direction != "forward" && direction != "reverse" {
        return Err(CascadeError::new("invalid_direction"));
    }
    validate_token(kind, 32)?;
    validate_token(message_id, 128)?;
    Ok(())
}

fn validate_clock(now_secs: i64) -> Result<(), CascadeError> {
    if !(0..(1i64 << 53)).contains(&now_secs) {
        return Err(CascadeError::new("invalid_clock"));
    }
    Ok(())
}

fn check_freshness(issued: i64, expires: i64, now_secs: i64) -> Result<(), CascadeError> {
    validate_clock(now_secs)?;
    if !(0..(1i64 << 53)).contains(&issued) || !(0..(1i64 << 53)).contains(&expires) {
        return Err(CascadeError::new("expired_or_future_message"));
    }
    let lifetime = expires.saturating_sub(issued);
    if !(1..=MAX_LIFETIME).contains(&lifetime)
        || issued > now_secs + CLOCK_SKEW
        || expires < now_secs - CLOCK_SKEW
    {
        return Err(CascadeError::new("expired_or_future_message"));
    }
    Ok(())
}

/// Decodes and validates a canonical standard base64 ciphertext string (`mcc_auth.py::_auth_decode_ct`).
pub fn decode_canonical_base64_ct(value: &str) -> Result<Vec<u8>, CascadeError> {
    let max_b64 = 4 * MAX_WIRE_CIPHERTEXT.div_ceil(3);
    if value.len() < 24 || value.len() > max_b64 || value.len() % 4 != 0 {
        return Err(CascadeError::new("invalid_wire_encoding"));
    }
    let raw = STANDARD
        .decode(value.as_bytes())
        .map_err(|_| CascadeError::new("invalid_wire_encoding"))?;
    if raw.len() < 16 || raw.len() > MAX_WIRE_CIPHERTEXT || STANDARD.encode(&raw) != value {
        return Err(CascadeError::new("invalid_wire_encoding"));
    }
    Ok(raw)
}

/// Encodes ciphertext bytes into canonical standard base64 (`mcc_auth.py::_auth_encode_ct`).
pub fn encode_canonical_base64_ct(raw: &[u8]) -> Result<String, CascadeError> {
    if raw.len() < 16 || raw.len() > MAX_WIRE_CIPHERTEXT {
        return Err(CascadeError::new("wire_ciphertext_size"));
    }
    Ok(STANDARD.encode(raw))
}

fn ensure_private_file(path: &Path, create: bool) -> Result<(), CascadeError> {
    if create {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .map_err(|_| CascadeError::new("private_file_unavailable"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(CascadeError::new("private_file_unavailable")),
        }
    }
    let meta =
        fs::symlink_metadata(path).map_err(|_| CascadeError::new("private_file_unavailable"))?;
    if !meta.file_type().is_file() {
        return Err(CascadeError::new("private_file_type"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if (meta.permissions().mode() & 0o777) != 0o600 {
            return Err(CascadeError::new("private_file_permissions"));
        }
    }
    let _ = BTreeSet::<u8>::new();
    Ok(())
}
