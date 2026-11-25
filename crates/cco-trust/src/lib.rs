#![forbid(unsafe_code)]
//! Authenticated, rollback-resistant Trust Registry v2 (`ipsec-ike-cascade-trust-registry/v2`).
//!
//! Security properties:
//! - Separate per-node `X25519` encryption key and `Ed25519` verification key.
//! - `key_id == sha256(verification_key)` verified strictly.
//! - No shared keys between nodes, no `encryption == verification`, and no root signer
//!   reused as a node signing key.
//! - Canonical JSON (sorted keys, compact, duplicate JSON keys forbidden at every level).
//! - Pinned out-of-band Ed25519 trust root with strict signature verification.
//! - Monotonic version counter, SHA-256 same-version replacement rejection, atomic
//!   `fsync + rename` commit ordering, and automatic `last-valid` recovery.
//! - Fail-closed environment loader that rejects unsigned public-key variables.

pub mod admin;
pub mod error;
pub mod json;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cco_crypto::{
    Ed25519PublicKey, Ed25519Signature, X25519PublicKey, decode_canonical_hex, sha256_hex,
};
use serde::Serialize;
use tempfile::NamedTempFile;

pub use admin::{
    KeygenSummary, NodePublicEntry, NodePublicEntryKeys, SignRegistrySummary,
    build_trust_root_bytes, generate_node_identity, read_ed25519_key_file, read_x25519_key_file,
    sign_registry_files, sign_registry_v2,
};
pub use error::TrustRegistryError;
pub use json::{
    StrictJson, b64url_decode_canonical, b64url_encode, canonical_json_bytes,
    canonical_object_bytes, parse_strict_json_object,
};

use crate::json::expect_exact_fields;

/// Pinned trust-root document schema.
pub const ROOT_SCHEMA: &str = "ipsec-ike-cascade-trust-root/v1";

/// Signed Trust Registry v2 document schema.
pub const REGISTRY_SCHEMA: &str = "ipsec-ike-cascade-trust-registry/v2";

/// Accepted state file schema storing anti-rollback version and digest.
pub const STATE_SCHEMA: &str = "ipsec-ike-cascade-trust-state/v1";

/// Hard upper bound on a registry JSON document in bytes.
pub const MAX_REGISTRY_BYTES: usize = 262_144;

/// Hard upper bound on the number of nodes in a single registry.
pub const MAX_NODES: usize = 256;

/// Validated per-node public key record inside a [`VerifiedRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeKeyRecord {
    /// Node's X25519 encryption public key.
    pub encryption: X25519PublicKey,
    /// Node's Ed25519 verification public key.
    pub verification: Ed25519PublicKey,
    /// Lowercase SHA-256 hex digest of `verification`.
    pub key_id: String,
    /// Explicit revocation flag.
    pub revoked: bool,
}

impl NodeKeyRecord {
    /// Lowercase hex representation of the X25519 encryption key.
    #[must_use]
    pub fn encryption_hex(&self) -> String {
        self.encryption.to_hex()
    }

    /// Lowercase hex representation of the Ed25519 verification key.
    #[must_use]
    pub fn verification_hex(&self) -> String {
        self.verification.to_hex()
    }
}

/// Public status summary of a verified registry (matches `VerifiedRegistry.status()`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryStatus {
    pub authenticated: bool,
    pub schema: String,
    pub version: u64,
    pub signer_key_id: String,
    pub nodes: Vec<String>,
    pub sha256: String,
    pub recovered: bool,
}

/// Immutable, cryptographically verified Trust Registry v2 snapshot.
///
/// Cannot be constructed outside [`cco_trust`](crate); downstream components can
/// require `&VerifiedRegistry` as a compile-time trust gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistry {
    version: u64,
    signer_key_id: String,
    nodes: BTreeMap<String, NodeKeyRecord>,
    sha256: String,
    recovered: bool,
}

impl VerifiedRegistry {
    /// Monotonic registry version (`>= 1`).
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Pinned root signer identifier that signed this registry.
    #[must_use]
    pub fn signer_key_id(&self) -> &str {
        &self.signer_key_id
    }

    /// Immutable map of all verified node key records.
    #[must_use]
    pub fn nodes(&self) -> &BTreeMap<String, NodeKeyRecord> {
        &self.nodes
    }

    /// SHA-256 hex digest of the raw verified registry bytes.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Whether this snapshot was recovered from `last-valid` after live verification failed.
    #[must_use]
    pub const fn recovered(&self) -> bool {
        self.recovered
    }

    /// Looks up a node key record by name.
    #[must_use]
    pub fn get_node(&self, name: &str) -> Option<&NodeKeyRecord> {
        self.nodes.get(name)
    }

    /// Returns a node key record if it exists and is not revoked.
    pub fn require_active_node(&self, name: &str) -> Result<&NodeKeyRecord, TrustRegistryError> {
        let node = self
            .nodes
            .get(name)
            .ok_or_else(|| TrustRegistryError::new("unknown_node", "node not in registry"))?;
        if node.revoked {
            return Err(TrustRegistryError::new(
                "revoked_key",
                "node key is revoked",
            ));
        }
        Ok(node)
    }

    /// Produces a structured status report.
    #[must_use]
    pub fn status(&self) -> RegistryStatus {
        RegistryStatus {
            authenticated: true,
            schema: REGISTRY_SCHEMA.to_owned(),
            version: self.version,
            signer_key_id: self.signer_key_id.clone(),
            nodes: self.nodes.keys().cloned().collect(),
            sha256: self.sha256.clone(),
            recovered: self.recovered,
        }
    }
}

/// Verification constraints for anti-rollback and exact-document pinning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyConstraints {
    /// Minimum acceptable registry version (default: `1`).
    pub minimum_version: u64,
    /// Exact required registry version (used when verifying against committed state).
    pub exact_version: Option<u64>,
    /// Exact required SHA-256 hex digest of raw bytes (rejects same-version replacement).
    pub exact_sha256: Option<String>,
}

impl Default for VerifyConstraints {
    fn default() -> Self {
        Self {
            minimum_version: 1,
            exact_version: None,
            exact_sha256: None,
        }
    }
}

/// Computes the canonical `key_id` (`sha256(raw_ed25519_pubkey)`) from canonical lowercase hex.
pub fn verification_key_id(verification_hex: &str) -> Result<String, TrustRegistryError> {
    let raw = parse_key_hex(verification_hex)?;
    Ok(sha256_hex(&raw))
}

/// Computes the SHA-256 hex digest of raw registry document bytes.
#[must_use]
pub fn registry_digest(raw: &[u8]) -> String {
    sha256_hex(raw)
}

/// Validates a node identifier (`[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}`).
pub fn validate_node_name(name: &str) -> Result<(), TrustRegistryError> {
    if name.is_empty() || name.len() > 128 {
        return Err(TrustRegistryError::new("invalid_node", "invalid node name"));
    }
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(TrustRegistryError::new("invalid_node", "invalid node name"));
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'-'))
    {
        return Err(TrustRegistryError::new("invalid_node", "invalid node name"));
    }
    Ok(())
}

fn parse_key_hex(value: &str) -> Result<[u8; 32], TrustRegistryError> {
    decode_canonical_hex::<32>(value).map_err(|_| {
        TrustRegistryError::new(
            "invalid_node_key",
            "expected canonical 32-byte lowercase hex",
        )
    })
}

fn read_bounded(path: &Path, label: &str) -> Result<Vec<u8>, TrustRegistryError> {
    let file = File::open(path)
        .map_err(|_| TrustRegistryError::new("missing_document", format!("cannot read {label}")))?;
    let mut buf = Vec::new();
    let limit = (MAX_REGISTRY_BYTES + 1) as u64;
    file.take(limit)
        .read_to_end(&mut buf)
        .map_err(|_| TrustRegistryError::new("missing_document", format!("cannot read {label}")))?;
    if buf.len() > MAX_REGISTRY_BYTES {
        return Err(TrustRegistryError::new(
            "registry_too_large",
            "registry document exceeds its size limit",
        ));
    }
    Ok(buf)
}

/// Loads and validates pinned Ed25519 root signers from a Trust Root v1 JSON file.
pub fn load_trust_root(
    path: &Path,
) -> Result<BTreeMap<String, Ed25519PublicKey>, TrustRegistryError> {
    let raw = read_bounded(path, "trust root")?;
    parse_trust_root_bytes(&raw)
}

/// Parses and validates pinned Ed25519 root signers from raw JSON bytes.
pub fn parse_trust_root_bytes(
    raw: &[u8],
) -> Result<BTreeMap<String, Ed25519PublicKey>, TrustRegistryError> {
    let root = parse_strict_json_object(raw, "trust root")?;
    expect_exact_fields(&root, &["schema", "signers"], "trust root")?;
    if root.get("schema").and_then(StrictJson::as_str) != Some(ROOT_SCHEMA) {
        return Err(TrustRegistryError::new(
            "invalid_schema",
            "unexpected trust-root schema",
        ));
    }
    let signers = root
        .get("signers")
        .and_then(StrictJson::as_object)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| {
            TrustRegistryError::new("invalid_trust_root", "trust root has no signers")
        })?;

    let mut parsed = BTreeMap::new();
    for (key_id, record) in signers {
        if key_id.is_empty() {
            return Err(TrustRegistryError::new(
                "invalid_signer",
                "signer key id must be non-empty",
            ));
        }
        let rec_obj = record.as_object().ok_or_else(|| {
            TrustRegistryError::new("invalid_signer", "signer record is not an object")
        })?;
        expect_exact_fields(rec_obj, &["algorithm", "public_key"], "signer")?;
        if rec_obj.get("algorithm").and_then(StrictJson::as_str) != Some("Ed25519") {
            return Err(TrustRegistryError::new(
                "unsupported_algorithm",
                "signer algorithm is not Ed25519",
            ));
        }
        let pk_str = rec_obj
            .get("public_key")
            .and_then(StrictJson::as_str)
            .ok_or_else(|| {
                TrustRegistryError::new("invalid_base64", "signer public_key must be base64url")
            })?;
        let raw_key = b64url_decode_canonical(pk_str, "signer public key")?;
        let pk = Ed25519PublicKey::from_slice(&raw_key).map_err(|_| {
            TrustRegistryError::new(
                "invalid_signer",
                "signer public key must be 32-byte Ed25519",
            )
        })?;
        parsed.insert(key_id.clone(), pk);
    }
    Ok(parsed)
}

/// Verifies raw Trust Registry v2 bytes against a pinned trust-root file.
pub fn verify_registry_bytes<'a, I>(
    raw: &[u8],
    trust_root_path: &Path,
    required_nodes: I,
    constraints: VerifyConstraints,
) -> Result<VerifiedRegistry, TrustRegistryError>
where
    I: IntoIterator<Item = &'a str>,
{
    if raw.len() > MAX_REGISTRY_BYTES {
        return Err(TrustRegistryError::new(
            "registry_too_large",
            "invalid registry byte length",
        ));
    }
    let envelope = parse_strict_json_object(raw, "trust registry v2")?;
    expect_exact_fields(&envelope, &["signed", "signatures"], "trust registry")?;

    let signed = envelope
        .get("signed")
        .and_then(StrictJson::as_object)
        .ok_or_else(|| {
            TrustRegistryError::new("invalid_signed_body", "signed body must be an object")
        })?;
    expect_exact_fields(signed, &["schema", "version", "nodes"], "signed body")?;

    if signed.get("schema").and_then(StrictJson::as_str) != Some(REGISTRY_SCHEMA) {
        return Err(TrustRegistryError::new(
            "invalid_schema",
            "a version 2 registry is required",
        ));
    }

    let version = signed
        .get("version")
        .and_then(StrictJson::as_strict_u64)
        .filter(|&v| v >= 1)
        .ok_or_else(|| {
            TrustRegistryError::new(
                "invalid_version",
                "registry version must be an integer >= 1",
            )
        })?;

    if let Some(exact) = constraints.exact_version {
        if version != exact {
            let code = if version < exact {
                "stale_version"
            } else {
                "uncommitted_version"
            };
            return Err(TrustRegistryError::new(
                code,
                "registry does not match the accepted version",
            ));
        }
    }
    if version < constraints.minimum_version {
        return Err(TrustRegistryError::new(
            "stale_version",
            "registry is below the required version",
        ));
    }

    let nodes_obj = signed
        .get("nodes")
        .and_then(StrictJson::as_object)
        .filter(|m| !m.is_empty() && m.len() <= MAX_NODES)
        .ok_or_else(|| {
            TrustRegistryError::new("invalid_nodes", "registry node count is out of bounds")
        })?;

    let mut required = BTreeSet::new();
    for name in required_nodes {
        validate_node_name(name)?;
        required.insert(name.to_owned());
    }
    let actual: BTreeSet<String> = nodes_obj.keys().cloned().collect();
    if required.iter().any(|n| !actual.contains(n)) {
        return Err(TrustRegistryError::new(
            "missing_node",
            "registry lacks a required node",
        ));
    }
    if actual.iter().any(|n| !required.contains(n)) {
        return Err(TrustRegistryError::new(
            "unknown_node",
            "registry contains an unexpected node",
        ));
    }

    let mut normalized = BTreeMap::new();
    let mut seen_encryption = BTreeSet::new();
    let mut seen_signing = BTreeSet::new();

    for (name, val) in nodes_obj {
        validate_node_name(name)?;
        let entry = val
            .as_object()
            .ok_or_else(|| TrustRegistryError::new("invalid_node", "invalid node entry"))?;
        expect_exact_fields(
            entry,
            &["encryption", "verification", "key_id", "revoked"],
            "node",
        )?;

        let enc_str = entry
            .get("encryption")
            .and_then(StrictJson::as_str)
            .ok_or_else(|| {
                TrustRegistryError::new("invalid_node_key", "encryption key must be hex")
            })?;
        let ver_str = entry
            .get("verification")
            .and_then(StrictJson::as_str)
            .ok_or_else(|| {
                TrustRegistryError::new("invalid_node_key", "verification key must be hex")
            })?;

        let enc_bytes = parse_key_hex(enc_str)?;
        let ver_bytes = parse_key_hex(ver_str)?;

        let expected_key_id = sha256_hex(&ver_bytes);
        let actual_key_id = entry
            .get("key_id")
            .and_then(StrictJson::as_str)
            .unwrap_or("");
        if actual_key_id != expected_key_id {
            return Err(TrustRegistryError::new(
                "invalid_key_id",
                "message key identifier does not match its public key",
            ));
        }

        let revoked = entry
            .get("revoked")
            .and_then(StrictJson::as_bool)
            .ok_or_else(|| {
                TrustRegistryError::new("invalid_revocation", "revoked must be a boolean")
            })?;

        if seen_encryption.contains(&enc_bytes)
            || seen_signing.contains(&ver_bytes)
            || enc_bytes == ver_bytes
        {
            return Err(TrustRegistryError::new(
                "shared_node_key",
                "node encryption and signing keys must be individual",
            ));
        }
        seen_encryption.insert(enc_bytes);
        seen_signing.insert(ver_bytes);

        let encryption = X25519PublicKey::from_bytes(enc_bytes);
        let verification = Ed25519PublicKey::from_bytes(ver_bytes).map_err(|_| {
            TrustRegistryError::new("invalid_node_key", "invalid Ed25519 verifying key")
        })?;

        normalized.insert(
            name.clone(),
            NodeKeyRecord {
                encryption,
                verification,
                key_id: expected_key_id,
                revoked,
            },
        );
    }

    let signatures = envelope
        .get("signatures")
        .and_then(StrictJson::as_array)
        .filter(|arr| arr.len() == 1)
        .ok_or_else(|| {
            TrustRegistryError::new(
                "missing_signature",
                "exactly one registry signature is required",
            )
        })?;
    let sig_obj = signatures[0].as_object().ok_or_else(|| {
        TrustRegistryError::new("missing_signature", "signature entry must be an object")
    })?;
    expect_exact_fields(sig_obj, &["key_id", "algorithm", "sig"], "signature")?;

    if sig_obj.get("algorithm").and_then(StrictJson::as_str) != Some("Ed25519") {
        return Err(TrustRegistryError::new(
            "unsupported_algorithm",
            "registry signature is not Ed25519",
        ));
    }

    let trust_keys = load_trust_root(trust_root_path)?;
    if trust_keys
        .values()
        .any(|root_pk| seen_signing.contains(root_pk.as_bytes()))
    {
        return Err(TrustRegistryError::new(
            "root_key_reused",
            "registry root must not be a node message key",
        ));
    }

    let signer_key_id = sig_obj
        .get("key_id")
        .and_then(StrictJson::as_str)
        .ok_or_else(|| {
            TrustRegistryError::new("unknown_signer", "registry signer is not pinned")
        })?;
    let root_pk = trust_keys.get(signer_key_id).ok_or_else(|| {
        TrustRegistryError::new("unknown_signer", "registry signer is not pinned")
    })?;

    let sig_b64 = sig_obj
        .get("sig")
        .and_then(StrictJson::as_str)
        .ok_or_else(|| {
            TrustRegistryError::new("invalid_base64", "registry signature must be base64url")
        })?;
    let sig_raw = b64url_decode_canonical(sig_b64, "registry signature")?;
    let signature = Ed25519Signature::from_slice(&sig_raw).map_err(|_| {
        TrustRegistryError::new("invalid_signature", "invalid Ed25519 signature length")
    })?;

    let signed_canonical = canonical_object_bytes(signed)?;
    root_pk
        .verify_strict(&signed_canonical, &signature)
        .map_err(|_| {
            TrustRegistryError::new("bad_signature", "registry signature verification failed")
        })?;

    let digest = registry_digest(raw);
    if let Some(expected_sha) = constraints.exact_sha256 {
        if digest != expected_sha {
            return Err(TrustRegistryError::new(
                "same_version_replacement",
                "registry differs from the accepted document",
            ));
        }
    }

    Ok(VerifiedRegistry {
        version,
        signer_key_id: signer_key_id.to_owned(),
        nodes: normalized,
        sha256: digest,
        recovered: false,
    })
}

fn state_bytes(registry: &VerifiedRegistry) -> Result<Vec<u8>, TrustRegistryError> {
    let mut state = BTreeMap::new();
    state.insert(
        "schema".to_owned(),
        StrictJson::String(STATE_SCHEMA.to_owned()),
    );
    state.insert(
        "accepted_version".to_owned(),
        StrictJson::Uint(registry.version),
    );
    state.insert(
        "accepted_sha256".to_owned(),
        StrictJson::String(registry.sha256.clone()),
    );
    let mut bytes = canonical_object_bytes(&state)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_state(path: &Path) -> Result<Option<(u64, String)>, TrustRegistryError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = read_bounded(path, "trust state")?;
    let state = parse_strict_json_object(&raw, "trust state")?;
    expect_exact_fields(
        &state,
        &["schema", "accepted_version", "accepted_sha256"],
        "trust state",
    )?;
    if state.get("schema").and_then(StrictJson::as_str) != Some(STATE_SCHEMA) {
        return Err(TrustRegistryError::new(
            "invalid_schema",
            "unexpected trust-state schema",
        ));
    }
    let version = state
        .get("accepted_version")
        .and_then(StrictJson::as_strict_u64)
        .filter(|&v| v >= 1)
        .ok_or_else(|| {
            TrustRegistryError::new("invalid_state", "accepted version must be an integer >= 1")
        })?;
    let digest_str = state
        .get("accepted_sha256")
        .and_then(StrictJson::as_str)
        .ok_or_else(|| {
            TrustRegistryError::new("invalid_state", "accepted digest must be SHA-256 hex")
        })?;
    if digest_str.len() != 64 || hex::decode(digest_str).is_err() {
        return Err(TrustRegistryError::new(
            "invalid_state",
            "accepted digest must be SHA-256 hex",
        ));
    }
    Ok(Some((version, digest_str.to_ascii_lowercase())))
}

/// Atomically writes `data` to `path` using a temporary file in the same directory,
/// `sync_all()`, and atomic `rename`.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), TrustRegistryError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|_| TrustRegistryError::new("io_error", "cannot create parent directory"))?;
    let mut temp = NamedTempFile::new_in(parent)
        .map_err(|_| TrustRegistryError::new("io_error", "cannot create temp file"))?;
    temp.write_all(data)
        .and_then(|()| temp.flush())
        .and_then(|()| temp.as_file().sync_all())
        .map_err(|_| TrustRegistryError::new("io_error", "cannot sync temp file"))?;
    temp.persist(path)
        .map_err(|_| TrustRegistryError::new("io_error", "atomic rename failed"))?;
    sync_parent_dir(parent);
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_parent_dir(_dir: &Path) {}

/// Persistent anti-rollback Trust Registry v2 store with atomic commit ordering
/// and automatic `last-valid` recovery.
#[derive(Debug, Clone)]
pub struct TrustRegistryStore {
    pub registry_path: PathBuf,
    pub trust_root_path: PathBuf,
    pub state_path: PathBuf,
    pub backup_path: PathBuf,
}

impl TrustRegistryStore {
    /// Creates a store bound to explicit live, root, state, and backup paths.
    #[must_use]
    pub fn new(
        registry_path: impl Into<PathBuf>,
        trust_root_path: impl Into<PathBuf>,
        state_path: impl Into<PathBuf>,
        backup_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            registry_path: registry_path.into(),
            trust_root_path: trust_root_path.into(),
            state_path: state_path.into(),
            backup_path: backup_path.into(),
        }
    }

    fn verify_live(
        &self,
        required_nodes: &[&str],
        state: Option<&(u64, String)>,
    ) -> Result<(VerifiedRegistry, Vec<u8>), TrustRegistryError> {
        let raw = read_bounded(&self.registry_path, "live trust registry")?;
        let constraints = match state {
            None => VerifyConstraints::default(),
            Some((v, sha)) => VerifyConstraints {
                minimum_version: 1,
                exact_version: Some(*v),
                exact_sha256: Some(sha.clone()),
            },
        };
        let verified = verify_registry_bytes(
            &raw,
            &self.trust_root_path,
            required_nodes.iter().copied(),
            constraints,
        )?;
        Ok((verified, raw))
    }

    /// Loads and verifies the active registry, transparently recovering from `last-valid`
    /// if the live file was corrupted or rolled back while committed state exists.
    pub fn load<'a, I>(&self, required_nodes: I) -> Result<VerifiedRegistry, TrustRegistryError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let required: Vec<&str> = required_nodes.into_iter().collect();
        let state = read_state(&self.state_path)?;
        match self.verify_live(&required, state.as_ref()) {
            Ok((verified, raw)) => {
                if state.is_none() {
                    let sb = state_bytes(&verified)?;
                    atomic_write(&self.state_path, &sb)?;
                }
                atomic_write(&self.backup_path, &raw)?;
                Ok(verified)
            }
            Err(live_error) => {
                let Some((exact_ver, exact_sha)) = state else {
                    return Err(live_error);
                };
                if !self.backup_path.exists() {
                    return Err(live_error);
                }
                let backup_raw = read_bounded(&self.backup_path, "last-valid trust registry")?;
                let backup = verify_registry_bytes(
                    &backup_raw,
                    &self.trust_root_path,
                    required.iter().copied(),
                    VerifyConstraints {
                        minimum_version: 1,
                        exact_version: Some(exact_ver),
                        exact_sha256: Some(exact_sha),
                    },
                )?;
                atomic_write(&self.registry_path, &backup_raw)?;
                Ok(VerifiedRegistry {
                    version: backup.version,
                    signer_key_id: backup.signer_key_id,
                    nodes: backup.nodes,
                    sha256: backup.sha256,
                    recovered: true,
                })
            }
        }
    }

    /// Installs a strictly newer signed registry candidate using crash-safe commit ordering:
    /// `live -> state -> backup`.
    pub fn install_update<'a, I>(
        &self,
        candidate_path: &Path,
        required_nodes: I,
    ) -> Result<VerifiedRegistry, TrustRegistryError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        self.install_update_with_writer(candidate_path, required_nodes, atomic_write)
    }

    /// Same as [`Self::install_update`], allowing fault-injection of atomic writes in tests.
    pub fn install_update_with_writer<'a, I, W>(
        &self,
        candidate_path: &Path,
        required_nodes: I,
        mut writer: W,
    ) -> Result<VerifiedRegistry, TrustRegistryError>
    where
        I: IntoIterator<Item = &'a str>,
        W: FnMut(&Path, &[u8]) -> Result<(), TrustRegistryError>,
    {
        let required: Vec<&str> = required_nodes.into_iter().collect();
        let current =
            if self.registry_path.exists() || self.state_path.exists() || self.backup_path.exists()
            {
                Some(self.load(required.iter().copied())?)
            } else {
                None
            };
        let raw = read_bounded(candidate_path, "candidate trust registry")?;
        let minimum_version = current.map_or(1, |c| c.version.saturating_add(1));
        let candidate = verify_registry_bytes(
            &raw,
            &self.trust_root_path,
            required.iter().copied(),
            VerifyConstraints {
                minimum_version,
                exact_version: None,
                exact_sha256: None,
            },
        )?;
        let sb = state_bytes(&candidate)?;

        // Commit order is intentional:
        // - Interrupted before state commit -> load() restores old backup.
        // - Interrupted after state commit  -> live file is authoritative, load() refreshes backup.
        writer(&self.registry_path, &raw)?;
        writer(&self.state_path, &sb)?;
        writer(&self.backup_path, &raw)?;
        Ok(candidate)
    }
}

/// Fail-closed environment loader matching `trust_registry.py::load_verified_registry_from_environment`.
///
/// Explicitly rejects legacy unsigned `IKE_CASCADE_PUBLIC_KEYS_JSON` / `IKE_CASCADE_PUBLIC_KEYS_FILE`.
pub fn load_verified_registry_from_env_map<'a, I, F>(
    required_nodes: I,
    get_env: F,
) -> Result<VerifiedRegistry, TrustRegistryError>
where
    I: IntoIterator<Item = &'a str>,
    F: Fn(&str) -> Option<String>,
{
    for forbidden in [
        "IKE_CASCADE_PUBLIC_KEYS_JSON",
        "IKE_CASCADE_PUBLIC_KEYS_FILE",
    ] {
        if get_env(forbidden).is_some_and(|v| !v.trim().is_empty()) {
            return Err(TrustRegistryError::new(
                "unsigned_registry_rejected",
                "unsigned public keys are not accepted",
            ));
        }
    }
    let registry = get_env("IKE_CASCADE_TRUST_REGISTRY_FILE")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    let root = get_env("IKE_CASCADE_TRUST_ROOT_FILE")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    if registry.is_empty() || root.is_empty() {
        return Err(TrustRegistryError::new(
            "missing_trust_configuration",
            "signed registry and pinned root files are required",
        ));
    }
    let state = get_env("IKE_CASCADE_TRUST_STATE_FILE")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{registry}.state.json"));
    let backup = get_env("IKE_CASCADE_TRUST_BACKUP_FILE")
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{registry}.last-valid.json"));

    TrustRegistryStore::new(registry, root, state, backup).load(required_nodes)
}

/// Loads a verified Trust Registry v2 using the current process environment.
pub fn load_verified_registry_from_environment<'a, I>(
    required_nodes: I,
) -> Result<VerifiedRegistry, TrustRegistryError>
where
    I: IntoIterator<Item = &'a str>,
{
    load_verified_registry_from_env_map(required_nodes, |k| std::env::var(k).ok())
}
