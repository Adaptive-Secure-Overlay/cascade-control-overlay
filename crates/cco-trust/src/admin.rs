#![forbid(unsafe_code)]
//! Offline provisioning helpers for Trust Registry v2 (`trust-admin` / `mcc_e2e_admin.py`).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use cco_crypto::{
    Ed25519PublicKey, Ed25519SecretKey, X25519PublicKey, X25519SecretKey, sha256_hex,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::TrustRegistryError;
use crate::json::{StrictJson, b64url_encode, canonical_object_bytes};
use crate::{
    NodeKeyRecord, REGISTRY_SCHEMA, ROOT_SCHEMA, VerifyConstraints, validate_node_name,
    verify_registry_bytes,
};

/// Public node entry produced by offline `keygen` and consumed by `sign-registry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePublicEntry {
    pub node: String,
    pub keys: NodePublicEntryKeys,
}

/// Public key bundle inside [`NodePublicEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePublicEntryKeys {
    pub encryption: String,
    pub verification: String,
    pub key_id: String,
    pub revoked: bool,
}

/// Result metadata returned after generating a node identity directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeygenSummary {
    pub generated: bool,
    pub node: String,
    pub public_entry: NodePublicEntry,
    pub posix_permissions_verified: bool,
    pub test_fixtures_only: bool,
}

/// Result metadata returned after signing a Trust Registry v2 document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignRegistrySummary {
    pub signed: bool,
    pub version: u64,
    pub nodes: Vec<String>,
    pub output_sha256: String,
    pub test_fixtures_only: bool,
}

/// Builds a canonical Trust Root v1 JSON document pinning Ed25519 root signers.
pub fn build_trust_root_bytes(
    signers: &BTreeMap<String, Ed25519PublicKey>,
) -> Result<Vec<u8>, TrustRegistryError> {
    if signers.is_empty() {
        return Err(TrustRegistryError::new(
            "invalid_trust_root",
            "trust root must contain at least one signer",
        ));
    }
    let mut signer_map = BTreeMap::new();
    for (key_id, pub_key) in signers {
        if key_id.is_empty() {
            return Err(TrustRegistryError::new(
                "invalid_signer",
                "signer key id must be non-empty",
            ));
        }
        let mut rec = BTreeMap::new();
        rec.insert(
            "algorithm".to_owned(),
            StrictJson::String("Ed25519".to_owned()),
        );
        rec.insert(
            "public_key".to_owned(),
            StrictJson::String(b64url_encode(pub_key.as_bytes())),
        );
        signer_map.insert(key_id.clone(), StrictJson::Object(rec));
    }
    let mut root = BTreeMap::new();
    root.insert(
        "schema".to_owned(),
        StrictJson::String(ROOT_SCHEMA.to_owned()),
    );
    root.insert("signers".to_owned(), StrictJson::Object(signer_map));
    canonical_object_bytes(&root)
}

/// Signs a Trust Registry v2 envelope using an Ed25519 root issuer key.
///
/// Returns canonical compact JSON bytes compatible with `trust_registry.py`.
pub fn sign_registry_v2(
    version: u64,
    nodes: &BTreeMap<String, NodeKeyRecord>,
    issuer_id: &str,
    issuer_key: &Ed25519SecretKey,
) -> Result<Vec<u8>, TrustRegistryError> {
    if version < 1 {
        return Err(TrustRegistryError::new(
            "invalid_version",
            "registry version must be >= 1",
        ));
    }
    if issuer_id.is_empty() {
        return Err(TrustRegistryError::new(
            "invalid_signer",
            "issuer_id must be non-empty",
        ));
    }
    let mut nodes_map = BTreeMap::new();
    for (name, rec) in nodes {
        validate_node_name(name)?;
        let mut entry = BTreeMap::new();
        entry.insert(
            "encryption".to_owned(),
            StrictJson::String(rec.encryption_hex()),
        );
        entry.insert(
            "verification".to_owned(),
            StrictJson::String(rec.verification_hex()),
        );
        entry.insert("key_id".to_owned(), StrictJson::String(rec.key_id.clone()));
        entry.insert("revoked".to_owned(), StrictJson::Bool(rec.revoked));
        nodes_map.insert(name.clone(), StrictJson::Object(entry));
    }

    let mut signed = BTreeMap::new();
    signed.insert(
        "schema".to_owned(),
        StrictJson::String(REGISTRY_SCHEMA.to_owned()),
    );
    signed.insert("version".to_owned(), StrictJson::Uint(version));
    signed.insert("nodes".to_owned(), StrictJson::Object(nodes_map));

    let signed_canonical = canonical_object_bytes(&signed)?;
    let sig = issuer_key.sign(&signed_canonical);

    let mut sig_obj = BTreeMap::new();
    sig_obj.insert(
        "algorithm".to_owned(),
        StrictJson::String("Ed25519".to_owned()),
    );
    sig_obj.insert(
        "key_id".to_owned(),
        StrictJson::String(issuer_id.to_owned()),
    );
    sig_obj.insert(
        "sig".to_owned(),
        StrictJson::String(b64url_encode(sig.as_bytes())),
    );

    let mut envelope = BTreeMap::new();
    envelope.insert("signed".to_owned(), StrictJson::Object(signed));
    envelope.insert(
        "signatures".to_owned(),
        StrictJson::Array(vec![StrictJson::Object(sig_obj)]),
    );
    canonical_object_bytes(&envelope)
}

/// Creates a new offline node identity directory with separate Ed25519 and X25519 keys.
///
/// Refuses to overwrite an existing directory. On non-POSIX platforms (Windows),
/// requires `test_fixtures_only = true` because POSIX 0600 mode bits are not enforced.
pub fn generate_node_identity(
    node_name: &str,
    directory: &Path,
    test_fixtures_only: bool,
) -> Result<KeygenSummary, TrustRegistryError> {
    validate_node_name(node_name)?;
    let posix = cfg!(unix);
    if !posix && !test_fixtures_only {
        return Err(TrustRegistryError::new(
            "private_file_permissions",
            "native node provisioning requires POSIX 0600 permissions; pass test_fixtures_only for non-POSIX fixtures",
        ));
    }
    if directory.exists() {
        return Err(TrustRegistryError::new(
            "io_error",
            "refusing to overwrite existing identity directory",
        ));
    }
    create_private_dir(directory)?;

    let signing = Ed25519SecretKey::generate();
    let encryption = X25519SecretKey::generate();

    let signing_line = Zeroizing::new(format!("{}\n", *signing.to_hex_zeroizing()));
    write_new_file(
        &directory.join("signing.key"),
        signing_line.as_bytes(),
        true,
    )?;

    let enc_line = Zeroizing::new(format!("{}\n", *encryption.to_hex_zeroizing()));
    write_new_file(&directory.join("encryption.key"), enc_line.as_bytes(), true)?;

    let verify_pub = signing.public_key();
    let enc_pub = encryption.public_key();
    let public_entry = NodePublicEntry {
        node: node_name.to_owned(),
        keys: NodePublicEntryKeys {
            encryption: enc_pub.to_hex(),
            verification: verify_pub.to_hex(),
            key_id: verify_pub.key_id(),
            revoked: false,
        },
    };
    let mut entry_json = serde_json::to_vec(&public_entry)
        .map_err(|_| TrustRegistryError::new("corrupt_json", "cannot serialize public entry"))?;
    entry_json.push(b'\n');
    write_new_file(&directory.join("public-entry.json"), &entry_json, false)?;

    Ok(KeygenSummary {
        generated: true,
        node: node_name.to_owned(),
        public_entry,
        posix_permissions_verified: posix,
        test_fixtures_only,
    })
}

/// Signs and self-verifies a Trust Registry v2 file from node public-entry JSON files.
pub fn sign_registry_files(
    entry_paths: &[&Path],
    trust_root_path: &Path,
    issuer_key_path: &Path,
    issuer_id: &str,
    version: u64,
    output_path: &Path,
    test_fixtures_only: bool,
) -> Result<SignRegistrySummary, TrustRegistryError> {
    if !cfg!(unix) && !test_fixtures_only {
        return Err(TrustRegistryError::new(
            "private_file_permissions",
            "signing on non-POSIX host requires explicit test_fixtures_only",
        ));
    }
    if entry_paths.len() < 2 || entry_paths.len() > crate::MAX_NODES {
        return Err(TrustRegistryError::new(
            "invalid_nodes",
            "registry requires between 2 and 256 node entries",
        ));
    }
    if output_path.exists() {
        return Err(TrustRegistryError::new(
            "io_error",
            "refusing to overwrite existing output registry",
        ));
    }

    let mut nodes = BTreeMap::new();
    for path in entry_paths {
        let raw = fs::read(path).map_err(|_| {
            TrustRegistryError::new("missing_document", "cannot read node public entry")
        })?;
        if raw.len() > 8192 {
            return Err(TrustRegistryError::new(
                "registry_too_large",
                "public entry exceeds size limit",
            ));
        }
        let entry: NodePublicEntry = serde_json::from_slice(&raw)
            .map_err(|_| TrustRegistryError::new("corrupt_json", "invalid node public entry"))?;
        if nodes.contains_key(&entry.node) {
            return Err(TrustRegistryError::new(
                "duplicate_json_key",
                "duplicate node entry",
            ));
        }
        let enc = X25519PublicKey::from_hex(&entry.keys.encryption)
            .map_err(|_| TrustRegistryError::new("invalid_node_key", "invalid encryption key"))?;
        let ver = Ed25519PublicKey::from_hex(&entry.keys.verification)
            .map_err(|_| TrustRegistryError::new("invalid_node_key", "invalid verification key"))?;
        nodes.insert(
            entry.node,
            NodeKeyRecord {
                encryption: enc,
                verification: ver,
                key_id: entry.keys.key_id,
                revoked: entry.keys.revoked,
            },
        );
    }

    let issuer_key = read_ed25519_key_file(issuer_key_path, test_fixtures_only)?;
    let mut data = sign_registry_v2(version, &nodes, issuer_id, &issuer_key)?;
    data.push(b'\n');

    let required: Vec<String> = nodes.keys().cloned().collect();
    let verified = verify_registry_bytes(
        &data,
        trust_root_path,
        required.iter().map(String::as_str),
        VerifyConstraints::default(),
    )?;

    write_new_file(output_path, &data, false)?;

    Ok(SignRegistrySummary {
        signed: true,
        version: verified.version(),
        nodes: required,
        output_sha256: sha256_hex(&data),
        test_fixtures_only,
    })
}

/// Reads an Ed25519 private seed file (64 lowercase hex chars + optional trailing `\n`).
pub fn read_ed25519_key_file(
    path: &Path,
    test_fixtures_only: bool,
) -> Result<Ed25519SecretKey, TrustRegistryError> {
    let raw = read_private_hex_file(path, test_fixtures_only)?;
    Ed25519SecretKey::from_hex(&raw)
        .map_err(|_| TrustRegistryError::new("invalid_signer", "invalid issuer private key hex"))
}

/// Reads an X25519 private key file (64 lowercase hex chars + optional trailing `\n`).
pub fn read_x25519_key_file(
    path: &Path,
    test_fixtures_only: bool,
) -> Result<X25519SecretKey, TrustRegistryError> {
    let raw = read_private_hex_file(path, test_fixtures_only)?;
    X25519SecretKey::from_hex(&raw)
        .map_err(|_| TrustRegistryError::new("invalid_node_key", "invalid private key hex"))
}

fn read_private_hex_file(
    path: &Path,
    test_fixtures_only: bool,
) -> Result<String, TrustRegistryError> {
    let meta = fs::symlink_metadata(path).map_err(|_| {
        TrustRegistryError::new("missing_document", "cannot inspect private key file")
    })?;
    if !meta.file_type().is_file() {
        return Err(TrustRegistryError::new(
            "private_file_permissions",
            "private key must be a regular file",
        ));
    }
    check_posix_private_permissions(&meta, test_fixtures_only)?;
    let raw = fs::read(path)
        .map_err(|_| TrustRegistryError::new("missing_document", "cannot read private key"))?;
    if raw.len() > 67 {
        return Err(TrustRegistryError::new(
            "invalid_node_key",
            "private key file exceeds 64 hex chars",
        ));
    }
    let text = std::str::from_utf8(&raw)
        .map_err(|_| TrustRegistryError::new("invalid_node_key", "private key is not ASCII"))?;
    let trimmed = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    Ok(trimmed.to_owned())
}

#[cfg(unix)]
fn check_posix_private_permissions(
    meta: &fs::Metadata,
    _test_fixtures_only: bool,
) -> Result<(), TrustRegistryError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TrustRegistryError::new(
            "private_file_permissions",
            "private key must not have group or world permissions",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_posix_private_permissions(
    _meta: &fs::Metadata,
    test_fixtures_only: bool,
) -> Result<(), TrustRegistryError> {
    if !test_fixtures_only {
        return Err(TrustRegistryError::new(
            "private_file_permissions",
            "non-POSIX private key permissions require test_fixtures_only",
        ));
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<(), TrustRegistryError> {
    fs::create_dir(path)
        .map_err(|_| TrustRegistryError::new("io_error", "cannot create identity directory"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| {
            TrustRegistryError::new("private_file_permissions", "cannot set 0700 on directory")
        })?;
    }
    Ok(())
}

fn write_new_file(path: &Path, data: &[u8], private: bool) -> Result<(), TrustRegistryError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    let _ = private;
    let mut file = opts
        .open(path)
        .map_err(|_| TrustRegistryError::new("io_error", "cannot create output file"))?;
    file.write_all(data)
        .and_then(|()| file.sync_all())
        .map_err(|_| TrustRegistryError::new("io_error", "cannot sync output file"))
}
