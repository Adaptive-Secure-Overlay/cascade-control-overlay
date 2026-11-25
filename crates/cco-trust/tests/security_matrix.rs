#![forbid(unsafe_code)]
//! Comprehensive positive & negative security matrix for Trust Registry v2,
//! plus byte-for-byte Python golden-vector cross-compatibility tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use cco_crypto::{Ed25519SecretKey, X25519SecretKey};
use cco_trust::{
    MAX_NODES, MAX_REGISTRY_BYTES, NodeKeyRecord, REGISTRY_SCHEMA, TrustRegistryError,
    TrustRegistryStore, VerifyConstraints, atomic_write, build_trust_root_bytes,
    generate_node_identity, load_verified_registry_from_env_map, registry_digest,
    sign_registry_files, sign_registry_v2, verification_key_id, verify_registry_bytes,
};
use tempfile::TempDir;

struct Fixture {
    _dir: TempDir,
    root_dir: PathBuf,
    root_path: PathBuf,
    root_sk: Ed25519SecretKey,
    names: Vec<String>,
    nodes: BTreeMap<String, NodeKeyRecord>,
}

impl Fixture {
    fn new(names: &[&str]) -> Self {
        let dir = TempDir::new().unwrap();
        let root_dir = dir.path().to_path_buf();
        let root_sk = Ed25519SecretKey::generate();
        let mut signers = BTreeMap::new();
        signers.insert("test-root".to_owned(), root_sk.public_key());
        let root_bytes = build_trust_root_bytes(&signers).unwrap();
        let root_path = root_dir.join("root.json");
        fs::write(&root_path, root_bytes).unwrap();

        let mut nodes = BTreeMap::new();
        for &name in names {
            let signing = Ed25519SecretKey::generate();
            let encryption = X25519SecretKey::generate();
            let ver = signing.public_key();
            nodes.insert(
                name.to_owned(),
                NodeKeyRecord {
                    encryption: encryption.public_key(),
                    verification: ver,
                    key_id: ver.key_id(),
                    revoked: false,
                },
            );
        }

        Self {
            _dir: dir,
            root_dir,
            root_path,
            root_sk,
            names: names.iter().map(|s| (*s).to_owned()).collect(),
            nodes,
        }
    }

    fn name_refs(&self) -> Vec<&str> {
        self.names.iter().map(String::as_str).collect()
    }

    fn raw(&self, version: u64, nodes: Option<&BTreeMap<String, NodeKeyRecord>>) -> Vec<u8> {
        sign_registry_v2(
            version,
            nodes.unwrap_or(&self.nodes),
            "test-root",
            &self.root_sk,
        )
        .unwrap()
    }

    fn store(&self) -> TrustRegistryStore {
        TrustRegistryStore::new(
            self.root_dir.join("registry.json"),
            self.root_path.clone(),
            self.root_dir.join("accepted.json"),
            self.root_dir.join("last-valid.json"),
        )
    }
}

#[test]
fn python_golden_vector_trust_registry_v2_byte_exact() {
    let expected_root = r#"{"schema":"ipsec-ike-cascade-trust-root/v1","signers":{"golden-root":{"algorithm":"Ed25519","public_key":"XJxt8mHJy4QEdXdqrvzZRLQFMo-rKPmzqV70BJDT3oQ"}}}"#;
    let expected_reg = r#"{"signatures":[{"algorithm":"Ed25519","key_id":"golden-root","sig":"ZlkKvsTuyi0c3pfkqVOcB-Pxtj2m38HPCfeHT0Wgz2JeaKhD6joAyQCeVfq4r1NsIUkQL1Ft2TbjZaZHV2NxCg"}],"signed":{"nodes":{"A":{"encryption":"7a1a4e709bf085ac494aba0469b9b1eda0ab1f78b16aabb79ffeda90623e8522","key_id":"48cca97f8993ffaebcac9728d7f94f7144f18090d329d9370a7dfc42db38d14d","revoked":false,"verification":"884b8857f4eaa1613c61504db34d4beaf346517a0e31de3cddd4d9b4201d9d0b"},"B":{"encryption":"132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472","key_id":"1325b850c2871916eae203f0efc3c8987f64e5e3cdb27679e6d1fa97808357e6","revoked":false,"verification":"a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"},"X1":{"encryption":"cdefd8783a91b446640e2e1f95599db35e484a0071bd2182b3b60d0812c10c70","key_id":"8a382c2a33e42c4f39c93a210ff0cbab5c33ea480f28be614b9da208ae63f634","revoked":false,"verification":"74f85cda34d1c27c4621484731e91579c3d9c6cfc0d94b281aa11e9162058aa9"},"X2":{"encryption":"ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b","key_id":"5f23ba66a62a6aeffca866a461c0686ae7f869c685e1ea1f69b2b84e84de5bb0","revoked":false,"verification":"58936604abda112bc94933569c82f8d0cc0ddf92a3f8329f2f448f7f484a594c"}},"schema":"ipsec-ike-cascade-trust-registry/v2","version":1}}"#;
    let expected_sha = "380cfe3738f17a4e66f6d86ad286a85aa615f64f15206367977160ee34bfa332";

    let root_sk = Ed25519SecretKey::from_bytes([0x10; 32]);
    let mut signers = BTreeMap::new();
    signers.insert("golden-root".to_owned(), root_sk.public_key());
    let rust_root = build_trust_root_bytes(&signers).unwrap();
    assert_eq!(std::str::from_utf8(&rust_root).unwrap(), expected_root);

    let mut nodes = BTreeMap::new();
    for (idx, name) in ["A", "B", "X1", "X2"].iter().enumerate() {
        let i = (idx + 1) as u8;
        let esk = Ed25519SecretKey::from_bytes([0x20 + i; 32]);
        let xsk = X25519SecretKey::from_bytes([0x40 + i; 32]);
        let ver = esk.public_key();
        nodes.insert(
            (*name).to_owned(),
            NodeKeyRecord {
                encryption: xsk.public_key(),
                verification: ver,
                key_id: ver.key_id(),
                revoked: false,
            },
        );
    }
    let rust_reg = sign_registry_v2(1, &nodes, "golden-root", &root_sk).unwrap();
    assert_eq!(std::str::from_utf8(&rust_reg).unwrap(), expected_reg);
    assert_eq!(registry_digest(&rust_reg), expected_sha);

    let dir = TempDir::new().unwrap();
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, expected_root.as_bytes()).unwrap();
    let verified = verify_registry_bytes(
        expected_reg.as_bytes(),
        &root_path,
        ["A", "B", "X1", "X2"],
        VerifyConstraints::default(),
    )
    .unwrap();
    assert_eq!(verified.version(), 1);
    assert_eq!(verified.sha256(), expected_sha);
    assert_eq!(verified.signer_key_id(), "golden-root");
}

#[test]
fn signed_v2_roundtrip_and_status() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let raw = f.raw(1, None);
    let verified = verify_registry_bytes(
        &raw,
        &f.root_path,
        f.name_refs(),
        VerifyConstraints::default(),
    )
    .unwrap();
    assert_eq!(verified.status().schema, REGISTRY_SCHEMA);
    assert_eq!(verified.status().nodes, vec!["A", "B", "X1", "X2"]);
    assert_eq!(
        verification_key_id(&f.nodes["A"].verification_hex()).unwrap(),
        f.nodes["A"].key_id
    );
}

#[test]
fn v1_entries_are_rejected_without_implicit_migration() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let raw = String::from_utf8(f.raw(1, None)).unwrap().replace(
        "ipsec-ike-cascade-trust-registry/v2",
        "ipsec-ike-cascade-trust-registry/v1",
    );
    let err = verify_registry_bytes(
        raw.as_bytes(),
        &f.root_path,
        f.name_refs(),
        VerifyConstraints::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "invalid_schema");
}

#[test]
fn unknown_signer_tampered_payload_and_missing_signature_rejected() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let raw_str = String::from_utf8(f.raw(1, None)).unwrap();

    // Unknown signer
    let unknown = raw_str.replace("\"key_id\":\"test-root\"", "\"key_id\":\"untrusted\"");
    let err = verify_registry_bytes(
        unknown.as_bytes(),
        &f.root_path,
        f.name_refs(),
        VerifyConstraints::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "unknown_signer");

    // Tampered node revocation flag -> bad_signature
    let tampered = raw_str.replacen("\"revoked\":false", "\"revoked\":true", 1);
    let err = verify_registry_bytes(
        tampered.as_bytes(),
        &f.root_path,
        f.name_refs(),
        VerifyConstraints::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "bad_signature");

    // Missing signatures array -> missing_signature
    let mut val: serde_json::Value = serde_json::from_str(&raw_str).unwrap();
    val["signatures"] = serde_json::json!([]);
    let no_sig = serde_json::to_vec(&val).unwrap();
    let err = verify_registry_bytes(
        &no_sig,
        &f.root_path,
        f.name_refs(),
        VerifyConstraints::default(),
    )
    .unwrap_err();
    assert_eq!(err.code(), "missing_signature");
}

#[test]
fn duplicate_json_keys_rejected_at_all_levels() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let raw_str = String::from_utf8(f.raw(1, None)).unwrap();

    for (old, new) in [
        ("\"version\":1", "\"version\":1,\"version\":1"),
        ("\"revoked\":false", "\"revoked\":false,\"revoked\":false"),
    ] {
        let dup = raw_str.replacen(old, new, 1);
        let err = verify_registry_bytes(
            dup.as_bytes(),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default(),
        )
        .unwrap_err();
        assert_eq!(err.code(), "duplicate_json_key");
    }
}

#[test]
fn node_key_format_key_id_and_revocation_are_strict() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let raw_str = String::from_utf8(f.raw(1, None)).unwrap();

    // Uppercase encryption key
    let upper = raw_str.replace(&f.nodes["A"].encryption_hex(), &"AA".repeat(32));
    assert_eq!(
        verify_registry_bytes(
            upper.as_bytes(),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "invalid_node_key"
    );

    // Leading space in verification key
    let spaced = raw_str.replace(
        &f.nodes["A"].verification_hex(),
        &format!(" {}", f.nodes["A"].verification_hex()),
    );
    assert_eq!(
        verify_registry_bytes(
            spaced.as_bytes(),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "invalid_node_key"
    );

    // Wrong key_id
    let wrong_kid = raw_str.replace(&f.nodes["A"].key_id, &"0".repeat(64));
    assert_eq!(
        verify_registry_bytes(
            wrong_kid.as_bytes(),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "invalid_key_id"
    );

    // Non-boolean revoked
    let bad_rev = raw_str.replacen("\"revoked\":false", "\"revoked\":0", 1);
    assert_eq!(
        verify_registry_bytes(
            bad_rev.as_bytes(),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "invalid_revocation"
    );

    // Explicit revoked = true is valid when properly signed, but require_active_node fails closed
    let mut nodes = f.nodes.clone();
    nodes.get_mut("A").unwrap().revoked = true;
    let verified = verify_registry_bytes(
        &f.raw(1, Some(&nodes)),
        &f.root_path,
        f.name_refs(),
        VerifyConstraints::default(),
    )
    .unwrap();
    assert!(verified.get_node("A").unwrap().revoked);
    assert_eq!(
        verified.require_active_node("A").unwrap_err().code(),
        "revoked_key"
    );
}

#[test]
fn individual_node_keys_and_separate_root_are_enforced() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);

    // Shared key between nodes A and B
    let mut shared = f.nodes.clone();
    shared.insert("B".to_owned(), shared["A"].clone());
    assert_eq!(
        verify_registry_bytes(
            &f.raw(1, Some(&shared)),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "shared_node_key"
    );

    // Encryption key == verification key on the same node
    let mut same_pair = f.nodes.clone();
    let ver_bytes = *same_pair["A"].verification.as_bytes();
    same_pair.get_mut("A").unwrap().encryption = cco_crypto::X25519PublicKey::from_bytes(ver_bytes);
    assert_eq!(
        verify_registry_bytes(
            &f.raw(1, Some(&same_pair)),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "shared_node_key"
    );

    // Root signer reused as a node verification key
    let mut reused_root = f.nodes.clone();
    let root_pk = f.root_sk.public_key();
    reused_root.get_mut("A").unwrap().verification = root_pk;
    reused_root.get_mut("A").unwrap().key_id = root_pk.key_id();
    assert_eq!(
        verify_registry_bytes(
            &f.raw(1, Some(&reused_root)),
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "root_key_reused"
    );
}

#[test]
fn required_nodes_version_types_and_resource_limits() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let raw = f.raw(1, None);

    assert_eq!(
        verify_registry_bytes(&raw, &f.root_path, ["A", "B"], VerifyConstraints::default())
            .unwrap_err()
            .code(),
        "unknown_node"
    );
    assert_eq!(
        verify_registry_bytes(
            &raw,
            &f.root_path,
            ["A", "B", "X1", "X2", "Z"],
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "missing_node"
    );

    // Oversized registry bytes
    let huge = vec![b' '; MAX_REGISTRY_BYTES + 1];
    assert_eq!(
        verify_registry_bytes(
            &huge,
            &f.root_path,
            f.name_refs(),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "registry_too_large"
    );

    // Invalid version types: true, 0, 1.0
    let raw_str = String::from_utf8(raw).unwrap();
    for bad_ver in ["true", "0", "1.0"] {
        let mutated = raw_str.replace("\"version\":1", &format!("\"version\":{bad_ver}"));
        assert_eq!(
            verify_registry_bytes(
                mutated.as_bytes(),
                &f.root_path,
                f.name_refs(),
                VerifyConstraints::default()
            )
            .unwrap_err()
            .code(),
            "invalid_version"
        );
    }

    // Exceeding MAX_NODES
    let mut too_many = serde_json::Map::new();
    let mut req_names = Vec::new();
    for i in 0..=MAX_NODES {
        let name = format!("n{i}");
        too_many.insert(name.clone(), serde_json::json!({}));
        req_names.push(name);
    }
    let big_env = serde_json::json!({
        "signed": {
            "schema": REGISTRY_SCHEMA,
            "version": 1,
            "nodes": too_many
        },
        "signatures": []
    });
    let big_bytes = serde_json::to_vec(&big_env).unwrap();
    assert_eq!(
        verify_registry_bytes(
            &big_bytes,
            &f.root_path,
            req_names.iter().map(String::as_str),
            VerifyConstraints::default()
        )
        .unwrap_err()
        .code(),
        "invalid_nodes"
    );
}

#[test]
fn store_update_rollback_recovery_and_same_version_replacement() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let store = f.store();
    let candidate = f.root_dir.join("candidate.json");

    // Install v1 then v2
    fs::write(&candidate, f.raw(1, None)).unwrap();
    assert_eq!(
        store
            .install_update(&candidate, f.name_refs())
            .unwrap()
            .version(),
        1
    );
    fs::write(&candidate, f.raw(2, None)).unwrap();
    assert_eq!(
        store
            .install_update(&candidate, f.name_refs())
            .unwrap()
            .version(),
        2
    );

    // Rollback (v1) and replay (v2) are rejected with stale_version
    for ver in [1, 2] {
        fs::write(&candidate, f.raw(ver, None)).unwrap();
        assert_eq!(
            store
                .install_update(&candidate, f.name_refs())
                .unwrap_err()
                .code(),
            "stale_version"
        );
    }

    // Overwrite live file with old v1 -> load() recovers v2 from backup automatically
    fs::write(&store.registry_path, f.raw(1, None)).unwrap();
    let recovered = store.load(f.name_refs()).unwrap();
    assert!(recovered.recovered());
    assert_eq!(recovered.version(), 2);
    assert_eq!(fs::read(&store.registry_path).unwrap(), f.raw(2, None));

    // Same-version replacement with different signed payload -> fail closed
    let mut alt_nodes = f.nodes.clone();
    alt_nodes.get_mut("A").unwrap().revoked = true;
    let replaced = f.raw(2, Some(&alt_nodes));
    fs::write(&store.registry_path, &replaced).unwrap();
    fs::write(&store.backup_path, &replaced).unwrap();
    assert_eq!(
        store.load(f.name_refs()).unwrap_err().code(),
        "same_version_replacement"
    );
}

#[test]
fn interrupted_state_commit_restores_previous_version() {
    let f = Fixture::new(&["A", "B", "X1", "X2"]);
    let store = f.store();
    let candidate = f.root_dir.join("candidate.json");

    fs::write(&candidate, f.raw(1, None)).unwrap();
    store.install_update(&candidate, f.name_refs()).unwrap();

    fs::write(&candidate, f.raw(2, None)).unwrap();
    let state_path = store.state_path.clone();
    let err = store
        .install_update_with_writer(&candidate, f.name_refs(), |path, bytes| {
            if path == state_path {
                return Err(TrustRegistryError::new(
                    "io_error",
                    "injected state commit failure",
                ));
            }
            atomic_write(path, bytes)
        })
        .unwrap_err();
    assert_eq!(err.code(), "io_error");

    // Next load must transparently recover v1 from last-valid backup
    let recovered = store.load(f.name_refs()).unwrap();
    assert!(recovered.recovered());
    assert_eq!(recovered.version(), 1);
}

#[test]
fn environment_loader_rejects_unsigned_and_missing_configuration() {
    let err = load_verified_registry_from_env_map(["A", "B"], |_| None).unwrap_err();
    assert_eq!(err.code(), "missing_trust_configuration");

    let err = load_verified_registry_from_env_map(["A", "B"], |k| {
        if k == "IKE_CASCADE_PUBLIC_KEYS_JSON" {
            Some("{}".to_owned())
        } else {
            None
        }
    })
    .unwrap_err();
    assert_eq!(err.code(), "unsigned_registry_rejected");

    let err = load_verified_registry_from_env_map(["A", "B"], |k| {
        if k == "IKE_CASCADE_PUBLIC_KEYS_FILE" {
            Some("/tmp/keys.json".to_owned())
        } else {
            None
        }
    })
    .unwrap_err();
    assert_eq!(err.code(), "unsigned_registry_rejected");
}

#[test]
fn offline_admin_keygen_and_sign_registry_roundtrip() {
    let dir = TempDir::new().unwrap();
    let a_dir = dir.path().join("node-A");
    let b_dir = dir.path().join("node-B");

    let a_sum = generate_node_identity("A", &a_dir, true).unwrap();
    let b_sum = generate_node_identity("B", &b_dir, true).unwrap();
    assert!(a_sum.generated && b_sum.generated);

    // Refuses to overwrite existing identity directory
    assert_eq!(
        generate_node_identity("A", &a_dir, true)
            .unwrap_err()
            .code(),
        "io_error"
    );

    // Create issuer key + trust root
    let issuer_sk = Ed25519SecretKey::generate();
    let issuer_path = dir.path().join("issuer.key");
    fs::write(
        &issuer_path,
        format!("{}\n", &*issuer_sk.to_hex_zeroizing()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&issuer_path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut signers = BTreeMap::new();
    signers.insert("ops-root".to_owned(), issuer_sk.public_key());
    let root_path = dir.path().join("root.json");
    fs::write(&root_path, build_trust_root_bytes(&signers).unwrap()).unwrap();

    let out_reg = dir.path().join("registry-v2.json");
    let a_entry = a_dir.join("public-entry.json");
    let b_entry = b_dir.join("public-entry.json");
    let summary = sign_registry_files(
        &[a_entry.as_path(), b_entry.as_path()],
        &root_path,
        &issuer_path,
        "ops-root",
        1,
        &out_reg,
        true,
    )
    .unwrap();
    assert!(summary.signed);
    assert_eq!(summary.version, 1);
    assert_eq!(summary.nodes, vec!["A", "B"]);

    // Verify with TrustRegistryStore
    let store = TrustRegistryStore::new(
        &out_reg,
        &root_path,
        dir.path().join("state.json"),
        dir.path().join("backup.json"),
    );
    let verified = store.load(["A", "B"]).unwrap();
    assert_eq!(verified.version(), 1);
    assert_eq!(verified.nodes().len(), 2);
}
