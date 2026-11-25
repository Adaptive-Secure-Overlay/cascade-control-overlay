#![forbid(unsafe_code)]
//! Domain-separated KDF info labels, AAD builders, and key derivation helpers.
//!
//! Every byte sequence in this module matches the Python reference implementation
//! (`crypto_util.py`, `node_daemon.py`, `mcc_e2e.py`, `mcc_privacy.py`, `universal_cascade.py`)
//! to guarantee wire-level cross-compatibility.

use crate::aead::Key256;
use crate::error::CryptoError;
use crate::kdf::hkdf_sha256_key256;
use crate::x25519::{X25519PublicKey, X25519SharedSecret};

/// HKDF info prefix for 4-step hop management sessions (`node_daemon.py`).
pub const MGMT_KDF_INFO_PREFIX: &[u8] = b"mgmt|ikev2-like|";

/// HKDF info for MCC forward continuation (`mcc_privacy.py`).
pub const MCC_A_B_FORWARD_INFO: &[u8] = b"mcc-a-b-forward-v1";

/// Domain label for Ed25519-signed MCC endpoint records (`mcc_e2e.py`).
pub const MCC_ENDPOINT_MESSAGE_DOMAIN: &str = "mcc-endpoint-message";

/// Domain label for X25519 MCC recipient capsules (`mcc_e2e.py`).
pub const MCC_CAPSULE_DOMAIN: &str = "mcc-recipient-capsule";

/// HKDF info prefix for X25519 MCC recipient capsules (`mcc_e2e.py`).
pub const MCC_CAPSULE_KDF_INFO_PREFIX: &[u8] = b"mcc-recipient-capsule/v1\x00";

/// HKDF info for legacy X1->B locator seal (`node_daemon.py`).
pub const PRIV_X1_B_INFO: &[u8] = b"priv-x1-b-v1";

/// HKDF info for reverse B->A privacy seal (`node_daemon.py` / `mcc_privacy.py`).
pub const PRIV_B_A_INFO: &[u8] = b"priv-b-a-v1";

/// HKDF info for A->X2 privacy seal (`node_daemon.py`).
pub const PRIV_A_X2_INFO: &[u8] = b"priv-a-x2-v1";

/// HKDF info for Universal H-hop Cascade endpoint capsule (`universal_cascade.py`).
pub const UNIVERSAL_CASCADE_CAPSULE_INFO: &[u8] = b"universal-cascade-endpoint-v1";

/// HKDF info for Universal H-hop Cascade route key (`universal_cascade.py`).
pub const UNIVERSAL_CASCADE_ROUTE_INFO: &[u8] = b"universal-cascade-route-v1";

/// Static AEAD AAD for Universal H-hop Cascade endpoint capsule (`universal_cascade.py`).
pub const UNIVERSAL_CASCADE_CAPSULE_AAD: &[u8] = b"universal-cascade-endpoint-capsule-v1";

/// Purpose of an MCC recipient capsule (`mcc_e2e.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MccCapsulePurpose {
    /// Intermediate hop capsule (e.g., X1 -> X2).
    Hop,
    /// Endpoint capsule (e.g., A -> B).
    Endpoint,
}

impl MccCapsulePurpose {
    /// Returns the wire string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hop => "hop",
            Self::Endpoint => "endpoint",
        }
    }
}

/// Validates an MCC identifier/context token (`[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}`).
pub fn validate_context_token(value: &str) -> Result<(), CryptoError> {
    if value.is_empty() || value.len() > 256 {
        return Err(CryptoError::InvalidContext);
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(CryptoError::InvalidContext);
    }
    if !bytes[1..]
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'@' | b'/' | b'-'))
    {
        return Err(CryptoError::InvalidContext);
    }
    Ok(())
}

/// Builds the HKDF info bytes for a 4-step MGMT handshake (`mgmt|ikev2-like|<label>`).
#[must_use]
pub fn mgmt_kdf_info(label: &str) -> Vec<u8> {
    let mut info = Vec::with_capacity(MGMT_KDF_INFO_PREFIX.len() + label.len());
    info.extend_from_slice(MGMT_KDF_INFO_PREFIX);
    info.extend_from_slice(label.as_bytes());
    info
}

/// Derives the 32-byte hop management session key `KD` (`node_daemon.py::mgmt_kdf`).
pub fn derive_mgmt_key(
    shared: &X25519SharedSecret,
    ni: &[u8],
    nr: &[u8],
    label: &str,
) -> Result<Key256, CryptoError> {
    let mut salt = Vec::with_capacity(ni.len() + nr.len());
    salt.extend_from_slice(ni);
    salt.extend_from_slice(nr);
    let info = mgmt_kdf_info(label);
    hkdf_sha256_key256(shared.as_bytes(), &salt, &info)
}

/// Builds AAD for `MGMT_AUTH` / `MGMT_AUTH_RESP`: `AUTH:<label>:<from>-><to>:<sid>`.
#[must_use]
pub fn mgmt_auth_aad(label: &str, from: &str, to: &str, sid: &str) -> Vec<u8> {
    format!("AUTH:{label}:{from}->{to}:{sid}").into_bytes()
}

/// Builds AAD for an encrypted hop message: `<mtype>:<from>-><to>:<sid>`.
#[must_use]
pub fn link_message_aad(msg_type: &str, from: &str, to: &str, sid: &str) -> Vec<u8> {
    format!("{msg_type}:{from}->{to}:{sid}").into_bytes()
}

/// Builds the canonical JSON AAD for an MCC recipient capsule (`mcc_e2e.py::_aad`).
///
/// Format: `{"context":"<context>","domain":"mcc-recipient-capsule","purpose":"<purpose>","version":1}`
pub fn mcc_capsule_aad(context: &str, purpose: MccCapsulePurpose) -> Result<Vec<u8>, CryptoError> {
    validate_context_token(context)?;
    // Token characters are strictly ASCII subset without quotes or backslashes,
    // so deterministic key-sorted canonical JSON needs no escaping.
    Ok(format!(
        r#"{{"context":"{}","domain":"{}","purpose":"{}","version":1}}"#,
        context,
        MCC_CAPSULE_DOMAIN,
        purpose.as_str()
    )
    .into_bytes())
}

/// Derives the 32-byte AEAD key for an MCC recipient capsule (`mcc_e2e.py::_capsule_key`).
pub fn derive_mcc_capsule_key(
    shared: &X25519SharedSecret,
    ephemeral_pub: &X25519PublicKey,
    recipient_pub: &X25519PublicKey,
    aad: &[u8],
) -> Result<Key256, CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pub.as_bytes());
    salt[32..].copy_from_slice(recipient_pub.as_bytes());

    let mut info = Vec::with_capacity(MCC_CAPSULE_KDF_INFO_PREFIX.len() + aad.len());
    info.extend_from_slice(MCC_CAPSULE_KDF_INFO_PREFIX);
    info.extend_from_slice(aad);

    hkdf_sha256_key256(shared.as_bytes(), &salt, &info)
}

/// Derives the 32-byte MCC opaque forward continuation key (`mcc_privacy.py::_opaque_forward_key`).
pub fn derive_mcc_forward_key(
    shared: &X25519SharedSecret,
    context: &str,
) -> Result<Key256, CryptoError> {
    hkdf_sha256_key256(shared.as_bytes(), context.as_bytes(), MCC_A_B_FORWARD_INFO)
}

/// Builds AAD for MCC opaque forward continuation: `mcc-a-b-fwd:<context>`.
#[must_use]
pub fn mcc_a_b_fwd_aad(context: &str) -> Vec<u8> {
    format!("mcc-a-b-fwd:{context}").into_bytes()
}

/// Derives the 32-byte reverse B->A privacy key (`node_daemon.py::_ab_key`).
pub fn derive_priv_b_a_key(
    shared: &X25519SharedSecret,
    context: &str,
) -> Result<Key256, CryptoError> {
    hkdf_sha256_key256(shared.as_bytes(), context.as_bytes(), PRIV_B_A_INFO)
}

/// Builds AAD for reverse B->A privacy seal: `priv-b-a:<context>`.
#[must_use]
pub fn priv_b_a_aad(context: &str) -> Vec<u8> {
    format!("priv-b-a:{context}").into_bytes()
}

/// Derives the 32-byte X1->B locator key (`node_daemon.py::_x1b_key`).
pub fn derive_priv_x1_b_key(
    shared: &X25519SharedSecret,
    conn_id: &str,
) -> Result<Key256, CryptoError> {
    hkdf_sha256_key256(shared.as_bytes(), conn_id.as_bytes(), PRIV_X1_B_INFO)
}

/// Builds AAD for X1->B locator seal: `priv-x1-b:<conn_id>`.
#[must_use]
pub fn priv_x1_b_aad(conn_id: &str) -> Vec<u8> {
    format!("priv-x1-b:{conn_id}").into_bytes()
}

/// Derives the 32-byte A->X2 privacy key (`node_daemon.py`).
pub fn derive_priv_a_x2_key(
    shared: &X25519SharedSecret,
    conn_id: &str,
) -> Result<Key256, CryptoError> {
    hkdf_sha256_key256(shared.as_bytes(), conn_id.as_bytes(), PRIV_A_X2_INFO)
}

/// Derives the 32-byte Universal H-hop Cascade endpoint capsule key (`universal_cascade.py`).
pub fn derive_universal_cascade_capsule_key(
    shared: &X25519SharedSecret,
    ephemeral_pub: &X25519PublicKey,
    recipient_pub: &X25519PublicKey,
) -> Result<Key256, CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pub.as_bytes());
    salt[32..].copy_from_slice(recipient_pub.as_bytes());
    hkdf_sha256_key256(shared.as_bytes(), &salt, UNIVERSAL_CASCADE_CAPSULE_INFO)
}

/// Derives the 32-byte Universal H-hop Cascade route key (`universal_cascade.py::route_key`).
pub fn derive_universal_cascade_route_key(
    shared: &X25519SharedSecret,
    route_tag_bytes: &[u8],
) -> Result<Key256, CryptoError> {
    hkdf_sha256_key256(
        shared.as_bytes(),
        route_tag_bytes,
        UNIVERSAL_CASCADE_ROUTE_INFO,
    )
}

/// Builds AAD for Universal H-hop Cascade data/back packets (`universal_cascade.py::_packet_aad`).
#[must_use]
pub fn universal_cascade_packet_aad(route_tag: &str, direction: &str, sequence: u64) -> Vec<u8> {
    format!("universal-cascade-data-v1:{route_tag}:{direction}:{sequence}").into_bytes()
}
