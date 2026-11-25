#![forbid(unsafe_code)]
//! Cryptographic foundation for Cascade Control Overlay.
//!
//! Built exclusively on audited RustCrypto / dalek crates:
//! - `x25519-dalek` (X25519 key agreement with contributory validation)
//! - `ed25519-dalek` (Ed25519 signing and `verify_strict`)
//! - `hkdf` + `sha2` (HKDF-SHA256, SHA-256)
//! - `aes-gcm` (AES-256-GCM and AES-128-GCM)
//! - `zeroize` + `subtle` (automatic secret zeroization and constant-time equality)

pub mod aead;
pub mod contexts;
pub mod ed25519;
pub mod error;
pub mod kdf;
pub mod x25519;

pub use aead::{
    AES_GCM_TAG_LEN, Key128, Key256, Nonce12, aes128_gcm_decrypt, aes128_gcm_encrypt,
    aes128_gcm_encrypt_with_nonce, aes256_gcm_decrypt, aes256_gcm_encrypt,
    aes256_gcm_encrypt_with_nonce, random_bytes, random_nonce12,
};
pub use contexts::{
    MCC_A_B_FORWARD_INFO, MCC_CAPSULE_DOMAIN, MCC_CAPSULE_KDF_INFO_PREFIX,
    MCC_ENDPOINT_MESSAGE_DOMAIN, MGMT_KDF_INFO_PREFIX, MccCapsulePurpose, PRIV_A_X2_INFO,
    PRIV_B_A_INFO, PRIV_X1_B_INFO, UNIVERSAL_CASCADE_CAPSULE_AAD, UNIVERSAL_CASCADE_CAPSULE_INFO,
    UNIVERSAL_CASCADE_ROUTE_INFO, derive_mcc_capsule_key, derive_mcc_forward_key, derive_mgmt_key,
    derive_priv_a_x2_key, derive_priv_b_a_key, derive_priv_x1_b_key,
    derive_universal_cascade_capsule_key, derive_universal_cascade_route_key, link_message_aad,
    mcc_a_b_fwd_aad, mcc_capsule_aad, mgmt_auth_aad, mgmt_kdf_info, priv_b_a_aad, priv_x1_b_aad,
    universal_cascade_packet_aad, validate_context_token,
};
pub use ed25519::{Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature};
pub use error::CryptoError;
pub use kdf::{
    constant_time_eq, decode_canonical_hex, decode_canonical_hex_vec, hkdf_sha256_key128,
    hkdf_sha256_key256, hkdf_sha256_vec, sha256, sha256_hex,
};
pub use x25519::{X25519PublicKey, X25519SecretKey, X25519SharedSecret};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_key_agreement_and_low_order_rejection() {
        let alice = X25519SecretKey::generate();
        let bob = X25519SecretKey::generate();

        let shared_ab = alice.diffie_hellman(&bob.public_key()).unwrap();
        let shared_ba = bob.diffie_hellman(&alice.public_key()).unwrap();
        assert!(constant_time_eq(shared_ab.as_bytes(), shared_ba.as_bytes()));

        // All-zero public key is a low-order point and must fail closed.
        let low_order = X25519PublicKey::from_bytes([0u8; 32]);
        assert_eq!(
            alice.diffie_hellman(&low_order).unwrap_err(),
            CryptoError::KeyAgreementFailed
        );
    }

    #[test]
    fn ed25519_sign_and_strict_verify() {
        let sk = Ed25519SecretKey::generate();
        let pk = sk.public_key();
        let msg = b"canonical-trust-registry-body";
        let sig = sk.sign(msg);
        assert!(pk.verify_strict(msg, &sig).is_ok());

        let mut tampered_msg = msg.to_vec();
        tampered_msg[0] ^= 0x01;
        assert_eq!(
            pk.verify_strict(&tampered_msg, &sig).unwrap_err(),
            CryptoError::BadSignature
        );

        let mut tampered_sig = *sig.as_bytes();
        tampered_sig[63] ^= 0x80;
        assert_eq!(
            pk.verify_strict(msg, &Ed25519Signature::from_bytes(tampered_sig))
                .unwrap_err(),
            CryptoError::BadSignature
        );
        assert_eq!(pk.key_id(), sha256_hex(pk.as_bytes()));
    }

    #[test]
    fn aes256_and_aes128_gcm_roundtrip_and_aad_binding() {
        let key256 = Key256::generate();
        let (nonce, ct) = aes256_gcm_encrypt(&key256, b"hello-ikev2", b"aad-v1").unwrap();
        let pt = aes256_gcm_decrypt(&key256, &nonce, &ct, b"aad-v1").unwrap();
        assert_eq!(pt, b"hello-ikev2");
        assert_eq!(
            aes256_gcm_decrypt(&key256, &nonce, &ct, b"wrong-aad").unwrap_err(),
            CryptoError::AuthenticationFailed
        );

        let key128 = Key128::generate();
        let (nonce128, ct128) = aes128_gcm_encrypt(&key128, b"bench-payload", b"bench").unwrap();
        let pt128 = aes128_gcm_decrypt(&key128, &nonce128, &ct128, b"bench").unwrap();
        assert_eq!(pt128, b"bench-payload");
        assert_eq!(
            aes128_gcm_decrypt(&key128, &nonce128, &ct128[..8], b"bench").unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn secret_debug_representations_are_redacted() {
        let k256 = Key256::from_bytes([0xAB; 32]);
        let k128 = Key128::from_bytes([0xCD; 16]);
        let xsk = X25519SecretKey::from_bytes([0x11; 32]);
        let esk = Ed25519SecretKey::from_bytes([0x22; 32]);
        let shared = xsk
            .diffie_hellman(&X25519SecretKey::generate().public_key())
            .unwrap();

        assert_eq!(format!("{k256:?}"), "Key256([REDACTED])");
        assert_eq!(format!("{k128:?}"), "Key128([REDACTED])");
        assert_eq!(format!("{xsk:?}"), "X25519SecretKey([REDACTED])");
        assert_eq!(format!("{esk:?}"), "Ed25519SecretKey([REDACTED])");
        assert_eq!(format!("{shared:?}"), "X25519SharedSecret([REDACTED])");
    }

    #[test]
    fn canonical_hex_rejects_uppercase_and_whitespace() {
        let lower = "ab".repeat(32);
        let upper = "AB".repeat(32);
        assert!(decode_canonical_hex::<32>(&lower).is_ok());
        assert_eq!(
            decode_canonical_hex::<32>(&upper).unwrap_err(),
            CryptoError::InvalidHex
        );
        assert_eq!(
            decode_canonical_hex::<32>(&format!(" {lower}")).unwrap_err(),
            CryptoError::InvalidHex
        );
    }

    #[test]
    fn mcc_capsule_aad_matches_canonical_json() {
        let aad = mcc_capsule_aad("ctx-01", MccCapsulePurpose::Endpoint).unwrap();
        assert_eq!(
            aad,
            br#"{"context":"ctx-01","domain":"mcc-recipient-capsule","purpose":"endpoint","version":1}"#
        );
        assert_eq!(
            mcc_capsule_aad("bad context!", MccCapsulePurpose::Hop).unwrap_err(),
            CryptoError::InvalidContext
        );
    }
}
