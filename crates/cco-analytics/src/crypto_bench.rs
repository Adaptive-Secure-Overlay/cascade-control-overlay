#![forbid(unsafe_code)]
//! Cryptographic microbenchmark comparing X25519 + HKDF-SHA256 + AES-128-GCM / AES-256-GCM
//! against RSA-3072 OAEP-SHA256 and Ed25519 sign/verify (reproducing Section 4.3.1 / Table 4.6).

use std::time::Instant;

use cco_crypto::{
    Ed25519SecretKey, X25519SecretKey, aes128_gcm_decrypt, aes128_gcm_encrypt, aes256_gcm_decrypt,
    aes256_gcm_encrypt, hkdf_sha256_key128, hkdf_sha256_key256,
};
use rand::rngs::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Summary latency statistics for one cryptographic operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpTiming {
    pub name: String,
    pub iterations: usize,
    pub median_us: f64,
    pub p95_us: f64,
    pub mean_us: f64,
    pub ops_per_sec: f64,
}

/// Complete comparison benchmark output (`cco bench crypto`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptoBenchReport {
    pub payload_bytes: usize,
    pub x25519_hkdf_aes128_seal_open: OpTiming,
    pub x25519_hkdf_aes256_seal_open: OpTiming,
    pub ed25519_sign_verify: OpTiming,
    pub rsa3072_oaep_encrypt_decrypt: Option<OpTiming>,
    pub speedup_x25519_vs_rsa3072: Option<f64>,
}

fn measure<F: FnMut()>(name: &str, iterations: usize, warmup: usize, mut f: F) -> OpTiming {
    for _ in 0..warmup {
        f();
    }
    let mut samples_us = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let t0 = Instant::now();
        f();
        samples_us.push(t0.elapsed().as_secs_f64() * 1_000_000.0);
    }
    samples_us.sort_by(|a, b| a.total_cmp(b));
    let mean_us = samples_us.iter().sum::<f64>() / (samples_us.len().max(1) as f64);
    let median_us = samples_us[samples_us.len() / 2];
    let p95_idx = (95 * samples_us.len())
        .div_ceil(100)
        .saturating_sub(1)
        .min(samples_us.len() - 1);
    let p95_us = samples_us[p95_idx];
    let ops_per_sec = if mean_us > 0.0 {
        1_000_000.0 / mean_us
    } else {
        0.0
    };
    OpTiming {
        name: name.to_owned(),
        iterations,
        median_us,
        p95_us,
        mean_us,
        ops_per_sec,
    }
}

/// Runs the Section 4.3.1 cryptographic comparison benchmark.
///
/// Set `include_rsa3072 = true` for the full Table 4.6 comparison (key generation for RSA-3072
/// takes ~0.5-2s in release mode); pass `false` for fast CI smoke runs.
#[must_use]
pub fn run_crypto_benchmark(
    x25519_iters: usize,
    rsa_iters: usize,
    payload_bytes: usize,
    include_rsa3072: bool,
) -> CryptoBenchReport {
    let payload = vec![0x42u8; payload_bytes];
    let aad = b"cco-bench-v1";
    let salt = b"bench-salt";
    let info = b"bench-info";

    let recipient_sk = X25519SecretKey::generate();
    let recipient_pk = recipient_sk.public_key();

    let x25519_aes128 = measure(
        "X25519 + HKDF-SHA256 + AES-128-GCM (seal + open)",
        x25519_iters.max(1),
        5,
        || {
            let eph = X25519SecretKey::generate();
            let epk = eph.public_key();
            let shared_s = eph.diffie_hellman(&recipient_pk).unwrap();
            let k_s = hkdf_sha256_key128(shared_s.as_bytes(), salt, info).unwrap();
            let (nonce, ct) = aes128_gcm_encrypt(&k_s, &payload, aad).unwrap();

            let shared_r = recipient_sk.diffie_hellman(&epk).unwrap();
            let k_r = hkdf_sha256_key128(shared_r.as_bytes(), salt, info).unwrap();
            let pt = aes128_gcm_decrypt(&k_r, &nonce, &ct, aad).unwrap();
            debug_assert_eq!(pt.len(), payload.len());
        },
    );

    let x25519_aes256 = measure(
        "X25519 + HKDF-SHA256 + AES-256-GCM (seal + open)",
        x25519_iters.max(1),
        5,
        || {
            let eph = X25519SecretKey::generate();
            let epk = eph.public_key();
            let shared_s = eph.diffie_hellman(&recipient_pk).unwrap();
            let k_s = hkdf_sha256_key256(shared_s.as_bytes(), salt, info).unwrap();
            let (nonce, ct) = aes256_gcm_encrypt(&k_s, &payload, aad).unwrap();

            let shared_r = recipient_sk.diffie_hellman(&epk).unwrap();
            let k_r = hkdf_sha256_key256(shared_r.as_bytes(), salt, info).unwrap();
            let pt = aes256_gcm_decrypt(&k_r, &nonce, &ct, aad).unwrap();
            debug_assert_eq!(pt.len(), payload.len());
        },
    );

    let sign_sk = Ed25519SecretKey::generate();
    let sign_pk = sign_sk.public_key();
    let ed25519_timing = measure(
        "Ed25519 (sign + verify_strict)",
        x25519_iters.max(1),
        5,
        || {
            let sig = sign_sk.sign(&payload);
            sign_pk.verify_strict(&payload, &sig).unwrap();
        },
    );

    let rsa_timing = if include_rsa3072 {
        let mut rng = OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 3072).expect("RSA-3072 keygen");
        let pub_key = RsaPublicKey::from(&priv_key);
        // OAEP-SHA256 on 3072-bit modulus holds up to 318 bytes directly; encapsulate a 32-byte key + AES-128-GCM.
        let session_key_raw = [0x17u8; 16];
        Some(measure(
            "RSA-3072 OAEP-SHA256 + AES-128-GCM (seal + open)",
            rsa_iters.max(1),
            1,
            || {
                let mut r = OsRng;
                let enc_key = pub_key
                    .encrypt(&mut r, Oaep::new::<Sha256>(), &session_key_raw)
                    .unwrap();
                let k_s = cco_crypto::Key128::from_bytes(session_key_raw);
                let (nonce, ct) = aes128_gcm_encrypt(&k_s, &payload, aad).unwrap();

                let dec_key = priv_key.decrypt(Oaep::new::<Sha256>(), &enc_key).unwrap();
                let k_r = cco_crypto::Key128::from_slice(&dec_key).unwrap();
                let pt = aes128_gcm_decrypt(&k_r, &nonce, &ct, aad).unwrap();
                debug_assert_eq!(pt.len(), payload.len());
            },
        ))
    } else {
        None
    };

    let speedup = rsa_timing.as_ref().and_then(|r| {
        if x25519_aes128.median_us > 0.0 {
            Some(r.median_us / x25519_aes128.median_us)
        } else {
            None
        }
    });

    CryptoBenchReport {
        payload_bytes,
        x25519_hkdf_aes128_seal_open: x25519_aes128,
        x25519_hkdf_aes256_seal_open: x25519_aes256,
        ed25519_sign_verify: ed25519_timing,
        rsa3072_oaep_encrypt_decrypt: rsa_timing,
        speedup_x25519_vs_rsa3072: speedup,
    }
}
