#![forbid(unsafe_code)]
//! 4-step MGMT hop handshake and AES-256-GCM link framing (`node_daemon.py` wire compatible).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cco_crypto::{
    Key256, X25519PublicKey, X25519SecretKey, aes256_gcm_decrypt, aes256_gcm_encrypt,
    decode_canonical_hex, decode_canonical_hex_vec, derive_mgmt_key, link_message_aad,
    mgmt_auth_aad, random_bytes,
};
use cco_proto::{
    CompactHopAckFrame, CompactSecureFrame, MessageType, MgmtAuth, MgmtInit, MgmtInitResp,
    SecureEnvelope, T_MGMT_AUTH, T_MGMT_AUTH_RESP, T_MGMT_INIT, T_MGMT_INIT_RESP, jdump,
};
use serde_json::{Map, Value};

use crate::error::TransportError;

/// Established symmetric hop management session between two adjacent overlay peers.
pub struct MgmtSession {
    pub peer: String,
    pub sid: String,
    pub key: Key256,
}

/// Responder-side state between `MGMT_INIT` and `MGMT_AUTH`.
pub struct PendingResponderHandshake {
    pub peer: String,
    pub r_priv: X25519SecretKey,
    pub ni: [u8; 16],
    pub nr: [u8; 16],
    pub i_pub: X25519PublicKey,
    pub label: String,
}

/// Initiator-side state between sending `MGMT_INIT` and finishing `MGMT_AUTH_RESP`.
pub struct InitiatorHandshake {
    pub sid: String,
    pub peer: String,
    pub label: String,
    pub i_priv: X25519SecretKey,
    pub ni: [u8; 16],
}

impl InitiatorHandshake {
    /// Generates step 1 (`MGMT_INIT`) wire bytes and initiator state.
    pub fn start(self_name: &str, peer: &str) -> Result<(Self, Vec<u8>), TransportError> {
        let sid = hex::encode(random_bytes::<8>());
        let i_priv = X25519SecretKey::generate();
        let i_pub = i_priv.public_key();
        let ni = random_bytes::<16>();
        let label = format!("{self_name}-{peer}");

        let msg = MgmtInit {
            t: T_MGMT_INIT.to_owned(),
            sid: sid.clone(),
            from: self_name.to_owned(),
            to: peer.to_owned(),
            ni: hex::encode(ni),
            ke: i_pub.to_hex(),
        };
        let wire = jdump(&msg).map_err(|_| TransportError::Protocol("mgmt_init_encode"))?;
        Ok((
            Self {
                sid,
                peer: peer.to_owned(),
                label,
                i_priv,
                ni,
            },
            wire,
        ))
    }

    /// Processes step 2 (`MGMT_INIT_RESP`), derives `KD`, and builds step 3 (`MGMT_AUTH`).
    pub fn process_init_resp(
        &self,
        self_name: &str,
        resp: &MgmtInitResp,
    ) -> Result<(Key256, Vec<u8>), TransportError> {
        if resp.t != T_MGMT_INIT_RESP
            || resp.sid != self.sid
            || resp.from != self.peer
            || resp.to != self_name
        {
            return Err(TransportError::MgmtHandshakeFailed);
        }
        let nr = decode_canonical_hex::<16>(&resp.nr)
            .map_err(|_| TransportError::MgmtHandshakeFailed)?;
        let r_pub =
            X25519PublicKey::from_hex(&resp.ke).map_err(|_| TransportError::MgmtHandshakeFailed)?;
        let shared = self
            .i_priv
            .diffie_hellman(&r_pub)
            .map_err(|_| TransportError::MgmtHandshakeFailed)?;
        let kd = derive_mgmt_key(&shared, &self.ni, &nr, &self.label)
            .map_err(|_| TransportError::MgmtHandshakeFailed)?;

        let aad = mgmt_auth_aad(&self.label, self_name, &self.peer, &self.sid);
        let mut auth_plain = format!("ID={self_name}|AUTH=").into_bytes();
        auth_plain.extend_from_slice(&random_bytes::<16>());
        let (nonce, ct) = aes256_gcm_encrypt(&kd, &auth_plain, &aad)
            .map_err(|_| TransportError::MgmtHandshakeFailed)?;

        let auth_msg = MgmtAuth {
            t: T_MGMT_AUTH.to_owned(),
            sid: self.sid.clone(),
            from: self_name.to_owned(),
            to: self.peer.clone(),
            nonce: hex::encode(nonce),
            ct: hex::encode(ct),
        };
        let wire = jdump(&auth_msg).map_err(|_| TransportError::Protocol("mgmt_auth_encode"))?;
        Ok((kd, wire))
    }

    /// Verifies step 4 (`MGMT_AUTH_RESP`) and promotes `KD` to an active [`MgmtSession`].
    pub fn finish_auth_resp(
        self,
        self_name: &str,
        kd: Key256,
        resp2: &MgmtAuth,
    ) -> Result<MgmtSession, TransportError> {
        if resp2.t != T_MGMT_AUTH_RESP
            || resp2.sid != self.sid
            || resp2.from != self.peer
            || resp2.to != self_name
        {
            return Err(TransportError::MgmtHandshakeFailed);
        }
        let nonce = decode_canonical_hex::<12>(&resp2.nonce)
            .map_err(|_| TransportError::MgmtHandshakeFailed)?;
        let ct = decode_canonical_hex_vec(&resp2.ct, 4096)
            .map_err(|_| TransportError::MgmtHandshakeFailed)?;
        let aad2 = mgmt_auth_aad(&self.label, &self.peer, self_name, &self.sid);
        let _ = aes256_gcm_decrypt(&kd, &nonce, &ct, &aad2)
            .map_err(|_| TransportError::MgmtHandshakeFailed)?;

        Ok(MgmtSession {
            peer: self.peer,
            sid: self.sid,
            key: kd,
        })
    }
}

/// Handles incoming step 1 (`MGMT_INIT`) on the responder side, returning `(Pending, MGMT_INIT_RESP)`.
pub fn responder_handle_init(
    self_name: &str,
    peer: &str,
    init: &MgmtInit,
) -> Result<(PendingResponderHandshake, Vec<u8>), TransportError> {
    if init.t != T_MGMT_INIT || init.from != peer || init.to != self_name || init.sid.is_empty() {
        return Err(TransportError::MgmtHandshakeFailed);
    }
    let ni =
        decode_canonical_hex::<16>(&init.ni).map_err(|_| TransportError::MgmtHandshakeFailed)?;
    let i_pub =
        X25519PublicKey::from_hex(&init.ke).map_err(|_| TransportError::MgmtHandshakeFailed)?;

    let r_priv = X25519SecretKey::generate();
    let r_pub = r_priv.public_key();
    let nr = random_bytes::<16>();
    let label = format!("{peer}-{self_name}");

    let resp = MgmtInitResp {
        t: T_MGMT_INIT_RESP.to_owned(),
        sid: init.sid.clone(),
        from: self_name.to_owned(),
        to: peer.to_owned(),
        nr: hex::encode(nr),
        ke: r_pub.to_hex(),
    };
    let wire = jdump(&resp).map_err(|_| TransportError::Protocol("mgmt_init_resp_encode"))?;
    Ok((
        PendingResponderHandshake {
            peer: peer.to_owned(),
            r_priv,
            ni,
            nr,
            i_pub,
            label,
        },
        wire,
    ))
}

/// Handles incoming step 3 (`MGMT_AUTH`) on the responder side, returning `(MgmtSession, MGMT_AUTH_RESP)`.
pub fn responder_handle_auth(
    self_name: &str,
    peer: &str,
    pending: PendingResponderHandshake,
    auth: &MgmtAuth,
) -> Result<(MgmtSession, Vec<u8>), TransportError> {
    if auth.t != T_MGMT_AUTH || auth.from != peer || auth.to != self_name || pending.peer != peer {
        return Err(TransportError::MgmtHandshakeFailed);
    }
    let shared = pending
        .r_priv
        .diffie_hellman(&pending.i_pub)
        .map_err(|_| TransportError::MgmtHandshakeFailed)?;
    let kd = derive_mgmt_key(&shared, &pending.ni, &pending.nr, &pending.label)
        .map_err(|_| TransportError::MgmtHandshakeFailed)?;

    let nonce =
        decode_canonical_hex::<12>(&auth.nonce).map_err(|_| TransportError::MgmtHandshakeFailed)?;
    let ct = decode_canonical_hex_vec(&auth.ct, 4096)
        .map_err(|_| TransportError::MgmtHandshakeFailed)?;
    let aad = mgmt_auth_aad(&pending.label, peer, self_name, &auth.sid);
    let _ = aes256_gcm_decrypt(&kd, &nonce, &ct, &aad)
        .map_err(|_| TransportError::MgmtHandshakeFailed)?;

    let aad2 = mgmt_auth_aad(&pending.label, self_name, peer, &auth.sid);
    let mut auth_plain = format!("ID={self_name}|AUTH=").into_bytes();
    auth_plain.extend_from_slice(&random_bytes::<16>());
    let (n2, c2) = aes256_gcm_encrypt(&kd, &auth_plain, &aad2)
        .map_err(|_| TransportError::MgmtHandshakeFailed)?;

    let resp = MgmtAuth {
        t: T_MGMT_AUTH_RESP.to_owned(),
        sid: auth.sid.clone(),
        from: self_name.to_owned(),
        to: peer.to_owned(),
        nonce: hex::encode(n2),
        ct: hex::encode(c2),
    };
    let wire = jdump(&resp).map_err(|_| TransportError::Protocol("mgmt_auth_resp_encode"))?;
    Ok((
        MgmtSession {
            peer: peer.to_owned(),
            sid: auth.sid.clone(),
            key: kd,
        },
        wire,
    ))
}

/// Encrypts a hop payload into a Python-compatible hex `SecureEnvelope` JSON frame (`node_daemon.py::link_send`).
pub fn encrypt_link_envelope(
    session: &MgmtSession,
    self_name: &str,
    mtype: MessageType,
    payload: &[u8],
    meta: Option<Value>,
) -> Result<Vec<u8>, TransportError> {
    let aad = link_message_aad(mtype.as_str(), self_name, &session.peer, &session.sid);
    let (nonce, ct) = aes256_gcm_encrypt(&session.key, payload, &aad)
        .map_err(|_| TransportError::Protocol("link_encrypt_failed"))?;
    let env = SecureEnvelope {
        t: mtype.as_str().to_owned(),
        sid: session.sid.clone(),
        from: self_name.to_owned(),
        to: session.peer.clone(),
        nonce: hex::encode(nonce),
        ct: hex::encode(ct),
        enc: None,
        meta: meta.unwrap_or_else(|| Value::Object(Map::new())),
    };
    jdump(&env).map_err(|_| TransportError::Protocol("link_envelope_encode"))
}

/// Encrypts a hop payload into a compact base64 JSON `SecureEnvelope` (`enc = "b64"`).
pub fn encrypt_link_envelope_b64(
    session: &MgmtSession,
    self_name: &str,
    mtype: MessageType,
    payload: &[u8],
    meta: Option<Value>,
) -> Result<Vec<u8>, TransportError> {
    let aad = link_message_aad(mtype.as_str(), self_name, &session.peer, &session.sid);
    let (nonce, ct) = aes256_gcm_encrypt(&session.key, payload, &aad)
        .map_err(|_| TransportError::Protocol("link_encrypt_failed"))?;
    let env = SecureEnvelope {
        t: mtype.as_str().to_owned(),
        sid: session.sid.clone(),
        from: self_name.to_owned(),
        to: session.peer.clone(),
        nonce: B64.encode(nonce),
        ct: B64.encode(ct),
        enc: Some("b64".to_owned()),
        meta: meta.unwrap_or_else(|| Value::Object(Map::new())),
    };
    jdump(&env).map_err(|_| TransportError::Protocol("link_envelope_encode"))
}

/// Decrypts an incoming JSON `SecureEnvelope` (supporting both legacy Python `hex` and compact `b64`).
pub fn decrypt_link_envelope(
    session: &MgmtSession,
    self_name: &str,
    env: &SecureEnvelope,
) -> Result<Vec<u8>, TransportError> {
    if env.from != session.peer || env.to != self_name {
        return Err(TransportError::Protocol("link_endpoint_mismatch"));
    }
    if !env.sid.is_empty() && env.sid != session.sid {
        return Err(TransportError::Protocol("stale_session_id"));
    }
    let (nonce, ct) = match env.enc.as_deref() {
        None | Some("hex") => {
            let nonce = decode_canonical_hex::<12>(&env.nonce)
                .map_err(|_| TransportError::Protocol("invalid_link_nonce"))?;
            let ct = decode_canonical_hex_vec(&env.ct, 65_535)
                .map_err(|_| TransportError::Protocol("invalid_link_ct"))?;
            (nonce, ct)
        }
        Some("b64") => {
            let nonce_vec = B64
                .decode(env.nonce.as_bytes())
                .map_err(|_| TransportError::Protocol("invalid_link_nonce"))?;
            let nonce: [u8; 12] = nonce_vec
                .try_into()
                .map_err(|_| TransportError::Protocol("invalid_link_nonce"))?;
            let ct = B64
                .decode(env.ct.as_bytes())
                .map_err(|_| TransportError::Protocol("invalid_link_ct"))?;
            if ct.len() > 65_535 {
                return Err(TransportError::Protocol("invalid_link_ct"));
            }
            (nonce, ct)
        }
        Some(_) => return Err(TransportError::Protocol("unsupported_link_encoding")),
    };
    let aad = link_message_aad(&env.t, &env.from, self_name, &session.sid);
    aes256_gcm_decrypt(&session.key, &nonce, &ct, &aad)
        .map_err(|_| TransportError::Protocol("link_decrypt_failed"))
}

fn compact_link_aad(
    mtype: MessageType,
    from: &str,
    to: &str,
    sid: &str,
    ack_id: &[u8; 8],
) -> Vec<u8> {
    format!(
        "CCO1:{}:{from}->{to}:{sid}:{}",
        mtype.as_str(),
        hex::encode(ack_id)
    )
    .into_bytes()
}

fn compact_hop_ack_aad(from: &str, to: &str, sid: &str) -> Vec<u8> {
    format!("CCO1_ACK:{from}->{to}:{sid}").into_bytes()
}

/// Encrypts a hop payload into a compact binary `CCO1` frame (`3,584 B` cascade -> `~3,651 B`, 4 UDP frags).
pub fn encrypt_compact_link_frame(
    session: &MgmtSession,
    self_name: &str,
    mtype: MessageType,
    payload: &[u8],
    ack_id: [u8; 8],
) -> Result<Vec<u8>, TransportError> {
    let aad = compact_link_aad(mtype, self_name, &session.peer, &session.sid, &ack_id);
    let (nonce, ct) = aes256_gcm_encrypt(&session.key, payload, &aad)
        .map_err(|_| TransportError::Protocol("link_encrypt_failed"))?;
    let frame = CompactSecureFrame {
        message_type: mtype,
        from: self_name.to_owned(),
        to: session.peer.clone(),
        sid: session.sid.clone(),
        ack_id,
        nonce,
        ct,
    };
    frame
        .encode()
        .map_err(|_| TransportError::Protocol("compact_envelope_encode"))
}

/// Decrypts an incoming `CCO1` compact encrypted hop envelope using `session`.
pub fn decrypt_compact_link_frame(
    session: &MgmtSession,
    self_name: &str,
    frame: &CompactSecureFrame,
) -> Result<Vec<u8>, TransportError> {
    if frame.from != session.peer || frame.to != self_name {
        return Err(TransportError::Protocol("link_endpoint_mismatch"));
    }
    if frame.sid != session.sid {
        return Err(TransportError::Protocol("stale_session_id"));
    }
    let aad = compact_link_aad(
        frame.message_type,
        &frame.from,
        self_name,
        &session.sid,
        &frame.ack_id,
    );
    aes256_gcm_decrypt(&session.key, &frame.nonce, &frame.ct, &aad)
        .map_err(|_| TransportError::Protocol("link_decrypt_failed"))
}

/// Builds an AEAD-authenticated compact hop-by-hop ACK for `ack_id` (~64 B single UDP datagram).
pub fn encrypt_compact_hop_ack(
    session: &MgmtSession,
    self_name: &str,
    ack_id: [u8; 8],
) -> Result<Vec<u8>, TransportError> {
    let aad = compact_hop_ack_aad(self_name, &session.peer, &session.sid);
    let (nonce, ct_vec) = aes256_gcm_encrypt(&session.key, &ack_id, &aad)
        .map_err(|_| TransportError::Protocol("hop_ack_encrypt_failed"))?;
    let ct: [u8; 24] = ct_vec
        .try_into()
        .map_err(|_| TransportError::Protocol("hop_ack_encrypt_failed"))?;
    let frame = CompactHopAckFrame {
        from: self_name.to_owned(),
        to: session.peer.clone(),
        sid: session.sid.clone(),
        nonce,
        ct,
    };
    frame
        .encode()
        .map_err(|_| TransportError::Protocol("hop_ack_encode"))
}

/// Verifies and decrypts an incoming AEAD-authenticated compact hop-by-hop ACK.
pub fn decrypt_compact_hop_ack(
    session: &MgmtSession,
    self_name: &str,
    frame: &CompactHopAckFrame,
) -> Result<[u8; 8], TransportError> {
    if frame.from != session.peer || frame.to != self_name {
        return Err(TransportError::Protocol("link_endpoint_mismatch"));
    }
    if frame.sid != session.sid {
        return Err(TransportError::Protocol("stale_session_id"));
    }
    let aad = compact_hop_ack_aad(&frame.from, self_name, &session.sid);
    let pt = aes256_gcm_decrypt(&session.key, &frame.nonce, &frame.ct, &aad)
        .map_err(|_| TransportError::Protocol("hop_ack_decrypt_failed"))?;
    pt.try_into()
        .map_err(|_| TransportError::Protocol("hop_ack_decrypt_failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cco_proto::{CompactFrame, decode_compact_frame, fragment_compact_payload};

    #[test]
    fn four_step_mgmt_handshake_and_link_aead_roundtrip() {
        let (init_hs, init_wire) = InitiatorHandshake::start("A", "X1").unwrap();
        let init_msg: MgmtInit = serde_json::from_slice(&init_wire).unwrap();

        let (pending, resp_wire) = responder_handle_init("X1", "A", &init_msg).unwrap();
        let resp_msg: MgmtInitResp = serde_json::from_slice(&resp_wire).unwrap();

        let (kd_a, auth_wire) = init_hs.process_init_resp("A", &resp_msg).unwrap();
        let auth_msg: MgmtAuth = serde_json::from_slice(&auth_wire).unwrap();

        let (sess_x1, auth_resp_wire) =
            responder_handle_auth("X1", "A", pending, &auth_msg).unwrap();
        let auth_resp_msg: MgmtAuth = serde_json::from_slice(&auth_resp_wire).unwrap();

        let sess_a = init_hs.finish_auth_resp("A", kd_a, &auth_resp_msg).unwrap();
        assert_eq!(sess_a.sid, sess_x1.sid);
        assert!(sess_a.key.ct_eq(&sess_x1.key));

        // 1. Legacy Python-compatible hex SecureEnvelope
        let wire =
            encrypt_link_envelope(&sess_a, "A", MessageType::MccStart, b"hello-hop", None).unwrap();
        let env: SecureEnvelope = serde_json::from_slice(&wire).unwrap();
        assert_eq!(env.enc, None);
        let pt = decrypt_link_envelope(&sess_x1, "X1", &env).unwrap();
        assert_eq!(pt, b"hello-hop");

        // 2. Compact JSON base64 SecureEnvelope (`enc = "b64"`)
        let wire_b64 =
            encrypt_link_envelope_b64(&sess_a, "A", MessageType::CascadeBuild, b"hello-b64", None)
                .unwrap();
        let env_b64: SecureEnvelope = serde_json::from_slice(&wire_b64).unwrap();
        assert_eq!(env_b64.enc.as_deref(), Some("b64"));
        assert_eq!(
            decrypt_link_envelope(&sess_x1, "X1", &env_b64).unwrap(),
            b"hello-b64"
        );

        // 3. Compact binary CCO1 frame (3,584 B cascade -> 4 UDP fragments!) + authenticated hop ACK
        let padded = vec![b'P'; 3584];
        let ack_id = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        let cwire =
            encrypt_compact_link_frame(&sess_a, "A", MessageType::CascadeBuild, &padded, ack_id)
                .unwrap();
        let cfrags = fragment_compact_payload("A", "X1", &cwire).unwrap();
        assert_eq!(cfrags.len(), 4);
        let CompactFrame::Secure(mut decoded) = decode_compact_frame(&cwire).unwrap() else {
            panic!("expected compact secure frame");
        };
        assert_eq!(
            decrypt_compact_link_frame(&sess_x1, "X1", &decoded).unwrap(),
            padded
        );
        // Tampering ack_id breaks AEAD AAD!
        decoded.ack_id[0] ^= 0xff;
        assert!(decrypt_compact_link_frame(&sess_x1, "X1", &decoded).is_err());

        // Hop ACK roundtrip + tamper rejection
        let ack_wire = encrypt_compact_hop_ack(&sess_x1, "X1", ack_id).unwrap();
        let CompactFrame::HopAck(mut ack_frame) = decode_compact_frame(&ack_wire).unwrap() else {
            panic!("expected compact hop ack");
        };
        assert_eq!(
            decrypt_compact_hop_ack(&sess_a, "A", &ack_frame).unwrap(),
            ack_id
        );
        ack_frame.ct[0] ^= 0x01;
        assert!(decrypt_compact_hop_ack(&sess_a, "A", &ack_frame).is_err());
    }
}
