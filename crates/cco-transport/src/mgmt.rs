#![forbid(unsafe_code)]
//! 4-step MGMT hop handshake and AES-256-GCM link framing (`node_daemon.py` wire compatible).

use cco_crypto::{
    Key256, X25519PublicKey, X25519SecretKey, aes256_gcm_decrypt, aes256_gcm_encrypt,
    decode_canonical_hex, decode_canonical_hex_vec, derive_mgmt_key, link_message_aad,
    mgmt_auth_aad, random_bytes,
};
use cco_proto::{
    MessageType, MgmtAuth, MgmtInit, MgmtInitResp, SecureEnvelope, T_MGMT_AUTH, T_MGMT_AUTH_RESP,
    T_MGMT_INIT, T_MGMT_INIT_RESP, jdump,
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

/// Encrypts a hop payload into a `SecureEnvelope` wire JSON frame (`node_daemon.py::link_send`).
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
        meta: meta.unwrap_or_else(|| Value::Object(Map::new())),
    };
    jdump(&env).map_err(|_| TransportError::Protocol("link_envelope_encode"))
}

/// Decrypts an incoming `SecureEnvelope` using the active [`MgmtSession`] (`node_daemon.py::link_decrypt`).
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
    let nonce = decode_canonical_hex::<12>(&env.nonce)
        .map_err(|_| TransportError::Protocol("invalid_link_nonce"))?;
    let ct = decode_canonical_hex_vec(&env.ct, 65_535)
        .map_err(|_| TransportError::Protocol("invalid_link_ct"))?;
    let aad = link_message_aad(&env.t, &env.from, self_name, &session.sid);
    aes256_gcm_decrypt(&session.key, &nonce, &ct, &aad)
        .map_err(|_| TransportError::Protocol("link_decrypt_failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let wire =
            encrypt_link_envelope(&sess_a, "A", MessageType::MccStart, b"hello-hop", None).unwrap();
        let env: SecureEnvelope = serde_json::from_slice(&wire).unwrap();
        let pt = decrypt_link_envelope(&sess_x1, "X1", &env).unwrap();
        assert_eq!(pt, b"hello-hop");
    }
}
