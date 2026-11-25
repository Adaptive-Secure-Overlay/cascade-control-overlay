#![forbid(unsafe_code)]
//! Wire protocol types, canonical JSON codecs, `LINK_FRAG` framing, and IKEv2/WireGuard parsers.

pub mod canonical;
pub mod error;
pub mod ikev2;
pub mod link_frag;
pub mod messages;
pub mod wireguard;

pub use canonical::{
    CanonicalValue, MAX_JSON_DEPTH, MAX_JSON_FIELDS, MAX_JSON_ITEMS, MAX_JSON_KEY_LEN,
    canonical_bytes_from_value, canonical_object_bytes, jdump, jdump_value, jload,
    parse_strict_json_object,
};
pub use error::ProtoError;
pub use ikev2::{
    CREATE_CHILD_SA, IKE_AUTH, IKE_SA_INIT, IKEV2_FLAG_INITIATOR, IKEV2_FLAG_RESPONSE,
    IKEV2_HEADER_LEN, IKEV2_MAJOR_VERSION, INFORMATIONAL, IkeRequestKey, Ikev2Header,
    is_ike_payload, parse_ikev2_packet,
};
pub use link_frag::{
    LINK_FRAG_CHUNK_BYTES, LINK_FRAG_ID_HEX_LEN, LINK_FRAG_MAX_ASSEMBLED, LINK_FRAG_MAX_BUFFERS,
    LINK_FRAG_MAX_TOTAL, LINK_FRAG_MAX_WIRE, LINK_FRAG_TTL_SECS, LinkFragFrame,
    LinkFragReassembler, fragment_payload, fragment_payload_with_id,
};
pub use messages::*;
pub use wireguard::{
    WG_COOKIE_REPLY_LEN, WG_INITIATION_LEN, WG_RESPONSE_LEN, WG_TRANSPORT_MIN_LEN,
    WireGuardMessageType, WireGuardPacket, parse_wireguard_packet,
};

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn sample_ike_sa_init(udp_port: u16, response: bool) -> Vec<u8> {
        let mut hdr = vec![0u8; 40];
        hdr[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        hdr[16] = 33; // SA payload
        hdr[17] = 0x20; // IKEv2 2.0
        hdr[18] = IKE_SA_INIT;
        hdr[19] = if response {
            IKEV2_FLAG_RESPONSE
        } else {
            IKEV2_FLAG_INITIATOR
        };
        hdr[20..24].copy_from_slice(&0u32.to_be_bytes());
        let total_len = hdr.len() as u32;
        hdr[24..28].copy_from_slice(&total_len.to_be_bytes());

        if udp_port == 4500 {
            let mut out = vec![0u8; 4];
            out.extend_from_slice(&hdr);
            out
        } else {
            hdr
        }
    }

    #[test]
    fn message_type_roundtrip_all_variants() {
        let all = [
            T_MGMT_INIT,
            T_MGMT_INIT_RESP,
            T_MGMT_AUTH,
            T_MGMT_AUTH_RESP,
            T_I1,
            T_I2,
            T_OKX2,
            T_PROXY_BLOB,
            T_PRIV_FWD,
            T_PRIV_DELIVER,
            T_PRIV_BACK,
            T_PRIV_BKEY_REQ,
            T_PRIV_BKEY_RESP,
            T_PRIV_X1B_SEAL,
            T_PRIV_INLINE_START,
            T_PRIV_INLINE_X2,
            T_MCC_START,
            T_MCC_X2,
            T_MCC_OFFER,
            T_MCC_ACCEPT,
            T_MCC_OPAQUE_FWD,
            T_CASCADE_BUILD,
            T_CASCADE_REJECT,
            T_CASCADE_ABORT,
            T_CASCADE_PROBE,
            T_CASCADE_ACCEPT,
            T_CASCADE_DATA,
            T_CASCADE_BACK,
            T_CASCADE_CLOSE,
            T_LINK_FRAG,
            T_LOCAL_CONNECT,
            T_ERROR,
        ];
        for name in all {
            let parsed = MessageType::from_str(name).unwrap();
            assert_eq!(parsed.as_str(), name);
        }
        assert_eq!(
            MessageType::from_str("UNKNOWN_MSG").unwrap_err(),
            ProtoError::UnknownMessageType
        );
    }

    #[test]
    fn link_frag_split_reassemble_and_security_guards() {
        let big_msg = jdump(&serde_json::json!({
            "t": "MCC_START",
            "payload": "x".repeat(2500)
        }))
        .unwrap();
        assert!(big_msg.len() > LINK_FRAG_MAX_WIRE);

        let frames = fragment_payload("A", "X1", &big_msg).unwrap();
        assert!(frames.len() >= 4);
        assert!(frames.iter().all(|f| f.len() <= LINK_FRAG_MAX_WIRE));

        let mut rx = LinkFragReassembler::new("X1");
        let mut assembled = None;
        for (i, raw) in frames.iter().enumerate() {
            let frame: LinkFragFrame = serde_json::from_slice(raw).unwrap();
            let res = rx.ingest("A", &frame, 100.0 + i as f64).unwrap();
            if i + 1 < frames.len() {
                assert!(res.is_none());
            } else {
                assembled = res;
            }
        }
        assert_eq!(assembled.unwrap(), big_msg);
        assert_eq!(rx.active_buffers(), 0);

        // Nested LINK_FRAG must be rejected after reassembly
        let nested_inner = jdump(&serde_json::json!({
            "t": "LINK_FRAG",
            "pad": "z".repeat(1300)
        }))
        .unwrap();
        let nested_frames =
            fragment_payload_with_id("A", "X1", &nested_inner, "0123456789abcdef").unwrap();
        let mut err_seen = None;
        for raw in nested_frames {
            let frame: LinkFragFrame = serde_json::from_slice(&raw).unwrap();
            if let Err(e) = rx.ingest("A", &frame, 200.0) {
                err_seen = Some(e);
            }
        }
        assert_eq!(err_seen, Some(ProtoError::NestedLinkFrag));

        // Buffer limit (32 max active buffers)
        for i in 0..LINK_FRAG_MAX_BUFFERS {
            let f = LinkFragFrame {
                t: T_LINK_FRAG.to_owned(),
                from: "A".to_owned(),
                to: "X1".to_owned(),
                frag_id: format!("{i:016x}"),
                seq: 0,
                total: 2,
                data: "YQ==".to_owned(),
            };
            assert!(rx.ingest("A", &f, 300.0).unwrap().is_none());
        }
        let overflow = LinkFragFrame {
            t: T_LINK_FRAG.to_owned(),
            from: "A".to_owned(),
            to: "X1".to_owned(),
            frag_id: "ffffffffffffffff".to_owned(),
            seq: 0,
            total: 2,
            data: "YQ==".to_owned(),
        };
        assert_eq!(
            rx.ingest("A", &overflow, 300.0).unwrap_err(),
            ProtoError::InvalidFragment
        );
        // After TTL expires, old buffers are pruned and new fragment succeeds
        assert!(rx.ingest("A", &overflow, 320.0).unwrap().is_none());
    }

    #[test]
    fn ikev2_parser_udp500_udp4500_and_esp_rejection() {
        let req500 = sample_ike_sa_init(500, false);
        assert!(is_ike_payload(500, &req500));
        let h500 = parse_ikev2_packet(500, &req500).unwrap();
        assert!(!h500.has_non_esp_marker);
        assert!(h500.is_request());
        assert_eq!(h500.exchange_type, IKE_SA_INIT);

        let resp4500 = sample_ike_sa_init(4500, true);
        assert!(is_ike_payload(4500, &resp4500));
        let h4500 = parse_ikev2_packet(4500, &resp4500).unwrap();
        assert!(h4500.has_non_esp_marker);
        assert!(h4500.is_response());
        assert_eq!(h500.request_key(), h4500.request_key());

        // ESP-in-UDP on 4500 (non-zero SPI in first 4 bytes) must be rejected!
        let mut esp_udp = vec![0u8; 64];
        esp_udp[0..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(!is_ike_payload(4500, &esp_udp));
        assert_eq!(
            parse_ikev2_packet(4500, &esp_udp).unwrap_err(),
            ProtoError::NotIkePayload
        );

        // Wrong IKE version (v1) rejected
        let mut ikev1 = sample_ike_sa_init(500, false);
        ikev1[17] = 0x10;
        assert_eq!(
            parse_ikev2_packet(500, &ikev1).unwrap_err(),
            ProtoError::InvalidIkev2Header
        );

        // Truncated / length mismatch rejected
        let mut bad_len = sample_ike_sa_init(500, false);
        bad_len.pop();
        assert_eq!(
            parse_ikev2_packet(500, &bad_len).unwrap_err(),
            ProtoError::InvalidIkev2Header
        );
    }

    #[test]
    fn wireguard_parser_types_and_strict_framing() {
        let mut init = vec![0u8; WG_INITIATION_LEN];
        init[0] = 1;
        init[4..8].copy_from_slice(&42u32.to_le_bytes());
        let p1 = parse_wireguard_packet(&init).unwrap();
        assert!(p1.is_handshake_control());
        assert!(!p1.is_transport());
        assert_eq!(p1.sender_index, Some(42));
        assert_eq!(p1.receiver_index, None);

        let mut resp = vec![0u8; WG_RESPONSE_LEN];
        resp[0] = 2;
        resp[4..8].copy_from_slice(&7u32.to_le_bytes());
        resp[8..12].copy_from_slice(&42u32.to_le_bytes());
        let p2 = parse_wireguard_packet(&resp).unwrap();
        assert!(p2.is_handshake_control());
        assert_eq!(p2.sender_index, Some(7));
        assert_eq!(p2.receiver_index, Some(42));

        let mut cookie = vec![0u8; WG_COOKIE_REPLY_LEN];
        cookie[0] = 3;
        cookie[4..8].copy_from_slice(&99u32.to_le_bytes());
        let p3 = parse_wireguard_packet(&cookie).unwrap();
        assert!(p3.is_handshake_control());
        assert_eq!(p3.receiver_index, Some(99));

        let mut data = vec![0u8; 48];
        data[0] = 4;
        data[4..8].copy_from_slice(&99u32.to_le_bytes());
        let p4 = parse_wireguard_packet(&data).unwrap();
        assert!(p4.is_transport());
        assert!(!p4.is_handshake_control());

        // Non-zero reserved byte -> rejected
        let mut bad_res = init.clone();
        bad_res[2] = 1;
        assert_eq!(
            parse_wireguard_packet(&bad_res).unwrap_err(),
            ProtoError::InvalidWireGuardPacket
        );

        // Wrong size for type 1 -> rejected
        assert_eq!(
            parse_wireguard_packet(&init[..147]).unwrap_err(),
            ProtoError::InvalidWireGuardPacket
        );

        // Unaligned type 4 -> rejected
        let mut bad_data = vec![0u8; 33];
        bad_data[0] = 4;
        assert_eq!(
            parse_wireguard_packet(&bad_data).unwrap_err(),
            ProtoError::InvalidWireGuardPacket
        );
    }

    #[test]
    fn strict_json_rejects_duplicates_and_floats() {
        assert_eq!(
            parse_strict_json_object(br#"{"a":1,"a":2}"#, 1024).unwrap_err(),
            ProtoError::DuplicateJsonKey
        );
        assert_eq!(
            parse_strict_json_object(br#"{"a":1.5}"#, 1024).unwrap_err(),
            ProtoError::InvalidJsonType
        );
        let ok = parse_strict_json_object(br#"{"b":2,"a":1}"#, 1024).unwrap();
        assert_eq!(
            canonical_object_bytes(&ok, 1024).unwrap(),
            br#"{"a":1,"b":2}"#
        );
    }
}
