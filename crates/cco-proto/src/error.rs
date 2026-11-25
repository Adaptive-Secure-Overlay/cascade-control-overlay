#![forbid(unsafe_code)]
//! Error types for wire protocol decoding, fragmentation, and VPN header parsers.

use thiserror::Error;

/// Fail-closed protocol error with stable log-safe codes.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProtoError {
    /// Unknown wire message type string.
    #[error("unknown_message_type")]
    UnknownMessageType,

    /// Malformed or oversized JSON frame.
    #[error("invalid_json")]
    InvalidJson,

    /// Duplicate object key encountered in strict JSON decoding.
    #[error("duplicate_json_key")]
    DuplicateJsonKey,

    /// JSON exceeded configured depth, item, field, or byte limits.
    #[error("json_resource_limit")]
    JsonResourceLimit,

    /// Disallowed JSON type (such as float or non-finite constant in strict mode).
    #[error("invalid_json_type")]
    InvalidJsonType,

    /// Payload exceeds the bounded 65,507-byte UDP overlay transport limit.
    #[error("payload_too_large")]
    PayloadTooLarge,

    /// Invalid `LINK_FRAG` fragment identifier, bounds, or base64 encoding.
    #[error("invalid_fragment")]
    InvalidFragment,

    /// Nested `LINK_FRAG` frame rejected after reassembly.
    #[error("nested_link_frag")]
    NestedLinkFrag,

    /// Packet is not an IKEv2 control payload (e.g. ESP-in-UDP on port 4500).
    #[error("not_ike_payload")]
    NotIkePayload,

    /// Invalid IKEv2 header version, length, or UDP service port.
    #[error("invalid_ikev2_header")]
    InvalidIkev2Header,

    /// Invalid WireGuard framing (length, reserved bytes, or message type).
    #[error("invalid_wireguard_packet")]
    InvalidWireGuardPacket,
}

impl ProtoError {
    /// Stable log-safe reason code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownMessageType => "unknown_message_type",
            Self::InvalidJson => "invalid_json",
            Self::DuplicateJsonKey => "duplicate_json_key",
            Self::JsonResourceLimit => "json_resource_limit",
            Self::InvalidJsonType => "invalid_json_type",
            Self::PayloadTooLarge => "payload_too_large",
            Self::InvalidFragment => "invalid_fragment",
            Self::NestedLinkFrag => "nested_link_frag",
            Self::NotIkePayload => "not_ike_payload",
            Self::InvalidIkev2Header => "invalid_ikev2_header",
            Self::InvalidWireGuardPacket => "invalid_wireguard_packet",
        }
    }
}
