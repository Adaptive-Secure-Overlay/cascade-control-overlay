#![forbid(unsafe_code)]
//! Zero-panic WireGuard framing classifier (`wg_handshake_overlay/parser.py`).
//!
//! Strictly classifies public WireGuard UDP framing without touching encryption keys:
//! - Type 1 (`HandshakeInitiation`): exact size 148 bytes -> overlay control eligible.
//! - Type 2 (`HandshakeResponse`): exact size 92 bytes -> overlay control eligible.
//! - Type 3 (`CookieReply`): exact size 64 bytes -> overlay control eligible.
//! - Type 4 (`TransportData`): `>= 32` bytes and multiple of 16 -> NEVER admitted into overlay!

use crate::error::ProtoError;

/// Exact byte length of WireGuard Type 1 Handshake Initiation.
pub const WG_INITIATION_LEN: usize = 148;

/// Exact byte length of WireGuard Type 2 Handshake Response.
pub const WG_RESPONSE_LEN: usize = 92;

/// Exact byte length of WireGuard Type 3 Cookie Reply.
pub const WG_COOKIE_REPLY_LEN: usize = 64;

/// Minimum byte length of WireGuard Type 4 Transport Data.
pub const WG_TRANSPORT_MIN_LEN: usize = 32;

/// WireGuard message type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WireGuardMessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
}

impl WireGuardMessageType {
    /// Returns the WireGuard type name matching the Python reference.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HandshakeInitiation => "HANDSHAKE_INITIATION",
            Self::HandshakeResponse => "HANDSHAKE_RESPONSE",
            Self::CookieReply => "COOKIE_REPLY",
            Self::TransportData => "TRANSPORT_DATA",
        }
    }
}

/// Parsed WireGuard public framing metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireGuardPacket {
    pub message_type: WireGuardMessageType,
    pub size: usize,
    pub sender_index: Option<u32>,
    pub receiver_index: Option<u32>,
}

impl WireGuardPacket {
    /// Returns `true` for handshake control messages (types 1, 2, 3) eligible for the overlay.
    #[must_use]
    pub const fn is_handshake_control(&self) -> bool {
        !matches!(self.message_type, WireGuardMessageType::TransportData)
    }

    /// Returns `true` for WireGuard transport data (type 4), which must bypass the overlay directly.
    #[must_use]
    pub const fn is_transport(&self) -> bool {
        matches!(self.message_type, WireGuardMessageType::TransportData)
    }

    /// Returns the WireGuard message type name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.message_type.name()
    }
}

/// Validates public WireGuard packet framing without panicking or inspecting encrypted contents.
pub fn parse_wireguard_packet(packet: &[u8]) -> Result<WireGuardPacket, ProtoError> {
    if packet.len() < 4 {
        return Err(ProtoError::InvalidWireGuardPacket);
    }
    let message_type = match packet[0] {
        1 => WireGuardMessageType::HandshakeInitiation,
        2 => WireGuardMessageType::HandshakeResponse,
        3 => WireGuardMessageType::CookieReply,
        4 => WireGuardMessageType::TransportData,
        _ => return Err(ProtoError::InvalidWireGuardPacket),
    };
    // Reserved bytes [1..4] must always be zero per WireGuard protocol spec.
    if packet[1..4] != [0, 0, 0] {
        return Err(ProtoError::InvalidWireGuardPacket);
    }

    match message_type {
        WireGuardMessageType::HandshakeInitiation => {
            if packet.len() != WG_INITIATION_LEN {
                return Err(ProtoError::InvalidWireGuardPacket);
            }
            let sender_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
            Ok(WireGuardPacket {
                message_type,
                size: packet.len(),
                sender_index: Some(sender_index),
                receiver_index: None,
            })
        }
        WireGuardMessageType::HandshakeResponse => {
            if packet.len() != WG_RESPONSE_LEN {
                return Err(ProtoError::InvalidWireGuardPacket);
            }
            let sender_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
            let receiver_index = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]);
            Ok(WireGuardPacket {
                message_type,
                size: packet.len(),
                sender_index: Some(sender_index),
                receiver_index: Some(receiver_index),
            })
        }
        WireGuardMessageType::CookieReply => {
            if packet.len() != WG_COOKIE_REPLY_LEN {
                return Err(ProtoError::InvalidWireGuardPacket);
            }
            let receiver_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
            Ok(WireGuardPacket {
                message_type,
                size: packet.len(),
                sender_index: None,
                receiver_index: Some(receiver_index),
            })
        }
        WireGuardMessageType::TransportData => {
            if packet.len() < WG_TRANSPORT_MIN_LEN || packet.len() % 16 != 0 {
                return Err(ProtoError::InvalidWireGuardPacket);
            }
            let receiver_index = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
            Ok(WireGuardPacket {
                message_type,
                size: packet.len(),
                sender_index: None,
                receiver_index: Some(receiver_index),
            })
        }
    }
}
