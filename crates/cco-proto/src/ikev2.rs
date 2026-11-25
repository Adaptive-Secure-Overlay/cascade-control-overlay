#![forbid(unsafe_code)]
//! Zero-panic IKEv2 header parser and UDP/500 vs UDP/4500 Non-ESP Marker filter.
//!
//! Matches `ike_proxy.py::is_ike_payload` and `mcc_privacy.py::_opaque_ike_header`.
//! Ensures that ESP-in-UDP packets on port 4500 (non-zero SPI in first 4 bytes)
//! are never admitted into the control overlay.

use crate::error::ProtoError;

/// Minimum IKEv2 header length in bytes (RFC 7296 Section 3.1).
pub const IKEV2_HEADER_LEN: usize = 28;

/// IKEv2 protocol major version (`2`).
pub const IKEV2_MAJOR_VERSION: u8 = 2;

/// Flag bit indicating an IKEv2 Response message (`0x20`).
pub const IKEV2_FLAG_RESPONSE: u8 = 0x20;

/// Flag bit indicating the original Initiator (`0x08`).
pub const IKEV2_FLAG_INITIATOR: u8 = 0x08;

/// Standard IKEv2 exchange types.
pub const IKE_SA_INIT: u8 = 34;
pub const IKE_AUTH: u8 = 35;
pub const CREATE_CHILD_SA: u8 = 36;
pub const INFORMATIONAL: u8 = 37;

/// Correlation tuple `(initiator_spi, exchange_type, message_id)` used by MCC opaque routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IkeRequestKey {
    pub initiator_spi: [u8; 8],
    pub exchange_type: u8,
    pub message_id: u32,
}

/// Parsed public IKEv2 header fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ikev2Header {
    pub udp_port: u16,
    pub has_non_esp_marker: bool,
    pub initiator_spi: [u8; 8],
    pub responder_spi: [u8; 8],
    pub next_payload: u8,
    pub major_version: u8,
    pub minor_version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl Ikev2Header {
    /// Returns `true` if the Response flag (`0x20`) is set.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        (self.flags & IKEV2_FLAG_RESPONSE) != 0
    }

    /// Returns `true` if this packet is an IKEv2 Request (Response flag clear).
    #[must_use]
    pub const fn is_request(&self) -> bool {
        !self.is_response()
    }

    /// Returns `true` if the Initiator flag (`0x08`) is set.
    #[must_use]
    pub const fn is_initiator(&self) -> bool {
        (self.flags & IKEV2_FLAG_INITIATOR) != 0
    }

    /// Extracts the `(initiator_spi, exchange_type, message_id)` correlation key.
    #[must_use]
    pub const fn request_key(&self) -> IkeRequestKey {
        IkeRequestKey {
            initiator_spi: self.initiator_spi,
            exchange_type: self.exchange_type,
            message_id: self.message_id,
        }
    }
}

/// Fast-path filter deciding whether a UDP datagram carries IKE control traffic vs ESP-in-UDP.
///
/// - UDP/500: IKE payload (must be non-empty).
/// - UDP/4500: IKE only when the first 4 bytes are the Non-ESP Marker (`00 00 00 00`).
/// - Any other UDP port: rejected (`false`).
#[must_use]
pub fn is_ike_payload(udp_port: u16, payload: &[u8]) -> bool {
    match udp_port {
        500 => !payload.is_empty(),
        4500 => payload.len() >= 4 && payload[..4] == [0, 0, 0, 0],
        _ => false,
    }
}

/// Parses and validates an IKEv2 header from UDP/500 or UDP/4500 payload bytes without panicking.
pub fn parse_ikev2_packet(udp_port: u16, payload: &[u8]) -> Result<Ikev2Header, ProtoError> {
    let (offset, has_non_esp_marker) = match udp_port {
        500 => (0usize, false),
        4500 => {
            if payload.len() < 4 || payload[..4] != [0, 0, 0, 0] {
                return Err(ProtoError::NotIkePayload);
            }
            (4usize, true)
        }
        _ => return Err(ProtoError::InvalidIkev2Header),
    };

    let header = payload
        .get(offset..)
        .ok_or(ProtoError::InvalidIkev2Header)?;
    if header.len() < IKEV2_HEADER_LEN {
        return Err(ProtoError::InvalidIkev2Header);
    }

    let version_byte = header[17];
    let major_version = version_byte >> 4;
    let minor_version = version_byte & 0x0f;
    if major_version != IKEV2_MAJOR_VERSION {
        return Err(ProtoError::InvalidIkev2Header);
    }

    let length = u32::from_be_bytes([header[24], header[25], header[26], header[27]]);
    if length as usize != header.len() {
        return Err(ProtoError::InvalidIkev2Header);
    }

    let mut initiator_spi = [0u8; 8];
    initiator_spi.copy_from_slice(&header[0..8]);
    let mut responder_spi = [0u8; 8];
    responder_spi.copy_from_slice(&header[8..16]);

    let next_payload = header[16];
    let exchange_type = header[18];
    let flags = header[19];
    let message_id = u32::from_be_bytes([header[20], header[21], header[22], header[23]]);

    Ok(Ikev2Header {
        udp_port,
        has_non_esp_marker,
        initiator_spi,
        responder_spi,
        next_payload,
        major_version,
        minor_version,
        exchange_type,
        flags,
        message_id,
        length,
    })
}
