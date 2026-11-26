#![forbid(unsafe_code)]
//! Compact binary wire framing (`CCO1`) for high-hop `UniversalCascade` frames.
//!
//! Eliminates double-encoding overhead (`hex` ciphertext + `base64` JSON fragments) while
//! keeping classic JSON `SecureEnvelope` + `LINK_FRAG` 100% wire-compatible with the Python
//! daemon for `MCC_*` / `MGMT_*` messages.
//!
//! With `COMPACT_FRAG_CHUNK_BYTES = 1120` (wire frame `<= 1160 B`, well below safe WAN MTU
//! `1280 B`), a constant-padded `3,584 B` `CASCADE_*` frame encrypts into `~3,651 B` and fits
//! into **4 UDP fragments** instead of 11.

use std::collections::BTreeMap;

use cco_crypto::random_bytes;

use crate::error::ProtoError;
use crate::messages::MessageType;

/// 4-byte binary magic prefix distinguishing compact frames from UTF-8 JSON (`'{' = 0x7b`).
pub const COMPACT_MAGIC: [u8; 4] = *b"CCO1";

/// Compact encrypted hop envelope carrying a `CASCADE_*` message with an 8-byte `ack_id`.
pub const COMPACT_KIND_SECURE: u8 = 0x01;
/// Compact binary UDP fragment carrying raw payload chunks (no base64 expansion).
pub const COMPACT_KIND_FRAG: u8 = 0x02;
/// Compact AEAD-authenticated hop-by-hop acknowledgment for a received `ack_id`.
pub const COMPACT_KIND_HOP_ACK: u8 = 0x03;

/// Maximum wire size of a single compact UDP fragment (safe under WAN / IPv6 1280 B MTU).
pub const COMPACT_FRAG_MAX_WIRE: usize = 1200;
/// Maximum raw payload bytes per compact fragment (`1120 + ~21 B header = ~1141 B <= 1200 B`).
pub const COMPACT_FRAG_CHUNK_BYTES: usize = 1120;
/// Maximum number of fragments per reassembled compact frame (`64 * 1120 > 65507`).
pub const COMPACT_FRAG_MAX_TOTAL: usize = 64;
/// Maximum reassembled compact frame size in bytes.
pub const COMPACT_FRAG_MAX_ASSEMBLED: usize = 65_507;
/// Maximum simultaneous in-flight compact reassembly buffers.
pub const COMPACT_FRAG_MAX_BUFFERS: usize = 64;
/// Expiration time for incomplete compact fragment buffers in seconds.
pub const COMPACT_FRAG_TTL_SECS: f64 = 15.0;

const MAX_SHORT_STR_LEN: usize = 64;
const HOP_ACK_CT_LEN: usize = 8 + 16; // 8-byte ack_id + 16-byte AES-256-GCM tag

/// Returns `true` if `data` begins with the `CCO1` compact binary magic prefix.
#[must_use]
pub fn is_compact_frame(data: &[u8]) -> bool {
    data.len() >= 5 && data[..4] == COMPACT_MAGIC
}

/// Peeks the `from` peer name of any valid `CCO1` frame (used for NAT peer lookup before AEAD).
#[must_use]
pub fn peek_compact_sender(data: &[u8]) -> Option<&str> {
    if data.len() < 6 || data[..4] != COMPACT_MAGIC {
        return None;
    }
    let offset = match data[4] {
        COMPACT_KIND_SECURE => 6, // magic(4) + kind(1) + msg_code(1)
        COMPACT_KIND_FRAG | COMPACT_KIND_HOP_ACK => 5, // magic(4) + kind(1)
        _ => return None,
    };
    let len = *data.get(offset)? as usize;
    if len == 0 || len > MAX_SHORT_STR_LEN || data.len() < offset + 1 + len {
        return None;
    }
    std::str::from_utf8(&data[offset + 1..offset + 1 + len]).ok()
}

/// Stable 1-byte wire code for `MessageType` inside compact frames.
#[must_use]
pub const fn message_type_to_code(mtype: MessageType) -> Option<u8> {
    match mtype {
        MessageType::CascadeBuild => Some(0x20),
        MessageType::CascadeReject => Some(0x21),
        MessageType::CascadeAbort => Some(0x22),
        MessageType::CascadeProbe => Some(0x23),
        MessageType::CascadeAccept => Some(0x24),
        MessageType::CascadeData => Some(0x25),
        MessageType::CascadeBack => Some(0x26),
        MessageType::CascadeClose => Some(0x27),
        MessageType::MccStart => Some(0x10),
        MessageType::MccX2 => Some(0x11),
        MessageType::MccOffer => Some(0x12),
        MessageType::MccAccept => Some(0x13),
        MessageType::MccOpaqueFwd => Some(0x14),
        MessageType::PrivFwd => Some(0x15),
        MessageType::PrivDeliver => Some(0x16),
        MessageType::PrivBack => Some(0x17),
        _ => None,
    }
}

/// Decodes a 1-byte compact wire code back into [`MessageType`].
#[must_use]
pub const fn message_type_from_code(code: u8) -> Option<MessageType> {
    match code {
        0x20 => Some(MessageType::CascadeBuild),
        0x21 => Some(MessageType::CascadeReject),
        0x22 => Some(MessageType::CascadeAbort),
        0x23 => Some(MessageType::CascadeProbe),
        0x24 => Some(MessageType::CascadeAccept),
        0x25 => Some(MessageType::CascadeData),
        0x26 => Some(MessageType::CascadeBack),
        0x27 => Some(MessageType::CascadeClose),
        0x10 => Some(MessageType::MccStart),
        0x11 => Some(MessageType::MccX2),
        0x12 => Some(MessageType::MccOffer),
        0x13 => Some(MessageType::MccAccept),
        0x14 => Some(MessageType::MccOpaqueFwd),
        0x15 => Some(MessageType::PrivFwd),
        0x16 => Some(MessageType::PrivDeliver),
        0x17 => Some(MessageType::PrivBack),
        _ => None,
    }
}

/// Parsed `CCO1` compact encrypted hop envelope (`COMPACT_KIND_SECURE`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactSecureFrame {
    pub message_type: MessageType,
    pub from: String,
    pub to: String,
    pub sid: String,
    pub ack_id: [u8; 8],
    pub nonce: [u8; 12],
    pub ct: Vec<u8>,
}

/// Parsed `CCO1` compact binary fragment (`COMPACT_KIND_FRAG`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactFragFrame {
    pub from: String,
    pub to: String,
    pub frag_id: [u8; 8],
    pub seq: u8,
    pub total: u8,
    pub data: Vec<u8>,
}

/// Parsed `CCO1` compact authenticated hop ACK (`COMPACT_KIND_HOP_ACK`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactHopAckFrame {
    pub from: String,
    pub to: String,
    pub sid: String,
    pub nonce: [u8; 12],
    pub ct: [u8; HOP_ACK_CT_LEN],
}

/// Decoded variant of any `CCO1` compact frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompactFrame {
    Secure(CompactSecureFrame),
    Frag(CompactFragFrame),
    HopAck(CompactHopAckFrame),
}

fn push_short_str(out: &mut Vec<u8>, s: &str) -> Result<(), ProtoError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SHORT_STR_LEN {
        return Err(ProtoError::InvalidFragment);
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_short_str(data: &[u8], pos: &mut usize) -> Result<String, ProtoError> {
    let len = *data.get(*pos).ok_or(ProtoError::InvalidFragment)? as usize;
    *pos += 1;
    if len == 0 || len > MAX_SHORT_STR_LEN || data.len() < *pos + len {
        return Err(ProtoError::InvalidFragment);
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| ProtoError::InvalidFragment)?
        .to_owned();
    *pos += len;
    Ok(s)
}

impl CompactSecureFrame {
    /// Serializes this compact encrypted envelope into raw `CCO1` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let code = message_type_to_code(self.message_type).ok_or(ProtoError::UnknownMessageType)?;
        if self.ct.is_empty() || self.ct.len() > u16::MAX as usize {
            return Err(ProtoError::PayloadTooLarge);
        }
        let cap = 6
            + (1 + self.from.len())
            + (1 + self.to.len())
            + (1 + self.sid.len())
            + 8
            + 12
            + 2
            + self.ct.len();
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&COMPACT_MAGIC);
        out.push(COMPACT_KIND_SECURE);
        out.push(code);
        push_short_str(&mut out, &self.from)?;
        push_short_str(&mut out, &self.to)?;
        push_short_str(&mut out, &self.sid)?;
        out.extend_from_slice(&self.ack_id);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.ct.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.ct);
        Ok(out)
    }

    /// Parses a `CCO1` compact encrypted envelope.
    pub fn decode(data: &[u8]) -> Result<Self, ProtoError> {
        if data.len() < 7 || data[..4] != COMPACT_MAGIC || data[4] != COMPACT_KIND_SECURE {
            return Err(ProtoError::InvalidFragment);
        }
        let message_type = message_type_from_code(data[5]).ok_or(ProtoError::UnknownMessageType)?;
        let mut pos = 6;
        let from = read_short_str(data, &mut pos)?;
        let to = read_short_str(data, &mut pos)?;
        let sid = read_short_str(data, &mut pos)?;
        if data.len() < pos + 8 + 12 + 2 {
            return Err(ProtoError::InvalidFragment);
        }
        let mut ack_id = [0u8; 8];
        ack_id.copy_from_slice(&data[pos..pos + 8]);
        pos += 8;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;
        let ct_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if ct_len == 0 || data.len() != pos + ct_len {
            return Err(ProtoError::InvalidFragment);
        }
        Ok(Self {
            message_type,
            from,
            to,
            sid,
            ack_id,
            nonce,
            ct: data[pos..].to_vec(),
        })
    }
}

impl CompactHopAckFrame {
    /// Serializes this compact authenticated hop ACK into raw `CCO1` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let cap = 5 + (1 + self.from.len()) + (1 + self.to.len()) + (1 + self.sid.len()) + 12 + 24;
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&COMPACT_MAGIC);
        out.push(COMPACT_KIND_HOP_ACK);
        push_short_str(&mut out, &self.from)?;
        push_short_str(&mut out, &self.to)?;
        push_short_str(&mut out, &self.sid)?;
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        Ok(out)
    }

    /// Parses a `CCO1` compact authenticated hop ACK.
    pub fn decode(data: &[u8]) -> Result<Self, ProtoError> {
        if data.len() < 6 || data[..4] != COMPACT_MAGIC || data[4] != COMPACT_KIND_HOP_ACK {
            return Err(ProtoError::InvalidFragment);
        }
        let mut pos = 5;
        let from = read_short_str(data, &mut pos)?;
        let to = read_short_str(data, &mut pos)?;
        let sid = read_short_str(data, &mut pos)?;
        if data.len() != pos + 12 + HOP_ACK_CT_LEN {
            return Err(ProtoError::InvalidFragment);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[pos..pos + 12]);
        pos += 12;
        let mut ct = [0u8; HOP_ACK_CT_LEN];
        ct.copy_from_slice(&data[pos..pos + HOP_ACK_CT_LEN]);
        Ok(Self {
            from,
            to,
            sid,
            nonce,
            ct,
        })
    }
}

impl CompactFragFrame {
    /// Serializes this binary fragment into a single UDP payload (`<= COMPACT_FRAG_MAX_WIRE`).
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        if self.data.is_empty()
            || self.data.len() > COMPACT_FRAG_CHUNK_BYTES
            || self.total == 0
            || usize::from(self.total) > COMPACT_FRAG_MAX_TOTAL
            || self.seq >= self.total
        {
            return Err(ProtoError::InvalidFragment);
        }
        let cap = 5 + (1 + self.from.len()) + (1 + self.to.len()) + 8 + 2 + self.data.len();
        if cap > COMPACT_FRAG_MAX_WIRE {
            return Err(ProtoError::PayloadTooLarge);
        }
        let mut out = Vec::with_capacity(cap);
        out.extend_from_slice(&COMPACT_MAGIC);
        out.push(COMPACT_KIND_FRAG);
        push_short_str(&mut out, &self.from)?;
        push_short_str(&mut out, &self.to)?;
        out.extend_from_slice(&self.frag_id);
        out.push(self.seq);
        out.push(self.total);
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Parses a binary `CCO1` fragment frame.
    pub fn decode(data: &[u8]) -> Result<Self, ProtoError> {
        if data.len() < 16 || data[..4] != COMPACT_MAGIC || data[4] != COMPACT_KIND_FRAG {
            return Err(ProtoError::InvalidFragment);
        }
        let mut pos = 5;
        let from = read_short_str(data, &mut pos)?;
        let to = read_short_str(data, &mut pos)?;
        if data.len() <= pos + 10 {
            return Err(ProtoError::InvalidFragment);
        }
        let mut frag_id = [0u8; 8];
        frag_id.copy_from_slice(&data[pos..pos + 8]);
        pos += 8;
        let seq = data[pos];
        let total = data[pos + 1];
        pos += 2;
        let chunk = &data[pos..];
        if chunk.is_empty()
            || chunk.len() > COMPACT_FRAG_CHUNK_BYTES
            || total == 0
            || usize::from(total) > COMPACT_FRAG_MAX_TOTAL
            || seq >= total
        {
            return Err(ProtoError::InvalidFragment);
        }
        Ok(Self {
            from,
            to,
            frag_id,
            seq,
            total,
            data: chunk.to_vec(),
        })
    }
}

/// Decodes any `CCO1` binary wire frame into [`CompactFrame`].
pub fn decode_compact_frame(data: &[u8]) -> Result<CompactFrame, ProtoError> {
    if !is_compact_frame(data) {
        return Err(ProtoError::InvalidFragment);
    }
    match data[4] {
        COMPACT_KIND_SECURE => Ok(CompactFrame::Secure(CompactSecureFrame::decode(data)?)),
        COMPACT_KIND_FRAG => Ok(CompactFrame::Frag(CompactFragFrame::decode(data)?)),
        COMPACT_KIND_HOP_ACK => Ok(CompactFrame::HopAck(CompactHopAckFrame::decode(data)?)),
        _ => Err(ProtoError::InvalidFragment),
    }
}

/// Splits a compact binary payload into `<= 1200 B` UDP datagrams (`4` packets for `3,584 B` cascade).
pub fn fragment_compact_payload(
    from: &str,
    to: &str,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, ProtoError> {
    fragment_compact_payload_with_id(from, to, payload, random_bytes::<8>())
}

/// Deterministic variant of [`fragment_compact_payload`] with an explicit 8-byte `frag_id`.
pub fn fragment_compact_payload_with_id(
    from: &str,
    to: &str,
    payload: &[u8],
    frag_id: [u8; 8],
) -> Result<Vec<Vec<u8>>, ProtoError> {
    if payload.len() <= COMPACT_FRAG_MAX_WIRE {
        return Ok(vec![payload.to_vec()]);
    }
    if payload.len() > COMPACT_FRAG_MAX_ASSEMBLED {
        return Err(ProtoError::PayloadTooLarge);
    }
    let header_len = 5 + (1 + from.len()) + (1 + to.len()) + 10;
    let max_chunk = COMPACT_FRAG_MAX_WIRE
        .saturating_sub(header_len)
        .min(COMPACT_FRAG_CHUNK_BYTES);
    if max_chunk == 0 {
        return Err(ProtoError::InvalidFragment);
    }
    let chunks: Vec<&[u8]> = payload.chunks(max_chunk).collect();
    let total = chunks.len();
    if total == 0 || total > COMPACT_FRAG_MAX_TOTAL {
        return Err(ProtoError::PayloadTooLarge);
    }
    let mut out = Vec::with_capacity(total);
    for (seq, chunk) in chunks.into_iter().enumerate() {
        let frame = CompactFragFrame {
            from: from.to_owned(),
            to: to.to_owned(),
            frag_id,
            seq: seq as u8,
            total: total as u8,
            data: chunk.to_vec(),
        };
        out.push(frame.encode()?);
    }
    Ok(out)
}

#[derive(Debug, Clone)]
struct CompactFragBuffer {
    created_at: f64,
    total: u8,
    parts: BTreeMap<u8, Vec<u8>>,
}

/// Bounded Sans-I/O reassembler for `CCO1` binary fragments (`COMPACT_KIND_FRAG`).
#[derive(Debug, Default)]
pub struct CompactFragReassembler {
    self_name: String,
    buffers: BTreeMap<(String, [u8; 8]), CompactFragBuffer>,
}

impl CompactFragReassembler {
    /// Creates a new compact binary fragment reassembler for `self_name`.
    #[must_use]
    pub fn new(self_name: impl Into<String>) -> Self {
        Self {
            self_name: self_name.into(),
            buffers: BTreeMap::new(),
        }
    }

    /// Returns the number of currently active partial fragment buffers.
    #[must_use]
    pub fn active_buffers(&self) -> usize {
        self.buffers.len()
    }

    /// Removes expired buffers older than [`COMPACT_FRAG_TTL_SECS`].
    pub fn prune(&mut self, now_secs: f64) {
        self.buffers
            .retain(|_, entry| now_secs - entry.created_at <= COMPACT_FRAG_TTL_SECS);
    }

    /// Ingests one `CompactFragFrame` from `peer`, returning the reassembled `CCO1` payload when complete.
    pub fn ingest(
        &mut self,
        peer: &str,
        frame: &CompactFragFrame,
        now_secs: f64,
    ) -> Result<Option<Vec<u8>>, ProtoError> {
        if peer.is_empty()
            || frame.from != peer
            || frame.to != self.self_name
            || frame.total == 0
            || usize::from(frame.total) > COMPACT_FRAG_MAX_TOTAL
            || frame.seq >= frame.total
            || frame.data.is_empty()
            || frame.data.len() > COMPACT_FRAG_CHUNK_BYTES
        {
            return Err(ProtoError::InvalidFragment);
        }

        self.prune(now_secs);

        let key = (peer.to_owned(), frame.frag_id);
        if !self.buffers.contains_key(&key) && self.buffers.len() >= COMPACT_FRAG_MAX_BUFFERS {
            return Err(ProtoError::InvalidFragment);
        }

        let entry = self
            .buffers
            .entry(key.clone())
            .or_insert_with(|| CompactFragBuffer {
                created_at: now_secs,
                total: frame.total,
                parts: BTreeMap::new(),
            });

        if entry.total != frame.total {
            self.buffers.remove(&key);
            return Err(ProtoError::InvalidFragment);
        }
        if let Some(prev) = entry.parts.get(&frame.seq) {
            if prev != &frame.data {
                self.buffers.remove(&key);
                return Err(ProtoError::InvalidFragment);
            }
        } else {
            entry.parts.insert(frame.seq, frame.data.clone());
        }

        if entry.parts.len() < usize::from(entry.total) {
            return Ok(None);
        }

        let Some(done) = self.buffers.remove(&key) else {
            return Err(ProtoError::InvalidFragment);
        };
        let mut assembled = Vec::new();
        for idx in 0..done.total {
            let Some(part) = done.parts.get(&idx) else {
                return Err(ProtoError::InvalidFragment);
            };
            assembled.extend_from_slice(part);
        }
        if assembled.len() > COMPACT_FRAG_MAX_ASSEMBLED {
            return Err(ProtoError::PayloadTooLarge);
        }
        if is_compact_frame(&assembled) && assembled[4] == COMPACT_KIND_FRAG {
            return Err(ProtoError::NestedLinkFrag);
        }
        Ok(Some(assembled))
    }
}
