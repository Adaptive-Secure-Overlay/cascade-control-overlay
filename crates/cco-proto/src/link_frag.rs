#![forbid(unsafe_code)]
//! Bounded `LINK_FRAG` UDP fragmentation and reassembly (`link_transport.py`).
//!
//! Splits overlay frames larger than `1200` bytes into base64 JSON chunks (`<= 1200` bytes on
//! the wire) to remain safely under standard 1500-byte IPv4 MTU without IP fragmentation.
//! Enforces strict memory bounds (`<= 32` active buffers, `<= 94` chunks, `<= 65,507` B
//! assembled, 15s TTL) and forbids nested `LINK_FRAG` frames.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use cco_crypto::random_bytes;
use serde::{Deserialize, Serialize};

use crate::canonical::{jdump, jload};
use crate::error::ProtoError;
use crate::messages::T_LINK_FRAG;

/// Maximum wire frame size before splitting into `LINK_FRAG` packets.
pub const LINK_FRAG_MAX_WIRE: usize = 1200;

/// Raw payload bytes carried in each `LINK_FRAG` chunk before base64 encoding.
pub const LINK_FRAG_CHUNK_BYTES: usize = 700;

/// Reassembly buffer expiration time in seconds.
pub const LINK_FRAG_TTL_SECS: f64 = 15.0;

/// Hard upper bound on fragment count per message (`ceil(65507 / 700) == 94`).
pub const LINK_FRAG_MAX_TOTAL: usize = 94;

/// Hard upper bound on reassembled payload size (IPv4 UDP payload limit).
pub const LINK_FRAG_MAX_ASSEMBLED: usize = 65_507;

/// Hard upper bound on simultaneous in-flight reassembly buffers.
pub const LINK_FRAG_MAX_BUFFERS: usize = 32;

/// Fixed lowercase hex length of `frag_id` (8 random bytes = 16 hex chars).
pub const LINK_FRAG_ID_HEX_LEN: usize = 16;

/// Wire JSON frame for a single `LINK_FRAG` chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkFragFrame {
    pub t: String,
    pub from: String,
    pub to: String,
    pub frag_id: String,
    pub seq: usize,
    pub total: usize,
    pub data: String,
}

/// Fragments `payload` into one raw wire frame (if `<= 1200` bytes) or multiple `LINK_FRAG`
/// frames with a fresh random `frag_id`.
pub fn fragment_payload(from: &str, to: &str, payload: &[u8]) -> Result<Vec<Vec<u8>>, ProtoError> {
    let frag_id = hex::encode(random_bytes::<8>());
    fragment_payload_with_id(from, to, payload, &frag_id)
}

/// Deterministic variant of [`fragment_payload`] accepting an explicit 16-char hex `frag_id`.
pub fn fragment_payload_with_id(
    from: &str,
    to: &str,
    payload: &[u8],
    frag_id: &str,
) -> Result<Vec<Vec<u8>>, ProtoError> {
    if payload.len() <= LINK_FRAG_MAX_WIRE {
        return Ok(vec![payload.to_vec()]);
    }
    if payload.len() > LINK_FRAG_MAX_ASSEMBLED {
        return Err(ProtoError::PayloadTooLarge);
    }
    if !is_valid_frag_id(frag_id) {
        return Err(ProtoError::InvalidFragment);
    }
    let chunks: Vec<&[u8]> = payload.chunks(LINK_FRAG_CHUNK_BYTES).collect();
    let total = chunks.len();
    if total == 0 || total > LINK_FRAG_MAX_TOTAL {
        return Err(ProtoError::PayloadTooLarge);
    }
    let mut frames = Vec::with_capacity(total);
    for (seq, chunk) in chunks.into_iter().enumerate() {
        let frame = LinkFragFrame {
            t: T_LINK_FRAG.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
            frag_id: frag_id.to_owned(),
            seq,
            total,
            data: STANDARD.encode(chunk),
        };
        let encoded = jdump(&frame)?;
        if encoded.len() > LINK_FRAG_MAX_WIRE {
            return Err(ProtoError::PayloadTooLarge);
        }
        frames.push(encoded);
    }
    Ok(frames)
}

fn is_valid_frag_id(frag_id: &str) -> bool {
    frag_id.len() == LINK_FRAG_ID_HEX_LEN
        && frag_id
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Debug, Clone)]
struct FragBuffer {
    created_at: f64,
    total: usize,
    parts: BTreeMap<usize, Vec<u8>>,
}

/// Sans-I/O bounded reassembler for incoming `LINK_FRAG` frames.
#[derive(Debug, Default)]
pub struct LinkFragReassembler {
    self_name: String,
    buffers: BTreeMap<String, FragBuffer>,
}

impl LinkFragReassembler {
    /// Creates a new reassembler bound to local node name `self_name`.
    #[must_use]
    pub fn new(self_name: impl Into<String>) -> Self {
        Self {
            self_name: self_name.into(),
            buffers: BTreeMap::new(),
        }
    }

    /// Returns the number of currently active partial reassembly buffers.
    #[must_use]
    pub fn active_buffers(&self) -> usize {
        self.buffers.len()
    }

    /// Removes expired buffers older than [`LINK_FRAG_TTL_SECS`].
    pub fn prune(&mut self, now_secs: f64) {
        self.buffers
            .retain(|_, entry| now_secs - entry.created_at <= LINK_FRAG_TTL_SECS);
    }

    /// Processes an incoming `LINK_FRAG` frame from authenticated `peer`.
    ///
    /// Returns:
    /// - `Ok(Some(assembled))` when all fragments are present and validated (non-nested).
    /// - `Ok(None)` when more fragments are still needed.
    /// - `Err(_)` when the fragment is invalid, conflicting, exceeds bounds, or nests `LINK_FRAG`.
    pub fn ingest(
        &mut self,
        peer: &str,
        frame: &LinkFragFrame,
        now_secs: f64,
    ) -> Result<Option<Vec<u8>>, ProtoError> {
        if frame.t != T_LINK_FRAG
            || peer.is_empty()
            || frame.from != peer
            || frame.to != self.self_name
        {
            return Err(ProtoError::InvalidFragment);
        }
        if !is_valid_frag_id(&frame.frag_id)
            || frame.total == 0
            || frame.total > LINK_FRAG_MAX_TOTAL
            || frame.seq >= frame.total
        {
            return Err(ProtoError::InvalidFragment);
        }
        let chunk = STANDARD
            .decode(frame.data.as_bytes())
            .map_err(|_| ProtoError::InvalidFragment)?;
        if chunk.len() > LINK_FRAG_CHUNK_BYTES {
            return Err(ProtoError::InvalidFragment);
        }

        self.prune(now_secs);

        let key = format!("{peer}:{}", frame.frag_id);
        if !self.buffers.contains_key(&key) && self.buffers.len() >= LINK_FRAG_MAX_BUFFERS {
            return Err(ProtoError::InvalidFragment);
        }

        let entry = self
            .buffers
            .entry(key.clone())
            .or_insert_with(|| FragBuffer {
                created_at: now_secs,
                total: frame.total,
                parts: BTreeMap::new(),
            });

        if entry.total != frame.total {
            self.buffers.remove(&key);
            return Err(ProtoError::InvalidFragment);
        }
        if let Some(prev) = entry.parts.get(&frame.seq) {
            if prev != &chunk {
                self.buffers.remove(&key);
                return Err(ProtoError::InvalidFragment);
            }
        } else {
            entry.parts.insert(frame.seq, chunk);
        }

        if entry.parts.len() < entry.total {
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

        if assembled.len() > LINK_FRAG_MAX_ASSEMBLED {
            return Err(ProtoError::PayloadTooLarge);
        }

        let parsed = jload(&assembled)?;
        if parsed.get("t").and_then(|v| v.as_str()) == Some(T_LINK_FRAG) {
            return Err(ProtoError::NestedLinkFrag);
        }
        Ok(Some(assembled))
    }
}
