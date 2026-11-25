#![forbid(unsafe_code)]
//! Strict JSON parsing (rejecting duplicate object keys) and deterministic canonical encoding.

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::error::TrustRegistryError;

const DUPLICATE_KEY_SENTINEL: &str = "__CCO_DUPLICATE_JSON_KEY__";

/// Strict JSON value preserving integer vs float distinction and sorted object keys.
#[derive(Debug, Clone, PartialEq)]
pub enum StrictJson {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(String),
    Array(Vec<StrictJson>),
    Object(BTreeMap<String, StrictJson>),
}

impl StrictJson {
    /// Returns the underlying map if this value is a JSON object.
    #[must_use]
    pub fn as_object(&self) -> Option<&BTreeMap<String, StrictJson>> {
        match self {
            Self::Object(map) => Some(map),
            _ => None,
        }
    }

    /// Returns the underlying slice if this value is a JSON array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[StrictJson]> {
        match self {
            Self::Array(arr) => Some(arr),
            _ => None,
        }
    }

    /// Returns the underlying string if this value is a JSON string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the underlying boolean if this value is a JSON boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Returns a strictly non-negative integer (`u64`), rejecting booleans and floats.
    #[must_use]
    pub fn as_strict_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            Self::Int(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any valid JSON value without duplicate object keys")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictJson::Null)
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictJson::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictJson::Int(v))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictJson::Uint(v))
            }

            fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E> {
                Ok(StrictJson::Float(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictJson::String(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictJson::String(v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(elem) = seq.next_element::<StrictJson>()? {
                    vec.push(elem);
                }
                Ok(StrictJson::Array(vec))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = BTreeMap::new();
                while let Some((key, val)) = map.next_entry::<String, StrictJson>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom(DUPLICATE_KEY_SENTINEL));
                    }
                    out.insert(key, val);
                }
                Ok(StrictJson::Object(out))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

/// Parses UTF-8 bytes as a strict JSON object, rejecting duplicate keys at every nesting level.
pub fn parse_strict_json_object(
    raw: &[u8],
    source: &str,
) -> Result<BTreeMap<String, StrictJson>, TrustRegistryError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| TrustRegistryError::new("corrupt_json", format!("cannot decode {source}")))?;
    let parsed: StrictJson = serde_json::from_str(text).map_err(|err| {
        if err.to_string().contains(DUPLICATE_KEY_SENTINEL) {
            TrustRegistryError::new("duplicate_json_key", "duplicate JSON key rejected")
        } else {
            TrustRegistryError::new("corrupt_json", format!("cannot parse {source}"))
        }
    })?;
    match parsed {
        StrictJson::Object(map) => Ok(map),
        _ => Err(TrustRegistryError::new(
            "invalid_document",
            format!("{source} must be a JSON object"),
        )),
    }
}

/// Encodes a [`StrictJson`] value into canonical compact JSON with sorted keys and no spaces.
///
/// Byte-for-byte compatible with Python's
/// `json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")`.
pub fn canonical_json_bytes(value: &StrictJson) -> Result<Vec<u8>, TrustRegistryError> {
    let mut out = Vec::new();
    write_canonical_json(value, &mut out)?;
    Ok(out)
}

/// Encodes a JSON object map into canonical compact JSON bytes.
pub fn canonical_object_bytes(
    map: &BTreeMap<String, StrictJson>,
) -> Result<Vec<u8>, TrustRegistryError> {
    let mut out = Vec::new();
    write_canonical_object(map, &mut out)?;
    Ok(out)
}

fn write_canonical_json(value: &StrictJson, out: &mut Vec<u8>) -> Result<(), TrustRegistryError> {
    match value {
        StrictJson::Null => out.extend_from_slice(b"null"),
        StrictJson::Bool(true) => out.extend_from_slice(b"true"),
        StrictJson::Bool(false) => out.extend_from_slice(b"false"),
        StrictJson::Int(v) => out.extend_from_slice(v.to_string().as_bytes()),
        StrictJson::Uint(v) => out.extend_from_slice(v.to_string().as_bytes()),
        StrictJson::Float(v) => {
            if !v.is_finite() {
                return Err(TrustRegistryError::new(
                    "corrupt_json",
                    "non-finite number in JSON",
                ));
            }
            let encoded = serde_json::to_string(v)
                .map_err(|_| TrustRegistryError::new("corrupt_json", "float encoding error"))?;
            out.extend_from_slice(encoded.as_bytes());
        }
        StrictJson::String(s) => {
            let encoded = serde_json::to_string(s)
                .map_err(|_| TrustRegistryError::new("corrupt_json", "string encoding error"))?;
            out.extend_from_slice(encoded.as_bytes());
        }
        StrictJson::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        StrictJson::Object(map) => write_canonical_object(map, out)?,
    }
    Ok(())
}

fn write_canonical_object(
    map: &BTreeMap<String, StrictJson>,
    out: &mut Vec<u8>,
) -> Result<(), TrustRegistryError> {
    out.push(b'{');
    for (idx, (k, v)) in map.iter().enumerate() {
        if idx > 0 {
            out.push(b',');
        }
        let encoded_key = serde_json::to_string(k)
            .map_err(|_| TrustRegistryError::new("corrupt_json", "key encoding error"))?;
        out.extend_from_slice(encoded_key.as_bytes());
        out.push(b':');
        write_canonical_json(v, out)?;
    }
    out.push(b'}');
    Ok(())
}

/// Verifies that a JSON object has the exact set of expected keys.
pub fn expect_exact_fields(
    map: &BTreeMap<String, StrictJson>,
    expected: &[&str],
    label: &str,
) -> Result<(), TrustRegistryError> {
    if map.len() != expected.len() || !expected.iter().all(|k| map.contains_key(*k)) {
        return Err(TrustRegistryError::new(
            "invalid_fields",
            format!("{label} fields mismatch"),
        ));
    }
    Ok(())
}

/// Encodes raw bytes as canonical unpadded base64url.
#[must_use]
pub fn b64url_encode(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

/// Decodes a canonical base64url string (matching Python `trust_registry_v1._b64url_decode`).
pub fn b64url_decode_canonical(value: &str, label: &str) -> Result<Vec<u8>, TrustRegistryError> {
    if value.is_empty() {
        return Err(TrustRegistryError::new(
            "invalid_base64",
            format!("{label} must be non-empty base64url"),
        ));
    }
    let trimmed = value.trim_end_matches('=');
    let pad_len = value.len() - trimmed.len();
    if pad_len > 2 || (pad_len > 0 && value.len() % 4 != 0) {
        return Err(TrustRegistryError::new(
            "invalid_base64",
            format!("{label} has invalid base64url padding"),
        ));
    }
    let decoded = URL_SAFE_NO_PAD.decode(trimmed).map_err(|_| {
        TrustRegistryError::new("invalid_base64", format!("{label} is not valid base64url"))
    })?;
    if URL_SAFE_NO_PAD.encode(&decoded) != trimmed {
        return Err(TrustRegistryError::new(
            "invalid_base64",
            format!("{label} is not canonical base64url"),
        ));
    }
    Ok(decoded)
}
