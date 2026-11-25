#![forbid(unsafe_code)]
//! Bounded strict JSON parser and canonical sorted-key JSON encoder.
//!
//! Enforces the same structural limits as `mcc_e2e.py::strict_json_loads`
//! (`MAX_DEPTH = 12`, `MAX_ITEMS = 4096`, `MAX_FIELDS = 128`, no duplicate keys,
//! no floats in strict MCC records).

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;

use crate::error::ProtoError;

/// Default maximum nesting depth for strict JSON records (`mcc_e2e.py::MAX_DEPTH`).
pub const MAX_JSON_DEPTH: usize = 12;

/// Default maximum total nodes/items for strict JSON records (`mcc_e2e.py::MAX_ITEMS`).
pub const MAX_JSON_ITEMS: usize = 4096;

/// Default maximum fields per JSON object (`mcc_e2e.py::MAX_FIELDS`).
pub const MAX_JSON_FIELDS: usize = 128;

/// Maximum JSON key length (`mcc_e2e.py`).
pub const MAX_JSON_KEY_LEN: usize = 128;

const ERR_DUP: &str = "__CCO_PROTO_DUP_KEY__";
const ERR_FLOAT: &str = "__CCO_PROTO_FLOAT__";
const ERR_LIMIT: &str = "__CCO_PROTO_LIMIT__";

/// Strict JSON value tree disallowing floats and duplicate object keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<CanonicalValue>),
    Object(BTreeMap<String, CanonicalValue>),
}

impl CanonicalValue {
    /// Returns the object map if this value is an object.
    #[must_use]
    pub fn as_object(&self) -> Option<&BTreeMap<String, CanonicalValue>> {
        match self {
            Self::Object(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the string slice if this value is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Returns the integer if this value is an integer.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Converts into a `serde_json::Value` (preserving sorted object order via `Map`).
    #[must_use]
    pub fn to_serde_value(&self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(b) => Value::Bool(*b),
            Self::Int(i) => Value::Number((*i).into()),
            Self::String(s) => Value::String(s.clone()),
            Self::Array(arr) => Value::Array(arr.iter().map(Self::to_serde_value).collect()),
            Self::Object(map) => {
                let mut m = serde_json::Map::new();
                for (k, v) in map {
                    m.insert(k.clone(), v.to_serde_value());
                }
                Value::Object(m)
            }
        }
    }

    /// Converts a `serde_json::Value` into a strict [`CanonicalValue`], rejecting floats/out-of-range ints.
    pub fn from_serde_value(val: &Value) -> Result<Self, ProtoError> {
        match val {
            Value::Null => Ok(Self::Null),
            Value::Bool(b) => Ok(Self::Bool(*b)),
            Value::Number(n) => n.as_i64().map(Self::Int).ok_or(ProtoError::InvalidJsonType),
            Value::String(s) => Ok(Self::String(s.clone())),
            Value::Array(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                for item in arr {
                    out.push(Self::from_serde_value(item)?);
                }
                Ok(Self::Array(out))
            }
            Value::Object(map) => {
                let mut out = BTreeMap::new();
                for (k, v) in map {
                    out.insert(k.clone(), Self::from_serde_value(v)?);
                }
                Ok(Self::Object(out))
            }
        }
    }
}

impl<'de> Deserialize<'de> for CanonicalValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = CanonicalValue;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("strict JSON value without floats or duplicate keys")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(CanonicalValue::Null)
            }

            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E> {
                Ok(CanonicalValue::Bool(v))
            }

            fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
                Ok(CanonicalValue::Int(v))
            }

            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                i64::try_from(v)
                    .map(CanonicalValue::Int)
                    .map_err(|_| de::Error::custom(ERR_FLOAT))
            }

            fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(de::Error::custom(ERR_FLOAT))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> {
                Ok(CanonicalValue::String(v.to_owned()))
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E> {
                Ok(CanonicalValue::String(v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::new();
                while let Some(elem) = seq.next_element::<CanonicalValue>()? {
                    if items.len() >= MAX_JSON_ITEMS {
                        return Err(de::Error::custom(ERR_LIMIT));
                    }
                    items.push(elem);
                }
                Ok(CanonicalValue::Array(items))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = BTreeMap::new();
                while let Some((k, v)) = map.next_entry::<String, CanonicalValue>()? {
                    if out.len() >= MAX_JSON_FIELDS || k.len() > MAX_JSON_KEY_LEN {
                        return Err(de::Error::custom(ERR_LIMIT));
                    }
                    if out.contains_key(&k) {
                        return Err(de::Error::custom(ERR_DUP));
                    }
                    out.insert(k, v);
                }
                Ok(CanonicalValue::Object(out))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn validate_shape(
    value: &CanonicalValue,
    depth: usize,
    remaining: &mut isize,
    max_bytes: usize,
) -> Result<(), ProtoError> {
    *remaining -= 1;
    if *remaining < 0 || depth > MAX_JSON_DEPTH {
        return Err(ProtoError::JsonResourceLimit);
    }
    match value {
        CanonicalValue::Null | CanonicalValue::Bool(_) | CanonicalValue::Int(_) => Ok(()),
        CanonicalValue::String(s) => {
            if s.len() > max_bytes {
                return Err(ProtoError::JsonResourceLimit);
            }
            Ok(())
        }
        CanonicalValue::Array(items) => {
            if items.len() > MAX_JSON_ITEMS {
                return Err(ProtoError::JsonResourceLimit);
            }
            for child in items {
                validate_shape(child, depth + 1, remaining, max_bytes)?;
            }
            Ok(())
        }
        CanonicalValue::Object(map) => {
            if map.len() > MAX_JSON_FIELDS {
                return Err(ProtoError::JsonResourceLimit);
            }
            for (k, v) in map {
                if k.len() > MAX_JSON_KEY_LEN {
                    return Err(ProtoError::JsonResourceLimit);
                }
                *remaining -= 1;
                if *remaining < 0 || depth + 1 > MAX_JSON_DEPTH {
                    return Err(ProtoError::JsonResourceLimit);
                }
                validate_shape(v, depth + 1, remaining, max_bytes)?;
            }
            Ok(())
        }
    }
}

/// Parses bounded strict JSON object bytes, rejecting duplicates, floats, and oversized trees.
pub fn parse_strict_json_object(
    raw: &[u8],
    max_bytes: usize,
) -> Result<BTreeMap<String, CanonicalValue>, ProtoError> {
    if raw.len() > max_bytes {
        return Err(ProtoError::JsonResourceLimit);
    }
    let text = std::str::from_utf8(raw).map_err(|_| ProtoError::InvalidJson)?;
    let val: CanonicalValue = serde_json::from_str(text).map_err(|err| {
        let msg = err.to_string();
        if msg.contains(ERR_DUP) {
            ProtoError::DuplicateJsonKey
        } else if msg.contains(ERR_FLOAT) {
            ProtoError::InvalidJsonType
        } else if msg.contains(ERR_LIMIT) {
            ProtoError::JsonResourceLimit
        } else {
            ProtoError::InvalidJson
        }
    })?;
    let mut remaining = MAX_JSON_ITEMS as isize;
    validate_shape(&val, 0, &mut remaining, max_bytes)?;
    let encoded = canonical_bytes_from_value(&val, max_bytes)?;
    if encoded.len() > max_bytes {
        return Err(ProtoError::JsonResourceLimit);
    }
    match val {
        CanonicalValue::Object(map) => Ok(map),
        _ => Err(ProtoError::InvalidJson),
    }
}

/// Encodes a [`CanonicalValue`] into compact sorted-key UTF-8 JSON bytes with a size cap.
pub fn canonical_bytes_from_value(
    value: &CanonicalValue,
    max_bytes: usize,
) -> Result<Vec<u8>, ProtoError> {
    let mut remaining = MAX_JSON_ITEMS as isize;
    validate_shape(value, 0, &mut remaining, max_bytes)?;
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    if out.len() > max_bytes {
        return Err(ProtoError::JsonResourceLimit);
    }
    Ok(out)
}

/// Encodes an object map into compact sorted-key UTF-8 JSON bytes with a size cap.
pub fn canonical_object_bytes(
    map: &BTreeMap<String, CanonicalValue>,
    max_bytes: usize,
) -> Result<Vec<u8>, ProtoError> {
    let val = CanonicalValue::Object(map.clone());
    canonical_bytes_from_value(&val, max_bytes)
}

fn write_canonical(value: &CanonicalValue, out: &mut Vec<u8>) -> Result<(), ProtoError> {
    match value {
        CanonicalValue::Null => out.extend_from_slice(b"null"),
        CanonicalValue::Bool(true) => out.extend_from_slice(b"true"),
        CanonicalValue::Bool(false) => out.extend_from_slice(b"false"),
        CanonicalValue::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        CanonicalValue::String(s) => {
            let encoded = serde_json::to_string(s).map_err(|_| ProtoError::InvalidJson)?;
            out.extend_from_slice(encoded.as_bytes());
        }
        CanonicalValue::Array(arr) => {
            out.push(b'[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        CanonicalValue::Object(map) => {
            out.push(b'{');
            for (idx, (k, v)) in map.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                let encoded_k = serde_json::to_string(k).map_err(|_| ProtoError::InvalidJson)?;
                out.extend_from_slice(encoded_k.as_bytes());
                out.push(b':');
                write_canonical(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Encodes any `serde_json::Value` into compact sorted-key JSON (`protocol.py::jdump`).
///
/// Unlike [`canonical_bytes_from_value`], this also supports floats (e.g. `expires_at` in
/// Universal Cascade wire messages) while sorting all object keys deterministically.
pub fn jdump_value(value: &Value) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::new();
    write_sorted_serde(value, &mut out)?;
    Ok(out)
}

/// Encodes any `Serialize` type into compact sorted-key JSON (`protocol.py::jdump`).
pub fn jdump<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let v = serde_json::to_value(value).map_err(|_| ProtoError::InvalidJson)?;
    jdump_value(&v)
}

/// Parses UTF-8 JSON bytes into `serde_json::Value` (`protocol.py::jload`).
pub fn jload(raw: &[u8]) -> Result<Value, ProtoError> {
    serde_json::from_slice(raw).map_err(|_| ProtoError::InvalidJson)
}

fn write_sorted_serde(value: &Value, out: &mut Vec<u8>) -> Result<(), ProtoError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            let encoded = serde_json::to_string(value).map_err(|_| ProtoError::InvalidJson)?;
            out.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(arr) => {
            out.push(b'[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_sorted_serde(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let sorted: BTreeMap<&str, &Value> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            out.push(b'{');
            for (idx, (k, v)) in sorted.into_iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                let encoded_k = serde_json::to_string(k).map_err(|_| ProtoError::InvalidJson)?;
                out.extend_from_slice(encoded_k.as_bytes());
                out.push(b':');
                write_sorted_serde(v, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}
