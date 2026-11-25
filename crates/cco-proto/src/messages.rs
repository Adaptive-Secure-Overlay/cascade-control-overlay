#![forbid(unsafe_code)]
//! Wire protocol message types and envelopes (1-to-1 with `protocol.py` and `universal_cascade.py`).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProtoError;

/// Overlay wire protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

// MGMT 4-step handshake
pub const T_MGMT_INIT: &str = "MGMT_INIT";
pub const T_MGMT_INIT_RESP: &str = "MGMT_INIT_RESP";
pub const T_MGMT_AUTH: &str = "MGMT_AUTH";
pub const T_MGMT_AUTH_RESP: &str = "MGMT_AUTH_RESP";

// Legacy / proxy
pub const T_I1: &str = "I1";
pub const T_I2: &str = "I2";
pub const T_OKX2: &str = "OKX2";
pub const T_PROXY_BLOB: &str = "PROXY_BLOB";

// Privacy on-demand
pub const T_PRIV_FWD: &str = "PRIV_FWD";
pub const T_PRIV_DELIVER: &str = "PRIV_DELIVER";
pub const T_PRIV_BACK: &str = "PRIV_BACK";
pub const T_PRIV_BKEY_REQ: &str = "PRIV_BKEY_REQ";
pub const T_PRIV_BKEY_RESP: &str = "PRIV_BKEY_RESP";
pub const T_PRIV_X1B_SEAL: &str = "PRIV_X1B_SEAL";
pub const T_PRIV_INLINE_START: &str = "PRIV_INLINE_START";
pub const T_PRIV_INLINE_X2: &str = "PRIV_INLINE_X2";

// MCC (Multiple Start Connections)
pub const T_MCC_START: &str = "MCC_START";
pub const T_MCC_X2: &str = "MCC_X2";
pub const T_MCC_OFFER: &str = "MCC_OFFER";
pub const T_MCC_ACCEPT: &str = "MCC_ACCEPT";
pub const T_MCC_OPAQUE_FWD: &str = "MCC_OPAQUE_FWD";

// Universal H-hop Cascade
pub const T_CASCADE_BUILD: &str = "CASCADE_BUILD";
pub const T_CASCADE_REJECT: &str = "CASCADE_REJECT";
pub const T_CASCADE_ABORT: &str = "CASCADE_ABORT";
pub const T_CASCADE_PROBE: &str = "CASCADE_PROBE";
pub const T_CASCADE_ACCEPT: &str = "CASCADE_ACCEPT";
pub const T_CASCADE_DATA: &str = "CASCADE_DATA";
pub const T_CASCADE_BACK: &str = "CASCADE_BACK";
pub const T_CASCADE_CLOSE: &str = "CASCADE_CLOSE";

// Transport / control / error
pub const T_LINK_FRAG: &str = "LINK_FRAG";
pub const T_LOCAL_CONNECT: &str = "LOCAL_CONNECT";
pub const T_ERROR: &str = "ERROR";

/// Complete enumeration of all overlay wire message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    #[serde(rename = "MGMT_INIT")]
    MgmtInit,
    #[serde(rename = "MGMT_INIT_RESP")]
    MgmtInitResp,
    #[serde(rename = "MGMT_AUTH")]
    MgmtAuth,
    #[serde(rename = "MGMT_AUTH_RESP")]
    MgmtAuthResp,

    #[serde(rename = "I1")]
    I1,
    #[serde(rename = "I2")]
    I2,
    #[serde(rename = "OKX2")]
    OkX2,
    #[serde(rename = "PROXY_BLOB")]
    ProxyBlob,

    #[serde(rename = "PRIV_FWD")]
    PrivFwd,
    #[serde(rename = "PRIV_DELIVER")]
    PrivDeliver,
    #[serde(rename = "PRIV_BACK")]
    PrivBack,
    #[serde(rename = "PRIV_BKEY_REQ")]
    PrivBkeyReq,
    #[serde(rename = "PRIV_BKEY_RESP")]
    PrivBkeyResp,
    #[serde(rename = "PRIV_X1B_SEAL")]
    PrivX1bSeal,
    #[serde(rename = "PRIV_INLINE_START")]
    PrivInlineStart,
    #[serde(rename = "PRIV_INLINE_X2")]
    PrivInlineX2,

    #[serde(rename = "MCC_START")]
    MccStart,
    #[serde(rename = "MCC_X2")]
    MccX2,
    #[serde(rename = "MCC_OFFER")]
    MccOffer,
    #[serde(rename = "MCC_ACCEPT")]
    MccAccept,
    #[serde(rename = "MCC_OPAQUE_FWD")]
    MccOpaqueFwd,

    #[serde(rename = "CASCADE_BUILD")]
    CascadeBuild,
    #[serde(rename = "CASCADE_REJECT")]
    CascadeReject,
    #[serde(rename = "CASCADE_ABORT")]
    CascadeAbort,
    #[serde(rename = "CASCADE_PROBE")]
    CascadeProbe,
    #[serde(rename = "CASCADE_ACCEPT")]
    CascadeAccept,
    #[serde(rename = "CASCADE_DATA")]
    CascadeData,
    #[serde(rename = "CASCADE_BACK")]
    CascadeBack,
    #[serde(rename = "CASCADE_CLOSE")]
    CascadeClose,

    #[serde(rename = "LINK_FRAG")]
    LinkFrag,
    #[serde(rename = "LOCAL_CONNECT")]
    LocalConnect,
    #[serde(rename = "ERROR")]
    Error,
}

impl MessageType {
    /// Returns the exact wire string identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MgmtInit => T_MGMT_INIT,
            Self::MgmtInitResp => T_MGMT_INIT_RESP,
            Self::MgmtAuth => T_MGMT_AUTH,
            Self::MgmtAuthResp => T_MGMT_AUTH_RESP,
            Self::I1 => T_I1,
            Self::I2 => T_I2,
            Self::OkX2 => T_OKX2,
            Self::ProxyBlob => T_PROXY_BLOB,
            Self::PrivFwd => T_PRIV_FWD,
            Self::PrivDeliver => T_PRIV_DELIVER,
            Self::PrivBack => T_PRIV_BACK,
            Self::PrivBkeyReq => T_PRIV_BKEY_REQ,
            Self::PrivBkeyResp => T_PRIV_BKEY_RESP,
            Self::PrivX1bSeal => T_PRIV_X1B_SEAL,
            Self::PrivInlineStart => T_PRIV_INLINE_START,
            Self::PrivInlineX2 => T_PRIV_INLINE_X2,
            Self::MccStart => T_MCC_START,
            Self::MccX2 => T_MCC_X2,
            Self::MccOffer => T_MCC_OFFER,
            Self::MccAccept => T_MCC_ACCEPT,
            Self::MccOpaqueFwd => T_MCC_OPAQUE_FWD,
            Self::CascadeBuild => T_CASCADE_BUILD,
            Self::CascadeReject => T_CASCADE_REJECT,
            Self::CascadeAbort => T_CASCADE_ABORT,
            Self::CascadeProbe => T_CASCADE_PROBE,
            Self::CascadeAccept => T_CASCADE_ACCEPT,
            Self::CascadeData => T_CASCADE_DATA,
            Self::CascadeBack => T_CASCADE_BACK,
            Self::CascadeClose => T_CASCADE_CLOSE,
            Self::LinkFrag => T_LINK_FRAG,
            Self::LocalConnect => T_LOCAL_CONNECT,
            Self::Error => T_ERROR,
        }
    }

    /// Returns `true` for message types encrypted inside an established MGMT hop session.
    #[must_use]
    pub const fn is_secure_hop_message(self) -> bool {
        !matches!(
            self,
            Self::MgmtInit
                | Self::MgmtInitResp
                | Self::MgmtAuth
                | Self::MgmtAuthResp
                | Self::LinkFrag
                | Self::LocalConnect
                | Self::Error
        )
    }

    /// Returns `true` for Universal H-hop Cascade messages (`CASCADE_*`).
    #[must_use]
    pub const fn is_cascade_message(self) -> bool {
        matches!(
            self,
            Self::CascadeBuild
                | Self::CascadeReject
                | Self::CascadeAbort
                | Self::CascadeProbe
                | Self::CascadeAccept
                | Self::CascadeData
                | Self::CascadeBack
                | Self::CascadeClose
        )
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MessageType {
    type Err = ProtoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            T_MGMT_INIT => Ok(Self::MgmtInit),
            T_MGMT_INIT_RESP => Ok(Self::MgmtInitResp),
            T_MGMT_AUTH => Ok(Self::MgmtAuth),
            T_MGMT_AUTH_RESP => Ok(Self::MgmtAuthResp),
            T_I1 => Ok(Self::I1),
            T_I2 => Ok(Self::I2),
            T_OKX2 => Ok(Self::OkX2),
            T_PROXY_BLOB => Ok(Self::ProxyBlob),
            T_PRIV_FWD => Ok(Self::PrivFwd),
            T_PRIV_DELIVER => Ok(Self::PrivDeliver),
            T_PRIV_BACK => Ok(Self::PrivBack),
            T_PRIV_BKEY_REQ => Ok(Self::PrivBkeyReq),
            T_PRIV_BKEY_RESP => Ok(Self::PrivBkeyResp),
            T_PRIV_X1B_SEAL => Ok(Self::PrivX1bSeal),
            T_PRIV_INLINE_START => Ok(Self::PrivInlineStart),
            T_PRIV_INLINE_X2 => Ok(Self::PrivInlineX2),
            T_MCC_START => Ok(Self::MccStart),
            T_MCC_X2 => Ok(Self::MccX2),
            T_MCC_OFFER => Ok(Self::MccOffer),
            T_MCC_ACCEPT => Ok(Self::MccAccept),
            T_MCC_OPAQUE_FWD => Ok(Self::MccOpaqueFwd),
            T_CASCADE_BUILD => Ok(Self::CascadeBuild),
            T_CASCADE_REJECT => Ok(Self::CascadeReject),
            T_CASCADE_ABORT => Ok(Self::CascadeAbort),
            T_CASCADE_PROBE => Ok(Self::CascadeProbe),
            T_CASCADE_ACCEPT => Ok(Self::CascadeAccept),
            T_CASCADE_DATA => Ok(Self::CascadeData),
            T_CASCADE_BACK => Ok(Self::CascadeBack),
            T_CASCADE_CLOSE => Ok(Self::CascadeClose),
            T_LINK_FRAG => Ok(Self::LinkFrag),
            T_LOCAL_CONNECT => Ok(Self::LocalConnect),
            T_ERROR => Ok(Self::Error),
            _ => Err(ProtoError::UnknownMessageType),
        }
    }
}

/// Step 1 of 4-step MGMT hop handshake (`MGMT_INIT`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MgmtInit {
    pub t: String,
    pub sid: String,
    pub from: String,
    pub to: String,
    pub ni: String,
    pub ke: String,
}

/// Step 2 of 4-step MGMT hop handshake (`MGMT_INIT_RESP`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MgmtInitResp {
    pub t: String,
    pub sid: String,
    pub from: String,
    pub to: String,
    pub nr: String,
    pub ke: String,
}

/// Step 3 & Step 4 of 4-step MGMT hop handshake (`MGMT_AUTH` / `MGMT_AUTH_RESP`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MgmtAuth {
    pub t: String,
    pub sid: String,
    pub from: String,
    pub to: String,
    pub nonce: String,
    pub ct: String,
}

/// AES-256-GCM hop-encrypted wire envelope (`node_daemon.py::link_send`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecureEnvelope {
    pub t: String,
    pub sid: String,
    pub from: String,
    pub to: String,
    pub nonce: String,
    pub ct: String,
    #[serde(default)]
    pub meta: Value,
}

/// Plaintext protocol error message (`protocol.py::err`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub v: u32,
    pub t: String,
    pub code: String,
    pub msg: String,
    #[serde(default)]
    pub meta: Value,
}

impl ErrorEnvelope {
    /// Constructs a wire error envelope matching `protocol.py::err`.
    #[must_use]
    pub fn new(code: impl Into<String>, msg: impl Into<String>, meta: Option<Value>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            t: T_ERROR.to_owned(),
            code: code.into(),
            msg: msg.into(),
            meta: meta.unwrap_or_else(|| Value::Object(serde_json::Map::new())),
        }
    }
}
