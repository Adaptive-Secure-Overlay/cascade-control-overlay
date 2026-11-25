#![forbid(unsafe_code)]
//! MCC branch selection modes and configuration policy (`first`, `window`, `adaptive`, `wait-all`).

use std::collections::BTreeMap;

use cco_proto::CanonicalValue;
use serde::{Deserialize, Serialize};

use crate::error::CascadeError;

/// Receiver-side selection mode for equivalent MCC start copies (`mcc_auth.py`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionMode {
    /// Accept the first authenticated copy immediately.
    #[serde(rename = "first")]
    First,
    /// Collect authenticated copies for `window_ms` then randomly choose one.
    #[serde(rename = "window")]
    Window,
    /// Wait until `min_copies` arrive and `quiet_ms` elapses without new copies (capped by `deadline_ms`).
    #[serde(rename = "adaptive")]
    Adaptive,
    /// Wait until all `expected_copies` arrive or `deadline_ms` expires, then choose randomly.
    #[serde(rename = "wait-all")]
    WaitAll,
}

impl SelectionMode {
    /// Wire string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Window => "window",
            Self::Adaptive => "adaptive",
            Self::WaitAll => "wait-all",
        }
    }
}

/// Complete MCC receiver selection policy embedded into signed start requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionPolicy {
    pub mode: SelectionMode,
    pub window_ms: u64,
    pub deadline_ms: u64,
    pub min_copies: usize,
    pub quiet_ms: u64,
}

impl SelectionPolicy {
    /// Creates a `first` policy with standard defaults.
    #[must_use]
    pub const fn first(deadline_ms: u64) -> Self {
        Self {
            mode: SelectionMode::First,
            window_ms: 0,
            deadline_ms,
            min_copies: 3,
            quiet_ms: 150,
        }
    }

    /// Creates a `window` policy collecting copies for `window_ms`.
    #[must_use]
    pub const fn window(window_ms: u64, deadline_ms: u64) -> Self {
        Self {
            mode: SelectionMode::Window,
            window_ms,
            deadline_ms,
            min_copies: 3,
            quiet_ms: 150,
        }
    }

    /// Creates an `adaptive` policy with explicit `min_copies` and `quiet_ms`.
    #[must_use]
    pub const fn adaptive(min_copies: usize, quiet_ms: u64, deadline_ms: u64) -> Self {
        Self {
            mode: SelectionMode::Adaptive,
            window_ms: 0,
            deadline_ms,
            min_copies,
            quiet_ms,
        }
    }

    /// Creates a `wait-all` policy waiting for all expected copies up to `deadline_ms`.
    #[must_use]
    pub const fn wait_all(deadline_ms: u64) -> Self {
        Self {
            mode: SelectionMode::WaitAll,
            window_ms: 0,
            deadline_ms,
            min_copies: 3,
            quiet_ms: 150,
        }
    }

    /// Validates bounds matching `mcc_auth.py::_auth_policy_from_environment`.
    pub fn validate(&self) -> Result<(), CascadeError> {
        if self.window_ms > 120_000
            || !(100..=120_000).contains(&self.deadline_ms)
            || !(1..=64).contains(&self.min_copies)
            || self.quiet_ms > 120_000
        {
            return Err(CascadeError::new("invalid_selection_config"));
        }
        if self.mode == SelectionMode::Window && self.window_ms == 0 {
            return Err(CascadeError::new("unsupported_selection_mode"));
        }
        Ok(())
    }

    /// Converts into canonical JSON object representation matching Python `mcc_auth.py`.
    #[must_use]
    pub fn to_canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "deadline_ms".to_owned(),
            CanonicalValue::Int(self.deadline_ms as i64),
        );
        map.insert(
            "min_copies".to_owned(),
            CanonicalValue::Int(self.min_copies as i64),
        );
        map.insert(
            "mode".to_owned(),
            CanonicalValue::String(self.mode.as_str().to_owned()),
        );
        map.insert(
            "quiet_ms".to_owned(),
            CanonicalValue::Int(self.quiet_ms as i64),
        );
        map.insert(
            "window_ms".to_owned(),
            CanonicalValue::Int(self.window_ms as i64),
        );
        CanonicalValue::Object(map)
    }
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self::first(12_000)
    }
}
