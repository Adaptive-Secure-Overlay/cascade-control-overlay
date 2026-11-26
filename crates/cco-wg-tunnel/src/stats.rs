#![forbid(unsafe_code)]
//! Live tunnel telemetry and sanitized event ring buffer (never stores keys or raw packet payloads).

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const MAX_EVENTS: usize = 256;

/// High-level lifecycle state of the split WireGuard tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelState {
    Disconnected,
    Starting,
    HandshakingViaMcc,
    ConnectedDirectData,
    Error,
}

/// Real-time proof and telemetry counters for the control/data split invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStats {
    pub state: TunnelState,
    /// WireGuard type 1/2/3 handshake packets transmitted through the MCC overlay (`A -> X1 -> X2 -> B`).
    pub overlay_handshake_tx: u64,
    /// WireGuard type 1/2/3 handshake packets received through the MCC overlay.
    pub overlay_handshake_rx: u64,
    /// WireGuard type 1/2/3 packets sent directly between endpoints (INVARIANT: ALWAYS 0!).
    pub direct_handshake_tx: u64,
    /// Unsolicited WireGuard type 1/2/3 packets dropped on the direct UDP socket.
    pub direct_handshake_rx_dropped: u64,
    /// WireGuard type 4 encrypted transport packets sent directly (`A <-> B`).
    pub direct_data_tx: u64,
    /// WireGuard type 4 encrypted transport packets received directly (`A <-> B`).
    pub direct_data_rx: u64,
    /// Direct encrypted data bytes transmitted (`A -> B`).
    pub direct_bytes_tx: u64,
    /// Direct encrypted data bytes received (`B -> A`).
    pub direct_bytes_rx: u64,
    /// Elapsed milliseconds for the initial overlay WireGuard handshake, once established.
    pub handshake_ms: Option<u64>,
    /// Number of hops in the MCC overlay control route (`4` for `A -> X1 -> X2 -> B`).
    pub selected_route_hops: u8,
    /// Selected first-hop relay `X1` (`X2` remains strictly hidden from initiator `A`).
    pub selected_x1: Option<String>,
    /// Active MCC branch selection mode (`first`, `window`, `adaptive`, `wait-all`).
    pub mcc_mode: String,
    /// Verified Trust Registry v2 monotonic version.
    pub trust_registry_version: u64,
    /// Verified Trust Registry v2 canonical SHA-256 digest.
    pub trust_registry_sha256: String,
    /// Last sanitized failure code, if any.
    pub last_error_code: Option<String>,
}

/// Log-safe telemetry event exposed to GUI clients (never carries key material or payloads).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedEvent {
    pub timestamp_ms: u64,
    pub level: String,
    pub code: String,
    pub peer: Option<String>,
}

/// Thread-safe stats + bounded sanitized event ring buffer.
pub(crate) struct TelemetryStore {
    stats: Mutex<TunnelStats>,
    events: Mutex<VecDeque<SanitizedEvent>>,
    handshake_started_ms: Mutex<Option<u64>>,
}

impl TelemetryStore {
    pub(crate) fn new(
        mcc_mode: String,
        trust_registry_version: u64,
        trust_registry_sha256: String,
    ) -> Self {
        Self {
            stats: Mutex::new(TunnelStats {
                state: TunnelState::Starting,
                overlay_handshake_tx: 0,
                overlay_handshake_rx: 0,
                direct_handshake_tx: 0,
                direct_handshake_rx_dropped: 0,
                direct_data_tx: 0,
                direct_data_rx: 0,
                direct_bytes_tx: 0,
                direct_bytes_rx: 0,
                handshake_ms: None,
                selected_route_hops: 4,
                selected_x1: None,
                mcc_mode,
                trust_registry_version,
                trust_registry_sha256,
                last_error_code: None,
            }),
            events: Mutex::new(VecDeque::with_capacity(MAX_EVENTS)),
            handshake_started_ms: Mutex::new(None),
        }
    }

    pub(crate) fn snapshot(&self) -> TunnelStats {
        self.stats
            .lock()
            .expect("telemetry stats mutex poisoned")
            .clone()
    }

    pub(crate) fn update(&self, f: impl FnOnce(&mut TunnelStats)) {
        let mut guard = self.stats.lock().expect("telemetry stats mutex poisoned");
        f(&mut guard);
    }

    pub(crate) fn mark_handshake_started(&self) {
        let mut started = self
            .handshake_started_ms
            .lock()
            .expect("handshake timestamp mutex poisoned");
        if started.is_none() {
            *started = Some(now_ms());
        }
        self.update(|s| {
            if s.state == TunnelState::Starting || s.state == TunnelState::Disconnected {
                s.state = TunnelState::HandshakingViaMcc;
            }
        });
    }

    pub(crate) fn mark_connected(&self, selected_x1: Option<String>) {
        let elapsed = self
            .handshake_started_ms
            .lock()
            .expect("handshake timestamp mutex poisoned")
            .map(|t0| now_ms().saturating_sub(t0));
        self.update(|s| {
            s.state = TunnelState::ConnectedDirectData;
            if s.handshake_ms.is_none() {
                s.handshake_ms = elapsed;
            }
            if selected_x1.is_some() {
                s.selected_x1 = selected_x1;
            }
        });
    }

    pub(crate) fn push_event(&self, level: &str, code: &str, peer: Option<&str>) {
        let mut q = self.events.lock().expect("telemetry events mutex poisoned");
        if q.len() >= MAX_EVENTS {
            q.pop_front();
        }
        q.push_back(SanitizedEvent {
            timestamp_ms: now_ms(),
            level: level.to_owned(),
            code: code.to_owned(),
            peer: peer.map(str::to_owned),
        });
    }

    pub(crate) fn drain_events(&self) -> Vec<SanitizedEvent> {
        let mut q = self.events.lock().expect("telemetry events mutex poisoned");
        q.drain(..).collect()
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
