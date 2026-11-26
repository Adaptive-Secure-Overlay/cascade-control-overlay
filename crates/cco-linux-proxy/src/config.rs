#![forbid(unsafe_code)]
//! Error types and configuration for the Linux transparent IKEv2 / WireGuard proxy backend.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use thiserror::Error;

/// Default Linux netfilter socket mark preventing capture loops (`0x53`).
pub const DEFAULT_SOCKET_MARK: u32 = 0x53;

/// Default base port for per-peer UDP/500 capture redirects.
pub const DEFAULT_CAPTURE_BASE_500: u16 = 15100;

/// Default base port for per-peer UDP/4500 capture redirects.
pub const DEFAULT_CAPTURE_BASE_4500: u16 = 15200;

/// Fail-closed proxy backend error.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// Operation requires Linux (`IP_TRANSPARENT`, `SO_MARK`, `SOCK_RAW`).
    #[error("unsupported_platform: Linux kernel required")]
    UnsupportedPlatform,

    /// Underlying OS socket error.
    #[error("socket_io_error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid IPv4/UDP header or payload length.
    #[error("invalid_packet: {0}")]
    InvalidPacket(&'static str),

    /// Unknown local or peer node mapping.
    #[error("unknown_peer")]
    UnknownPeer,
}

/// Capture socket binding specification mapping one local redirect port to `(ike_port, dst_hint)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSpec {
    /// Canonical IKE service port (`500` or `4500`).
    pub ike_port: u16,
    /// Local capture UDP port receiving `nftables` redirected packets.
    pub capture_port: u16,
    /// Optional peer name inferred from per-destination redirect port.
    pub dst_user_hint: Option<String>,
}

/// Configuration for the Linux transparent IKEv2 capture/inject adapter.
#[derive(Debug, Clone)]
pub struct IkeProxyConfig {
    /// Local node logical name.
    pub local_node: String,
    /// Local node underlay IPv4 address used by `strongSwan`/`charon`.
    pub local_ip: Ipv4Addr,
    /// Bind address for capture sockets (`0.0.0.0` or `127.0.0.1`).
    pub capture_bind: Ipv4Addr,
    /// Mapping of peer logical names to their underlay IPv4 addresses.
    pub peer_ips: BTreeMap<String, Ipv4Addr>,
    /// Capture port specifications.
    pub capture_specs: Vec<CaptureSpec>,
    /// Socket `SO_MARK` applied to raw injected packets (`0x53` by default).
    pub socket_mark: u32,
    /// Enable `IP_TRANSPARENT` + `IP_FREEBIND` on capture sockets (for TPROXY rules).
    pub enable_tproxy: bool,
    /// Optional fallback destination peer when `REDIRECT` hides `orig_dst` as `127.0.0.1`.
    pub default_dst_user: Option<String>,
}

impl IkeProxyConfig {
    /// Derives deterministic per-peer capture specs (`base_500 + idx`, `base_4500 + idx`)
    /// sorted alphabetically by peer name so both firewall generator and proxy match identically.
    pub fn from_peers(
        local_node: impl Into<String>,
        peer_ips: BTreeMap<String, Ipv4Addr>,
        base_500: u16,
        base_4500: u16,
        socket_mark: u32,
    ) -> Result<Self, ProxyError> {
        let local_node = local_node.into();
        let local_ip = *peer_ips.get(&local_node).ok_or(ProxyError::UnknownPeer)?;

        let mut capture_specs = Vec::new();
        for (idx, peer_name) in peer_ips.keys().enumerate() {
            if peer_name == &local_node {
                continue;
            }
            let offset = (idx + 1) as u16;
            capture_specs.push(CaptureSpec {
                ike_port: 500,
                capture_port: base_500.saturating_add(offset),
                dst_user_hint: Some(peer_name.clone()),
            });
            capture_specs.push(CaptureSpec {
                ike_port: 4500,
                capture_port: base_4500.saturating_add(offset),
                dst_user_hint: Some(peer_name.clone()),
            });
        }

        Ok(Self {
            local_node,
            local_ip,
            capture_bind: Ipv4Addr::UNSPECIFIED,
            peer_ips,
            capture_specs,
            socket_mark,
            enable_tproxy: false,
            default_dst_user: None,
        })
    }

    /// Resolves a peer logical name by underlay IPv4 address.
    #[must_use]
    pub fn peer_by_ip(&self, ip: Ipv4Addr) -> Option<&str> {
        self.peer_ips
            .iter()
            .find_map(|(name, &addr)| (addr == ip).then_some(name.as_str()))
    }

    /// Maps a capture port back to its canonical IKE port (`500` or `4500`).
    #[must_use]
    pub fn reverse_capture_port(&self, port: u16) -> u16 {
        self.capture_specs
            .iter()
            .find_map(|s| (s.capture_port == port).then_some(s.ike_port))
            .unwrap_or(port)
    }
}
