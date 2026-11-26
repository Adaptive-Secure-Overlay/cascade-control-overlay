#![forbid(unsafe_code)]
//! Split userspace WireGuard tunnel engine (`boringtun` Noise_IKpsk2 + `cco-cascade` MCC overlay).
//!
//! Enforces a strict process-level control/data split invariant:
//! - WireGuard types `1` (Initiation), `2` (Response), `3` (Cookie Reply) MUST traverse
//!   the authenticated MCC overlay (`A -> X1 -> X2 -> B`). They are NEVER sent on the
//!   direct UDP socket, and any unsolicited `type 1/2/3` arriving on the direct UDP socket
//!   is dropped fail-closed.
//! - WireGuard type `4` (Transport Data) MUST traverse the direct UDP socket (`A <-> B`)
//!   and is NEVER admitted into the MCC overlay.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey as WgPublicKey, StaticSecret as WgStaticSecret};
use cco_cascade::mcc::{
    DeliveryReceipt, EndpointSecurity, IkeInjectionOutcome, LocalDeliveryProof,
};
use cco_proto::{WireGuardMessageType, parse_wireguard_packet_rfc as parse_wireguard_packet};
use cco_transport::{
    IkeSink, NodeTransportConfig, OverlayNode, OverlayNodeHandle, SocketProtector,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::error::WgTunnelError;
use crate::stats::{SanitizedEvent, TelemetryStore, TunnelState, TunnelStats};
use crate::tun::TunDevice;

const WG_BUF_SIZE: usize = 65_536;

/// Complete configuration for one [`SplitWireGuardTunnel`] endpoint (`A` or `B`).
pub struct WgTunnelConfig {
    /// Logical peer node name in Trust Registry v2 and `overlay.peers` (e.g., `"B"`).
    pub peer_name: String,
    /// Local WireGuard static X25519 private key (32 bytes, zeroized on drop).
    pub wg_private_key: Zeroizing<[u8; 32]>,
    /// Remote peer WireGuard static X25519 public key (32 bytes).
    pub peer_wg_public_key: [u8; 32],
    /// Optional WireGuard preshared key (32 bytes, zeroized on drop).
    pub wg_preshared_key: Option<Zeroizing<[u8; 32]>>,
    /// Local UDP bind address for direct WireGuard `type 4` data packets (`:0` allowed in tests).
    pub direct_bind_addr: SocketAddr,
    /// Remote peer UDP address for direct WireGuard `type 4` data packets.
    pub peer_direct_addr: SocketAddr,
    /// Persistent keepalive interval in seconds (`None` disables automatic keepalive).
    pub persistent_keepalive_secs: Option<u16>,
    /// Underlying MCC overlay transport configuration (`A -> X1 -> X2 -> B`).
    pub overlay: NodeTransportConfig,
    /// Verified Trust Registry v2 version (for telemetry proof).
    pub trust_registry_version: u64,
    /// Verified Trust Registry v2 canonical SHA-256 hex digest (for telemetry proof).
    pub trust_registry_sha256: String,
}

struct SharedTunnel {
    peer_name: String,
    /// Dynamic direct UDP endpoint; updated only after Poly1305 AEAD verification of inbound Type 4.
    peer_direct_addr: StdMutex<SocketAddr>,
    tunn: StdMutex<Tunn>,
    direct_socket: UdpSocket,
    tun: Arc<dyn TunDevice>,
    telemetry: TelemetryStore,
    outbound_wg_tx: mpsc::Sender<Vec<u8>>,
}

struct WgOverlayControlSink {
    shared: Arc<SharedTunnel>,
    rt: tokio::runtime::Handle,
}

impl IkeSink for WgOverlayControlSink {
    fn deliver(&self, proof: LocalDeliveryProof) -> (IkeInjectionOutcome, DeliveryReceipt) {
        let (payload, meta, receipt) = proof.consume();
        let Ok(parsed) = parse_wireguard_packet(&payload) else {
            self.shared.telemetry.push_event(
                "warn",
                "rejected_invalid_wg_overlay",
                Some(&meta.src),
            );
            return (IkeInjectionOutcome::Rejected, receipt);
        };
        if parsed.is_transport() {
            // Defense-in-depth: WG type 4 must NEVER be accepted via the overlay.
            self.shared
                .telemetry
                .push_event("warn", "rejected_type4_in_overlay", Some(&meta.src));
            return (IkeInjectionOutcome::Rejected, receipt);
        }

        self.shared.telemetry.update(|s| {
            s.overlay_handshake_rx = s.overlay_handshake_rx.saturating_add(1);
            if s.state == TunnelState::Starting {
                s.state = TunnelState::HandshakingViaMcc;
            }
        });
        self.shared.telemetry.push_event(
            "info",
            match parsed.message_type {
                WireGuardMessageType::HandshakeInitiation => "overlay_rx_wg_type1",
                WireGuardMessageType::HandshakeResponse => "overlay_rx_wg_type2",
                WireGuardMessageType::CookieReply => "overlay_rx_wg_type3",
                WireGuardMessageType::TransportData => "rejected_type4_in_overlay",
            },
            Some(&self.shared.peer_name),
        );

        let selected_x1 = (!meta.x1.is_empty()).then_some(meta.x1);
        let (net_out, tun_out, session_established, _) =
            decapsulate_wg_into_queues(&self.shared.tunn, &payload);

        if session_established || parsed.message_type == WireGuardMessageType::HandshakeResponse {
            self.shared.telemetry.mark_connected(selected_x1);
            self.shared.telemetry.push_event(
                "info",
                "wg_session_established_via_mcc",
                Some(&self.shared.peer_name),
            );
        }

        for pkt in net_out {
            if self.shared.outbound_wg_tx.try_send(pkt).is_err() {
                self.shared.telemetry.push_event(
                    "warn",
                    "outbound_wg_queue_full",
                    Some(&self.shared.peer_name),
                );
            }
        }
        if !tun_out.is_empty() {
            let tun = Arc::clone(&self.shared.tun);
            self.rt.spawn(async move {
                for ip_pkt in tun_out {
                    let _ = tun.write_packet(ip_pkt).await;
                }
            });
        }

        (IkeInjectionOutcome::Sent, receipt)
    }
}

/// Handle to a running [`SplitWireGuardTunnel`].
#[derive(Clone)]
pub struct SplitTunnelHandle {
    direct_local_addr: SocketAddr,
    overlay_handle: OverlayNodeHandle,
    shared: Arc<SharedTunnel>,
    shutdown_tx: watch::Sender<bool>,
}

impl SplitTunnelHandle {
    /// Returns the actual bound local UDP address used for direct WireGuard `type 4` traffic.
    #[must_use]
    pub const fn direct_local_addr(&self) -> SocketAddr {
        self.direct_local_addr
    }

    /// Returns the actual bound local UDP address of the MCC overlay node.
    #[must_use]
    pub fn overlay_local_addr(&self) -> SocketAddr {
        self.overlay_handle.local_addr()
    }

    /// Borrows the underlying overlay transport handle (for traffic counters & cascade inspection).
    #[must_use]
    pub const fn overlay_handle(&self) -> &OverlayNodeHandle {
        &self.overlay_handle
    }

    /// Returns a snapshot of live tunnel telemetry and proof counters.
    #[must_use]
    pub fn stats(&self) -> TunnelStats {
        self.shared.telemetry.snapshot()
    }

    /// Drains accumulated sanitized telemetry events (never contains secrets or raw payloads).
    #[must_use]
    pub fn drain_events(&self) -> Vec<SanitizedEvent> {
        self.shared.telemetry.drain_events()
    }

    /// Proactively triggers a WireGuard `type 1` Handshake Initiation over the MCC overlay.
    pub async fn initiate_handshake(&self) -> Result<(), WgTunnelError> {
        let maybe_init = {
            let mut tunn = self
                .shared
                .tunn
                .lock()
                .expect("boringtun state mutex poisoned");
            let mut dst = vec![0u8; WG_BUF_SIZE];
            match tunn.format_handshake_initiation(&mut dst, false) {
                TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                TunnResult::Done => None,
                TunnResult::Err(_) => None,
                TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => None,
            }
        };
        if let Some(pkt) = maybe_init {
            self.shared.telemetry.mark_handshake_started();
            self.shared
                .outbound_wg_tx
                .send(pkt)
                .await
                .map_err(|_| WgTunnelError::Stopped)?;
        }
        Ok(())
    }

    /// Cleanly stops the split tunnel, direct socket loops, and underlying MCC overlay node.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.shared.telemetry.update(|s| {
            s.state = TunnelState::Disconnected;
        });
        self.shared
            .telemetry
            .push_event("info", "tunnel_stopped", Some(&self.shared.peer_name));
        self.overlay_handle.shutdown().await;
    }
}

/// Userspace WireGuard tunnel splitting control handshakes through MCC overlay and data directly.
pub struct SplitWireGuardTunnel;

impl SplitWireGuardTunnel {
    /// Starts a live split tunnel after verifying `security` (fail-closed Trust Registry v2 gate).
    pub async fn start(
        mut config: WgTunnelConfig,
        security: EndpointSecurity,
        tun: Arc<dyn TunDevice>,
    ) -> Result<SplitTunnelHandle, WgTunnelError> {
        if config.peer_name.is_empty()
            || !config.overlay.peers.contains_key(&config.peer_name)
            || config.peer_name == config.overlay.name
        {
            return Err(WgTunnelError::InvalidPeer);
        }

        // Security privacy invariant (`ov_ab == 0`): never initiate proactive direct MGMT
        // overlay sessions to the target VPN peer; all control-plane handshakes must traverse relays.
        if !config
            .overlay
            .preconnect_exclude
            .iter()
            .any(|p| p == &config.peer_name)
        {
            config
                .overlay
                .preconnect_exclude
                .push(config.peer_name.clone());
        }

        let static_secret = WgStaticSecret::from(*config.wg_private_key);
        let peer_public = WgPublicKey::from(config.peer_wg_public_key);
        let psk = config.wg_preshared_key.as_ref().map(|k| **k);

        let tunn = Tunn::new(
            static_secret,
            peer_public,
            psk,
            config.persistent_keepalive_secs,
            0,
            None,
        );

        let direct_socket = bind_direct_udp(
            config.direct_bind_addr,
            config.overlay.socket_protector.as_ref(),
        )?;
        let direct_local_addr = direct_socket.local_addr()?;

        let route_hops = match config.overlay.route_mode {
            cco_transport::RouteMode::Mcc2 => 2u8,
            cco_transport::RouteMode::Cascade => config.overlay.cascade.hops.min(255) as u8,
        };
        let telemetry = TelemetryStore::new(
            config.overlay.policy.mode.as_str().to_owned(),
            config.overlay.route_mode.as_str().to_owned(),
            config.overlay.cascade.hop_model.as_str().to_owned(),
            route_hops,
            config.overlay.cascade.parallel_chains,
            config.trust_registry_version,
            config.trust_registry_sha256,
        );
        telemetry.push_event("info", "tunnel_starting", Some(&config.peer_name));

        let (outbound_wg_tx, mut outbound_wg_rx) = mpsc::channel::<Vec<u8>>(512);
        let shared = Arc::new(SharedTunnel {
            peer_name: config.peer_name.clone(),
            peer_direct_addr: StdMutex::new(config.peer_direct_addr),
            tunn: StdMutex::new(tunn),
            direct_socket,
            tun,
            telemetry,
            outbound_wg_tx,
        });

        let sink = Arc::new(WgOverlayControlSink {
            shared: Arc::clone(&shared),
            rt: tokio::runtime::Handle::current(),
        });

        // Fail-closed trust gate enforced inside OverlayNode::start!
        let overlay_handle = OverlayNode::start(config.overlay, security, sink)
            .await
            .map_err(|e| WgTunnelError::Overlay(e.to_string()))?;

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Task 1: Outbound WireGuard dispatcher enforcing strict control/data split.
        {
            let shared_out = Arc::clone(&shared);
            let overlay_out = overlay_handle.clone();
            let mut stop_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        changed = stop_rx.changed() => {
                            if changed.is_err() || *stop_rx.borrow() {
                                break;
                            }
                        }
                        maybe_pkt = outbound_wg_rx.recv() => {
                            let Some(pkt) = maybe_pkt else { break };
                            route_wg_outbound(&shared_out, &overlay_out, pkt).await;
                        }
                    }
                }
            });
        }

        // Task 2: Outbound TUN IP packet reader -> boringtun encapsulate -> outbound_wg_tx.
        {
            let shared_tun = Arc::clone(&shared);
            let mut stop_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut dst = vec![0u8; WG_BUF_SIZE];
                loop {
                    tokio::select! {
                        changed = stop_rx.changed() => {
                            if changed.is_err() || *stop_rx.borrow() {
                                break;
                            }
                        }
                        read_res = shared_tun.tun.read_packet() => {
                            match read_res {
                                Ok(ip_pkt) if !ip_pkt.is_empty() => {
                                    let out = {
                                        let mut tunn = shared_tun.tunn.lock().expect("boringtun mutex poisoned");
                                        match tunn.encapsulate(&ip_pkt, &mut dst) {
                                            TunnResult::WriteToNetwork(wg_pkt) => Some(wg_pkt.to_vec()),
                                            TunnResult::Done => None,
                                            TunnResult::Err(err) => {
                                                debug!(?err, "boringtun encapsulate returned error");
                                                None
                                            }
                                            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => None,
                                        }
                                    };
                                    if let Some(wg_pkt) = out {
                                        if let Ok(parsed) = parse_wireguard_packet(&wg_pkt) {
                                            if parsed.is_handshake_control() {
                                                shared_tun.telemetry.mark_handshake_started();
                                            }
                                        }
                                        if shared_tun.outbound_wg_tx.send(wg_pkt).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(err) => {
                                    debug!(error = %err, "tun read loop exited");
                                    break;
                                }
                            }
                        }
                    }
                }
            });
        }

        // Task 3: Direct UDP socket receiver — STRICTLY WireGuard type 4 ONLY!
        {
            let shared_in = Arc::clone(&shared);
            let mut stop_rx = shutdown_rx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; WG_BUF_SIZE];
                loop {
                    tokio::select! {
                        changed = stop_rx.changed() => {
                            if changed.is_err() || *stop_rx.borrow() {
                                break;
                            }
                        }
                        recv_res = shared_in.direct_socket.recv_from(&mut buf) => {
                            match recv_res {
                                Ok((n, src)) if n > 0 => {
                                    let pkt = &buf[..n];
                                    let Ok(parsed) = parse_wireguard_packet(pkt) else {
                                        continue;
                                    };
                                    if parsed.is_handshake_control() {
                                        // HARD SECURITY INVARIANT: drop unsolicited direct WG handshakes!
                                        shared_in.telemetry.update(|s| {
                                            s.direct_handshake_rx_dropped =
                                                s.direct_handshake_rx_dropped.saturating_add(1);
                                        });
                                        shared_in.telemetry.push_event(
                                            "warn",
                                            "dropped_direct_wg_handshake",
                                            Some(&shared_in.peer_name),
                                        );
                                        continue;
                                    }

                                    let (net_out, tun_out, _, authenticated) =
                                        decapsulate_wg_into_queues(&shared_in.tunn, pkt);
                                    if authenticated {
                                        let mut addr_guard = shared_in
                                            .peer_direct_addr
                                            .lock()
                                            .expect("peer_direct_addr mutex poisoned");
                                        if *addr_guard != src {
                                            info!(peer = %shared_in.peer_name, %src, "updated authenticated WG direct NAT endpoint");
                                            *addr_guard = src;
                                        }
                                        shared_in.telemetry.update(|s| {
                                            s.direct_data_rx = s.direct_data_rx.saturating_add(1);
                                            s.direct_bytes_rx =
                                                s.direct_bytes_rx.saturating_add(n as u64);
                                            if s.state != TunnelState::ConnectedDirectData {
                                                s.state = TunnelState::ConnectedDirectData;
                                            }
                                        });
                                    } else {
                                        debug!(peer = %shared_in.peer_name, %src, len = n, "ignored unauthenticated/stale direct WG type 4 datagram");
                                    }

                                    for out_pkt in net_out {
                                        let _ = shared_in.outbound_wg_tx.try_send(out_pkt);
                                    }
                                    for ip_pkt in tun_out {
                                        if shared_in.tun.write_packet(ip_pkt).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                Ok(_) => {}
                                Err(err) if err.kind() == std::io::ErrorKind::ConnectionReset => {
                                    continue;
                                }
                                Err(err) => {
                                    warn!(error = %err, "direct wg udp recv error");
                                }
                            }
                        }
                    }
                }
            });
        }

        // Task 4: WireGuard timer tick (250ms) for handshake retransmit, rekey, and keepalive.
        {
            let shared_tmr = Arc::clone(&shared);
            let mut stop_rx = shutdown_rx;
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_millis(250));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut dst = vec![0u8; WG_BUF_SIZE];
                loop {
                    tokio::select! {
                        changed = stop_rx.changed() => {
                            if changed.is_err() || *stop_rx.borrow() {
                                break;
                            }
                        }
                        _ = ticker.tick() => {
                            let maybe_pkt = {
                                let mut tunn = shared_tmr.tunn.lock().expect("boringtun mutex poisoned");
                                match tunn.update_timers(&mut dst) {
                                    TunnResult::WriteToNetwork(pkt) => Some(pkt.to_vec()),
                                    _ => None,
                                }
                            };
                            if let Some(pkt) = maybe_pkt {
                                let _ = shared_tmr.outbound_wg_tx.try_send(pkt);
                            }
                        }
                    }
                }
            });
        }

        info!(
            peer = %shared.peer_name,
            direct_addr = %direct_local_addr,
            overlay_addr = %overlay_handle.local_addr(),
            "split userspace WireGuard tunnel started"
        );

        Ok(SplitTunnelHandle {
            direct_local_addr,
            overlay_handle,
            shared,
            shutdown_tx,
        })
    }
}

/// Strictly classifies every outbound WireGuard packet produced by `boringtun`:
/// - `type 1/2/3` -> MCC overlay (`A -> X1 -> X2 -> B`), NEVER direct UDP!
/// - `type 4` -> direct UDP (`A <-> B`), NEVER MCC overlay!
async fn route_wg_outbound(
    shared: &SharedTunnel,
    overlay_handle: &OverlayNodeHandle,
    pkt: Vec<u8>,
) {
    let Ok(parsed) = parse_wireguard_packet(&pkt) else {
        shared.telemetry.push_event(
            "warn",
            "dropped_malformed_outbound_wg",
            Some(&shared.peer_name),
        );
        return;
    };

    if parsed.is_handshake_control() {
        shared.telemetry.mark_handshake_started();
        shared.telemetry.update(|s| {
            s.overlay_handshake_tx = s.overlay_handshake_tx.saturating_add(1);
        });
        shared.telemetry.push_event(
            "info",
            match parsed.message_type {
                WireGuardMessageType::HandshakeInitiation => "overlay_tx_wg_type1",
                WireGuardMessageType::HandshakeResponse => "overlay_tx_wg_type2",
                WireGuardMessageType::CookieReply => "overlay_tx_wg_type3",
                WireGuardMessageType::TransportData => unreachable!(),
            },
            Some(&shared.peer_name),
        );
        if let Err(err) = overlay_handle
            .send_local_wg_handshake(&shared.peer_name, pkt)
            .await
        {
            shared.telemetry.update(|s| {
                s.last_error_code = Some("overlay_handshake_send_failed".to_owned());
            });
            shared.telemetry.push_event(
                "error",
                "overlay_handshake_send_failed",
                Some(&shared.peer_name),
            );
            warn!(peer = %shared.peer_name, error = %err, "failed to send WG handshake via MCC overlay");
        }
    } else {
        // WireGuard Type 4 Transport Data -> direct UDP A <-> B!
        let len = pkt.len() as u64;
        let peer_addr = *shared
            .peer_direct_addr
            .lock()
            .expect("peer_direct_addr mutex poisoned");
        match shared.direct_socket.send_to(&pkt, peer_addr).await {
            Ok(_) => {
                shared.telemetry.update(|s| {
                    s.direct_data_tx = s.direct_data_tx.saturating_add(1);
                    s.direct_bytes_tx = s.direct_bytes_tx.saturating_add(len);
                });
            }
            Err(err) => {
                shared.telemetry.update(|s| {
                    s.last_error_code = Some("direct_data_send_failed".to_owned());
                });
                warn!(peer = %shared.peer_name, error = %err, "direct WG type 4 send failed");
            }
        }
    }
}

fn decapsulate_wg_into_queues(
    tunn_mutex: &StdMutex<Tunn>,
    datagram: &[u8],
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, bool, bool) {
    let mut net_out = Vec::new();
    let mut tun_out = Vec::new();
    let mut session_established = false;
    let mut authenticated = false;
    let mut dst = vec![0u8; WG_BUF_SIZE];

    let mut tunn = tunn_mutex.lock().expect("boringtun mutex poisoned");
    match tunn.decapsulate(None, datagram, &mut dst) {
        TunnResult::WriteToNetwork(pkt) => {
            authenticated = true;
            if let Ok(parsed) = parse_wireguard_packet(pkt) {
                if parsed.is_transport() {
                    // Keepalive type 4 emitted immediately after completing handshake!
                    session_established = true;
                }
            }
            net_out.push(pkt.to_vec());
            // Drain any queued IP packets buffered while the handshake was in flight!
            while let TunnResult::WriteToNetwork(queued) = tunn.decapsulate(None, &[], &mut dst) {
                net_out.push(queued.to_vec());
            }
        }
        TunnResult::WriteToTunnelV4(ip, _) | TunnResult::WriteToTunnelV6(ip, _) => {
            authenticated = true;
            session_established = true;
            tun_out.push(ip.to_vec());
        }
        TunnResult::Done => {
            authenticated = true;
        }
        TunnResult::Err(_) => {}
    }

    (net_out, tun_out, session_established, authenticated)
}

fn bind_direct_udp(
    addr: SocketAddr,
    protector: Option<&SocketProtector>,
) -> Result<UdpSocket, WgTunnelError> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    sock.set_nonblocking(true)?;
    #[cfg(unix)]
    if let Some(protect_fn) = protector {
        use std::os::fd::AsRawFd;
        if !protect_fn(sock.as_raw_fd()) {
            return Err(WgTunnelError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "vpn_direct_socket_protect_failed",
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = protector;
    sock.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}
