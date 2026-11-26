#![forbid(unsafe_code)]
//! Asynchronous Tokio UDP overlay node with non-blocking MGMT session worker,
//! `LINK_FRAG` framing, fail-closed `EndpointSecurity` trust gate, and dual
//! control-plane routing (`mcc2` 2-hop MCC and arbitrary H-hop `UniversalCascade`).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cco_cascade::mcc::{
    DeliveredIkeMeta, EndpointSecurity, IkeInjectionOutcome, LocalDeliveryProof, MccAction,
    MccNodeConfig, MccNodeMachine, WG_OVERLAY_CONTROL_PORT,
};
use cco_cascade::universal::{CascadeAction, CascadeCounts, RelayKnowledge, UniversalCascade};
use cco_crypto::{Key256, sha256_hex};
use cco_proto::{
    ErrorEnvelope, IKE_SA_INIT, LinkFragFrame, LinkFragReassembler, MessageType, MgmtAuth,
    MgmtInit, MgmtInitResp, SecureEnvelope, T_ERROR, T_LINK_FRAG, T_MGMT_AUTH, T_MGMT_AUTH_RESP,
    T_MGMT_INIT, T_MGMT_INIT_RESP, WireGuardMessageType, fragment_payload, jdump, jload,
    parse_ikev2_packet, parse_wireguard_packet_rfc,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::config::{NodeTransportConfig, RouteMode};
use crate::error::TransportError;
use crate::mgmt::{
    InitiatorHandshake, MgmtSession, PendingResponderHandshake, decrypt_link_envelope,
    encrypt_link_envelope, responder_handle_auth, responder_handle_init,
};

const MAX_PENDING_PER_PEER: usize = 512;
/// Minimum interval between unsolicited MGMT session-recovery handshakes per peer (DoS guard).
const SESSION_RECOVERY_COOLDOWN: Duration = Duration::from_millis(1_500);

type PendingSendMap = HashMap<String, VecDeque<(MessageType, Vec<u8>)>>;
type PendingInitAuth = (InitiatorHandshake, Key256, oneshot::Sender<bool>);

/// Live UDP and overlay protocol traffic counters for telemetry and benchmarks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCounters {
    pub udp_packets_tx: u64,
    pub udp_packets_rx: u64,
    pub udp_bytes_tx: u64,
    pub udp_bytes_rx: u64,
    pub cascade_msgs_tx: u64,
    pub cascade_msgs_rx: u64,
    pub mcc_msgs_tx: u64,
    pub mcc_msgs_rx: u64,
}

#[derive(Default)]
struct AtomicCounters {
    udp_packets_tx: AtomicU64,
    udp_packets_rx: AtomicU64,
    udp_bytes_tx: AtomicU64,
    udp_bytes_rx: AtomicU64,
    cascade_msgs_tx: AtomicU64,
    cascade_msgs_rx: AtomicU64,
    mcc_msgs_tx: AtomicU64,
    mcc_msgs_rx: AtomicU64,
}

impl AtomicCounters {
    fn snapshot(&self) -> TransportCounters {
        TransportCounters {
            udp_packets_tx: self.udp_packets_tx.load(Ordering::Relaxed),
            udp_packets_rx: self.udp_packets_rx.load(Ordering::Relaxed),
            udp_bytes_tx: self.udp_bytes_tx.load(Ordering::Relaxed),
            udp_bytes_rx: self.udp_bytes_rx.load(Ordering::Relaxed),
            cascade_msgs_tx: self.cascade_msgs_tx.load(Ordering::Relaxed),
            cascade_msgs_rx: self.cascade_msgs_rx.load(Ordering::Relaxed),
            mcc_msgs_tx: self.mcc_msgs_tx.load(Ordering::Relaxed),
            mcc_msgs_rx: self.mcc_msgs_rx.load(Ordering::Relaxed),
        }
    }
}

/// Per-peer MGMT session slot retaining one previous session during rekey / crossing-init overlap.
struct PeerSessionSlot {
    active: MgmtSession,
    previous: Option<MgmtSession>,
}

impl PeerSessionSlot {
    fn new(session: MgmtSession) -> Self {
        Self {
            active: session,
            previous: None,
        }
    }

    fn install(&mut self, session: MgmtSession) {
        if self.active.sid == session.sid {
            self.active = session;
            return;
        }
        let prev = std::mem::replace(&mut self.active, session);
        self.previous = Some(prev);
    }

    fn decrypt(
        &self,
        self_name: &str,
        env: &SecureEnvelope,
    ) -> Result<Vec<u8>, (TransportError, bool)> {
        if env.sid.is_empty() || env.sid == self.active.sid {
            return decrypt_link_envelope(&self.active, self_name, env).map_err(|e| (e, true));
        }
        if let Some(ref prev) = self.previous {
            if env.sid == prev.sid {
                return decrypt_link_envelope(prev, self_name, env).map_err(|e| (e, false));
            }
        }
        Err((TransportError::Protocol("stale_session_id"), false))
    }
}

/// Local IKE/WG control injection boundary invoked when `MccNodeMachine` or `UniversalCascade`
/// emits a single-use [`LocalDeliveryProof`].
pub trait IkeSink: Send + Sync + 'static {
    /// Consumes the move-only proof and performs local delivery (e.g. via `cco-linux-proxy` or test sink).
    fn deliver(
        &self,
        proof: LocalDeliveryProof,
    ) -> (IkeInjectionOutcome, cco_cascade::mcc::DeliveryReceipt);
}

/// No-op rejecting sink used when running a pure relay node without local IKE injection.
#[derive(Debug, Default)]
pub struct RelayOnlySink;

impl IkeSink for RelayOnlySink {
    fn deliver(
        &self,
        proof: LocalDeliveryProof,
    ) -> (IkeInjectionOutcome, cco_cascade::mcc::DeliveryReceipt) {
        let (_payload, _meta, receipt) = proof.consume();
        (IkeInjectionOutcome::Rejected, receipt)
    }
}

struct SharedTransport {
    self_name: String,
    config: NodeTransportConfig,
    socket: UdpSocket,
    addr_to_peer: HashMap<SocketAddr, String>,
    /// Live peer UDP endpoints; updated only after cryptographic MGMT/AEAD authentication
    /// to support clients behind NAT / Docker bridge without enabling unauthenticated spoofing.
    peer_addrs: Mutex<HashMap<String, SocketAddr>>,

    sessions: Mutex<HashMap<String, PeerSessionSlot>>,
    pending_resp: Mutex<HashMap<String, PendingResponderHandshake>>,
    hs_init_waiters: Mutex<HashMap<String, oneshot::Sender<MgmtInitResp>>>,
    pending_init_auth: Mutex<HashMap<String, PendingInitAuth>>,
    inflight_ensure: Mutex<HashMap<String, Arc<Notify>>>,
    session_recovery_last: Mutex<HashMap<String, tokio::time::Instant>>,
    pending_sends: Mutex<PendingSendMap>,
    reassembler: Mutex<LinkFragReassembler>,
    machine: Mutex<MccNodeMachine>,
    cascade: Mutex<UniversalCascade>,
    sink: Arc<dyn IkeSink>,
    counters: AtomicCounters,
}

enum ControlCommand {
    SendLocalIke {
        dst_user: String,
        payload: Vec<u8>,
        udp_port: u16,
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    EnsureSession {
        peer: String,
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    SendRawSecure {
        peer: String,
        message_type: MessageType,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), TransportError>>,
    },
    Shutdown,
}

/// Handle to a running asynchronous [`OverlayNode`].
#[derive(Clone)]
pub struct OverlayNodeHandle {
    local_addr: SocketAddr,
    shared: Arc<SharedTransport>,
    cmd_tx: mpsc::Sender<ControlCommand>,
}

impl OverlayNodeHandle {
    /// Returns the actual bound UDP socket address (supports ephemeral `:0` ports in tests).
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns this node's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.shared.self_name
    }

    /// Returns live atomic UDP and overlay message counters.
    #[must_use]
    pub fn counters(&self) -> TransportCounters {
        self.shared.counters.snapshot()
    }

    /// Explicitly establishes (or awaits) the 4-step MGMT session with `peer`.
    pub async fn ensure_session(&self, peer: &str) -> Result<(), TransportError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::EnsureSession {
                peer: peer.to_owned(),
                reply: tx,
            })
            .await
            .map_err(|_| TransportError::NodeStopped)?;
        rx.await.map_err(|_| TransportError::NodeStopped)?
    }

    /// Submits a local IKEv2 datagram (request or response) into the configured overlay
    /// (`mcc2` or `cascade` H-hop engine).
    pub async fn send_local_ike(
        &self,
        dst_user: &str,
        payload: Vec<u8>,
        udp_port: u16,
    ) -> Result<(), TransportError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendLocalIke {
                dst_user: dst_user.to_owned(),
                payload,
                udp_port,
                reply: tx,
            })
            .await
            .map_err(|_| TransportError::NodeStopped)?;
        rx.await.map_err(|_| TransportError::NodeStopped)?
    }

    /// Submits a local WireGuard control-plane handshake (`type 1/2/3` ONLY) into the overlay.
    /// WireGuard `type 4` transport packets are rejected fail-closed in both `mcc2` and `cascade`.
    pub async fn send_local_wg_handshake(
        &self,
        dst_user: &str,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.send_local_ike(dst_user, payload, WG_OVERLAY_CONTROL_PORT)
            .await
    }

    /// Sends a hop-encrypted frame over an established MGMT session (used in wire-compat tests).
    pub async fn send_secure_message(
        &self,
        peer: &str,
        message_type: MessageType,
        payload: Vec<u8>,
    ) -> Result<(), TransportError> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(ControlCommand::SendRawSecure {
                peer: peer.to_owned(),
                message_type,
                payload,
                reply: tx,
            })
            .await
            .map_err(|_| TransportError::NodeStopped)?;
        rx.await.map_err(|_| TransportError::NodeStopped)?
    }

    /// Checks whether an active MGMT session currently exists for `peer`.
    pub async fn has_session(&self, peer: &str) -> bool {
        self.shared.sessions.lock().await.contains_key(peer)
    }

    /// Returns the active MGMT session identifier (`sid`) for `peer`, if established.
    pub async fn active_session_id(&self, peer: &str) -> Option<String> {
        self.shared
            .sessions
            .lock()
            .await
            .get(peer)
            .map(|slot| slot.active.sid.clone())
    }

    /// Returns initiator route summary `(x1, opaque_token, context)` for `(dst, spi)`, if ready (`mcc2`).
    pub async fn initiator_route_summary(
        &self,
        dst: &str,
        initiator_spi: [u8; 8],
    ) -> Option<(String, String, String)> {
        self.shared
            .machine
            .lock()
            .await
            .initiator_route_summary(dst, initiator_spi)
    }

    /// Returns active `UniversalCascade` state counts on this node.
    pub async fn cascade_counts(&self) -> CascadeCounts {
        self.shared.cascade.lock().await.local_counts(now_secs())
    }

    /// Returns role-limited relay knowledge visible to this node in `UniversalCascade`.
    pub async fn cascade_relay_knowledge(&self) -> Vec<RelayKnowledge> {
        self.shared.cascade.lock().await.relay_knowledge(now_secs())
    }

    /// Returns full diagnostic relay memory dump for negative leakage tests.
    pub async fn cascade_memory_debug(&self) -> Value {
        self.shared
            .cascade
            .lock()
            .await
            .inspect_relay_memory_debug()
    }

    /// Returns first hop `X1` known to initiator `A` for `dst` (`X2..Xm` remain unknown).
    pub async fn cascade_first_hop(&self, dst: &str) -> Option<String> {
        self.shared.cascade.lock().await.source_first_hop(dst)
    }

    /// Returns last hop `Xm` known to destination `B` for `src` (`X1..X(m-1)` remain unknown).
    pub async fn cascade_last_hop(&self, src: &str) -> Option<String> {
        self.shared.cascade.lock().await.endpoint_last_hop(src)
    }

    /// Closes an active source cascade route to `dst` (for multi-trial benchmarks and cleanup).
    pub async fn close_cascade_route(&self, dst: &str) {
        let actions = self.shared.cascade.lock().await.close_source_route(dst);
        if !actions.is_empty() {
            dispatch_cascade_actions(Arc::clone(&self.shared), actions).await;
        }
    }

    /// Cleanly shuts down the overlay node tasks.
    pub async fn shutdown(&self) {
        let _ = self.cmd_tx.send(ControlCommand::Shutdown).await;
    }
}

/// Asynchronous Tokio UDP overlay daemon.
pub struct OverlayNode;

impl OverlayNode {
    /// Starts an authenticated overlay node after verifying [`EndpointSecurity`] and Trust Registry v2.
    ///
    /// Notice: because `security: EndpointSecurity` requires a [`cco_trust::VerifiedRegistry`],
    /// this function enforces the fail-closed trust gate BEFORE binding the UDP socket.
    pub async fn start(
        config: NodeTransportConfig,
        security: EndpointSecurity,
        sink: Arc<dyn IkeSink>,
    ) -> Result<OverlayNodeHandle, TransportError> {
        if config.route_mode == RouteMode::Cascade {
            if config.cascade.hops < 2 || config.cascade.hops > config.cascade.max_hops {
                return Err(TransportError::Cascade("invalid_hop_count"));
            }
            if config.cascade.parallel_chains == 0
                || config.cascade.parallel_chains > cco_cascade::universal::MAX_PARALLEL_CHAINS
            {
                return Err(TransportError::Cascade("invalid_parallel_chains"));
            }
        }

        let peer_ips: BTreeMap<String, std::net::Ipv4Addr> = config
            .peers
            .iter()
            .map(|(k, v)| (k.clone(), v.underlay_ip))
            .collect();
        let members: Vec<String> = config.peers.keys().cloned().collect();

        // Build authenticated UniversalCascade identity (X25519 + Ed25519) before moving `security`.
        let cascade_id = security
            .build_cascade_identity()
            .map_err(|e| TransportError::Cascade(e.code()))?;
        let cascade = UniversalCascade::new_with_model(
            cascade_id,
            members,
            config.cascade.max_hops.max(config.cascade.hops).max(2),
            config.cascade.route_ttl_secs,
            config.cascade.hop_model,
            None,
        )
        .map_err(|e| TransportError::Cascade(e.code()))?;

        let mcc_cfg = MccNodeConfig {
            peers: peer_ips,
            fanout: config.fanout,
            policy: config.policy.clone(),
            deterministic_seed: config.deterministic_seed,
        };
        let machine = MccNodeMachine::new(security, mcc_cfg)
            .map_err(|e| TransportError::Cascade(e.code()))?;

        // Bind UDP socket ONLY after Trust Registry v2 + EndpointSecurity + state machines succeeded!
        let socket = bind_sized_udp_socket(config.bind_addr, config.socket_protector.as_deref())?;
        let local_addr = socket.local_addr()?;

        let mut addr_to_peer = HashMap::new();
        let mut peer_addrs = HashMap::new();
        for (name, ep) in &config.peers {
            addr_to_peer.insert(ep.overlay_addr, name.clone());
            peer_addrs.insert(name.clone(), ep.overlay_addr);
        }

        let self_name = config.name.clone();
        let preconnect = config.preconnect;
        let preconnect_peers: Vec<String> = config
            .peers
            .keys()
            .filter(|p| {
                p.as_str() > self_name.as_str()
                    && !config.preconnect_exclude.iter().any(|ex| ex == *p)
            })
            .cloned()
            .collect();

        let shared = Arc::new(SharedTransport {
            self_name: self_name.clone(),
            config,
            socket,
            addr_to_peer,
            peer_addrs: Mutex::new(peer_addrs),
            sessions: Mutex::new(HashMap::new()),
            pending_resp: Mutex::new(HashMap::new()),
            hs_init_waiters: Mutex::new(HashMap::new()),
            pending_init_auth: Mutex::new(HashMap::new()),
            inflight_ensure: Mutex::new(HashMap::new()),
            session_recovery_last: Mutex::new(HashMap::new()),
            pending_sends: Mutex::new(HashMap::new()),
            reassembler: Mutex::new(LinkFragReassembler::new(self_name)),
            machine: Mutex::new(machine),
            cascade: Mutex::new(cascade),
            sink,
            counters: AtomicCounters::default(),
        });

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ControlCommand>(256);
        let shared_loop = Arc::clone(&shared);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            let mut ticker = tokio::time::interval(Duration::from_millis(50));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    recv_res = shared_loop.socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, src)) => {
                                shared_loop.counters.udp_packets_rx.fetch_add(1, Ordering::Relaxed);
                                shared_loop.counters.udp_bytes_rx.fetch_add(len as u64, Ordering::Relaxed);
                                let packet = buf[..len].to_vec();
                                handle_udp_packet(Arc::clone(&shared_loop), packet, src).await;
                            }
                            Err(err) => {
                                if err.kind() == std::io::ErrorKind::ConnectionReset {
                                    debug!("udp recv ignored connection reset");
                                    continue;
                                }
                                warn!(error = %err, "udp recv error");
                            }
                        }
                    }
                    _ = ticker.tick() => {
                        let actions = shared_loop.machine.lock().await.on_tick(now_ms());
                        if !actions.is_empty() {
                            dispatch_actions(Arc::clone(&shared_loop), actions).await;
                        }
                        shared_loop.cascade.lock().await.cleanup(now_secs());
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(ControlCommand::SendLocalIke { dst_user, payload, udp_port, reply }) => {
                                match shared_loop.config.route_mode {
                                    RouteMode::Mcc2 => {
                                        let res = {
                                            let mut m = shared_loop.machine.lock().await;
                                            m.send_local_ike(&dst_user, &payload, udp_port, now_ms())
                                        };
                                        match res {
                                            Ok(actions) => {
                                                dispatch_actions(Arc::clone(&shared_loop), actions).await;
                                                let _ = reply.send(Ok(()));
                                            }
                                            Err(e) => {
                                                let _ = reply.send(Err(TransportError::Cascade(e.code())));
                                            }
                                        }
                                    }
                                    RouteMode::Cascade => {
                                        let res = send_local_via_cascade(
                                            Arc::clone(&shared_loop),
                                            &dst_user,
                                            &payload,
                                            udp_port,
                                        )
                                        .await;
                                        let _ = reply.send(res);
                                    }
                                }
                            }
                            Some(ControlCommand::EnsureSession { peer, reply }) => {
                                let s = Arc::clone(&shared_loop);
                                tokio::spawn(async move {
                                    let res = ensure_session_async(s, &peer).await;
                                    let _ = reply.send(res);
                                });
                            }
                            Some(ControlCommand::SendRawSecure { peer, message_type, payload, reply }) => {
                                let s = Arc::clone(&shared_loop);
                                tokio::spawn(async move {
                                    let res = send_link_encrypted(s, &peer, message_type, payload).await;
                                    let _ = reply.send(res);
                                });
                            }
                            Some(ControlCommand::Shutdown) | None => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        if preconnect {
            for peer in preconnect_peers {
                let s = Arc::clone(&shared);
                tokio::spawn(async move {
                    let _ = ensure_session_async(s, &peer).await;
                });
            }
        }

        info!(
            node = %shared.self_name,
            addr = %local_addr,
            route_mode = shared.config.route_mode.as_str(),
            hops = shared.config.cascade.hops,
            hop_model = shared.config.cascade.hop_model.as_str(),
            parallel_chains = shared.config.cascade.parallel_chains,
            "overlay node started"
        );
        Ok(OverlayNodeHandle {
            local_addr,
            shared,
            cmd_tx,
        })
    }
}

async fn send_local_via_cascade(
    shared: Arc<SharedTransport>,
    dst_user: &str,
    payload: &[u8],
    udp_port: u16,
) -> Result<(), TransportError> {
    // Fail-closed protocol gate identical to MCC: ONLY IKEv2 or WG Type 1/2/3 permitted!
    let (is_response, is_initial_exchange) = if udp_port == WG_OVERLAY_CONTROL_PORT {
        let parsed = parse_wireguard_packet_rfc(payload)
            .map_err(|_| TransportError::Cascade("invalid_wg_packet"))?;
        if !parsed.is_handshake_control() {
            return Err(TransportError::Cascade("wg_transport_forbidden_in_overlay"));
        }
        (
            parsed.message_type != WireGuardMessageType::HandshakeInitiation,
            parsed.message_type == WireGuardMessageType::HandshakeInitiation,
        )
    } else {
        let hdr = parse_ikev2_packet(udp_port, payload)
            .map_err(|_| TransportError::Cascade("invalid_ike_packet"))?;
        (
            hdr.is_response(),
            !hdr.is_response() && hdr.exchange_type == IKE_SA_INIT && hdr.message_id == 0,
        )
    };

    let mut meta = Map::new();
    meta.insert("udp_port".to_owned(), json!(udp_port));
    meta.insert(
        "proto".to_owned(),
        json!(if udp_port == WG_OVERLAY_CONTROL_PORT {
            "wg"
        } else {
            "ikev2"
        }),
    );

    let now_s = now_secs();
    let hops = shared.config.cascade.hops;
    let k_chains = shared.config.cascade.parallel_chains;

    let actions = {
        let mut uc = shared.cascade.lock().await;
        if is_response {
            if uc.has_endpoint_route(dst_user, now_s) {
                uc.send_reverse(dst_user, payload, meta, now_s)
            } else if uc.has_source_route(dst_user, false, now_s) {
                uc.send_forward(dst_user, payload, meta, now_s)
            } else {
                uc.start_parallel_chains(dst_user, hops, k_chains, payload, meta, now_s)
            }
        } else if uc.has_source_route(dst_user, false, now_s) && !is_initial_exchange {
            uc.send_forward(dst_user, payload, meta, now_s)
        } else if uc.has_source_route(dst_user, true, now_s) && udp_port == WG_OVERLAY_CONTROL_PORT
        {
            // Active route already open for WG rekey / follow-up handshake -> send forward.
            uc.send_forward(dst_user, payload, meta, now_s)
        } else {
            uc.start_parallel_chains(dst_user, hops, k_chains, payload, meta, now_s)
        }
    }
    .map_err(|e| TransportError::Cascade(e.code()))?;

    dispatch_cascade_actions(shared, actions).await;
    Ok(())
}

fn bind_sized_udp_socket(
    addr: SocketAddr,
    protector: Option<&(dyn Fn(i32) -> bool + Send + Sync)>,
) -> Result<UdpSocket, TransportError> {
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
            return Err(TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "vpn_socket_protect_failed",
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = protector;
    sock.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn now_secs() -> f64 {
    (now_ms() as f64) / 1000.0
}

async fn send_peer_framed_to(
    shared: &SharedTransport,
    peer: &str,
    payload: &[u8],
    override_addr: Option<SocketAddr>,
) -> Result<(), TransportError> {
    if peer == shared.self_name {
        return Err(TransportError::UnknownPeer);
    }
    let addr = match override_addr {
        Some(a) => a,
        None => {
            if let Some(&live) = shared.peer_addrs.lock().await.get(peer) {
                live
            } else {
                shared
                    .config
                    .peers
                    .get(peer)
                    .ok_or(TransportError::UnknownPeer)?
                    .overlay_addr
            }
        }
    };
    let frames = fragment_payload(&shared.self_name, peer, payload)
        .map_err(|e| TransportError::Protocol(e.code()))?;
    for frame in frames {
        shared.socket.send_to(&frame, addr).await?;
        shared
            .counters
            .udp_packets_tx
            .fetch_add(1, Ordering::Relaxed);
        shared
            .counters
            .udp_bytes_tx
            .fetch_add(frame.len() as u64, Ordering::Relaxed);
    }
    Ok(())
}

async fn send_peer_framed(
    shared: &SharedTransport,
    peer: &str,
    payload: &[u8],
) -> Result<(), TransportError> {
    send_peer_framed_to(shared, peer, payload, None).await
}

async fn update_authenticated_peer_addr(shared: &SharedTransport, peer: &str, src: SocketAddr) {
    let mut map = shared.peer_addrs.lock().await;
    if map.get(peer) != Some(&src) {
        info!(peer, %src, "updated authenticated NAT peer endpoint");
        map.insert(peer.to_owned(), src);
    }
}

async fn install_peer_session(shared: &SharedTransport, peer: &str, session: MgmtSession) {
    let mut sessions = shared.sessions.lock().await;
    if let Some(slot) = sessions.get_mut(peer) {
        slot.install(session);
    } else {
        sessions.insert(peer.to_owned(), PeerSessionSlot::new(session));
    }
    drop(sessions);
    if let Some(notify) = shared.inflight_ensure.lock().await.get(peer).cloned() {
        notify.notify_waiters();
    }
}

/// Non-blocking 4-step MGMT handshake with deduplication across concurrent callers.
async fn ensure_session_async(
    shared: Arc<SharedTransport>,
    peer: &str,
) -> Result<(), TransportError> {
    ensure_session_inner(shared, peer, false).await
}

/// Triggers a rate-limited MGMT session recovery (`MGMT_INIT -> MGMT_AUTH`) after receiving an
/// encrypted frame from a known peer whose session is missing or stale (e.g. after relay restart).
/// Never trusts unauthenticated plaintext `ERROR` frames and never drops an active session before
/// the replacement handshake completes cryptographically.
async fn trigger_rate_limited_session_recovery(
    shared: Arc<SharedTransport>,
    peer: &str,
    force_rekey: bool,
) {
    let now = tokio::time::Instant::now();
    {
        let mut rl = shared.session_recovery_last.lock().await;
        if let Some(&last) = rl.get(peer) {
            if now.duration_since(last) < SESSION_RECOVERY_COOLDOWN {
                debug!(
                    node = %shared.self_name,
                    peer,
                    "rate-limited MGMT session recovery trigger"
                );
                return;
            }
        }
        rl.insert(peer.to_owned(), now);
    }
    info!(
        node = %shared.self_name,
        peer,
        force_rekey,
        "initiating rate-limited MGMT session recovery for unknown/stale encrypted frame"
    );
    let peer_owned = peer.to_owned();
    tokio::spawn(async move {
        let _ = ensure_session_inner(shared, &peer_owned, force_rekey).await;
    });
}

async fn ensure_session_inner(
    shared: Arc<SharedTransport>,
    peer: &str,
    force_rekey: bool,
) -> Result<(), TransportError> {
    if peer == shared.self_name || !shared.config.peers.contains_key(peer) {
        return Err(TransportError::UnknownPeer);
    }
    let initial_sid = {
        let sessions = shared.sessions.lock().await;
        sessions.get(peer).map(|slot| slot.active.sid.clone())
    };
    if !force_rekey && initial_sid.is_some() {
        flush_pending_sends(Arc::clone(&shared), peer).await;
        return Ok(());
    }

    let maybe_waiter = {
        let mut inflight = shared.inflight_ensure.lock().await;
        if let Some(notify) = inflight.get(peer) {
            Some(Arc::clone(notify))
        } else {
            let notify = Arc::new(Notify::new());
            inflight.insert(peer.to_owned(), notify);
            None
        }
    };
    if let Some(notify) = maybe_waiter {
        let wait_limit = Duration::from_millis(
            shared
                .config
                .udp_timeout_ms
                .saturating_mul(shared.config.retries.max(1) as u64),
        );
        let ready = {
            let sessions = shared.sessions.lock().await;
            match sessions.get(peer) {
                Some(_) if !force_rekey => true,
                Some(slot) => initial_sid.as_deref() != Some(slot.active.sid.as_str()),
                None => false,
            }
        };
        if !ready {
            let _ = tokio::time::timeout(wait_limit, notify.notified()).await;
        }
        return if shared.sessions.lock().await.contains_key(peer) {
            flush_pending_sends(Arc::clone(&shared), peer).await;
            Ok(())
        } else {
            Err(TransportError::MgmtHandshakeFailed)
        };
    }

    let timeout = Duration::from_millis(shared.config.udp_timeout_ms.max(100));
    let retries = shared.config.retries.max(1);
    let mut established = false;

    for _attempt in 0..retries {
        let already_ready = {
            let sessions = shared.sessions.lock().await;
            match sessions.get(peer) {
                Some(_) if !force_rekey => true,
                Some(slot) => initial_sid.as_deref() != Some(slot.active.sid.as_str()),
                None => false,
            }
        };
        if already_ready {
            established = true;
            break;
        }
        let Ok((hs, init_wire)) = InitiatorHandshake::start(&shared.self_name, peer) else {
            break;
        };
        let sid = hs.sid.clone();
        let (init_tx, init_rx) = oneshot::channel();
        shared
            .hs_init_waiters
            .lock()
            .await
            .insert(sid.clone(), init_tx);

        if send_peer_framed(&shared, peer, &init_wire).await.is_err() {
            cleanup_hs_waiters(&shared, &sid).await;
            continue;
        }

        let Ok(Ok(init_resp)) = tokio::time::timeout(timeout, init_rx).await else {
            cleanup_hs_waiters(&shared, &sid).await;
            continue;
        };

        let Ok((kd, auth_wire)) = hs.process_init_resp(&shared.self_name, &init_resp) else {
            cleanup_hs_waiters(&shared, &sid).await;
            continue;
        };

        let (auth_done_tx, auth_done_rx) = oneshot::channel();
        shared
            .pending_init_auth
            .lock()
            .await
            .insert(sid.clone(), (hs, kd, auth_done_tx));

        if send_peer_framed(&shared, peer, &auth_wire).await.is_err() {
            cleanup_hs_waiters(&shared, &sid).await;
            continue;
        }

        match tokio::time::timeout(timeout, auth_done_rx).await {
            Ok(Ok(true)) => {
                cleanup_hs_waiters(&shared, &sid).await;
                established = true;
                break;
            }
            _ => {
                cleanup_hs_waiters(&shared, &sid).await;
            }
        }
    }

    if let Some(notify) = shared.inflight_ensure.lock().await.remove(peer) {
        notify.notify_waiters();
    }

    if established || shared.sessions.lock().await.contains_key(peer) {
        flush_pending_sends(Arc::clone(&shared), peer).await;
        Ok(())
    } else {
        shared.pending_sends.lock().await.remove(peer);
        Err(TransportError::MgmtHandshakeFailed)
    }
}

async fn cleanup_hs_waiters(shared: &SharedTransport, sid: &str) {
    shared.hs_init_waiters.lock().await.remove(sid);
    shared.pending_init_auth.lock().await.remove(sid);
}

async fn flush_pending_sends(shared: Arc<SharedTransport>, peer: &str) {
    loop {
        let queued = { shared.pending_sends.lock().await.remove(peer) };
        let Some(items) = queued else {
            return;
        };
        if items.is_empty() {
            return;
        }
        for (mtype, payload) in items {
            let maybe_wire = {
                let sessions = shared.sessions.lock().await;
                sessions.get(peer).map(|slot| {
                    encrypt_link_envelope(&slot.active, &shared.self_name, mtype, &payload, None)
                })
            };
            if let Some(Ok(wire)) = maybe_wire {
                if let Err(err) = send_peer_framed(&shared, peer, &wire).await {
                    warn!(peer, error = %err, "queued send after session establishment failed");
                }
            }
        }
    }
}

async fn send_link_encrypted(
    shared: Arc<SharedTransport>,
    peer: &str,
    mtype: MessageType,
    payload: Vec<u8>,
) -> Result<(), TransportError> {
    let maybe_wire = {
        let sessions = shared.sessions.lock().await;
        if let Some(slot) = sessions.get(peer) {
            Some(encrypt_link_envelope(
                &slot.active,
                &shared.self_name,
                mtype,
                &payload,
                None,
            ))
        } else {
            let mut pending = shared.pending_sends.lock().await;
            let queue = pending.entry(peer.to_owned()).or_default();
            if queue.len() < MAX_PENDING_PER_PEER {
                queue.push_back((mtype, payload));
            }
            None
        }
    };

    if let Some(wire_res) = maybe_wire {
        let wire = wire_res?;
        return send_peer_framed(&shared, peer, &wire).await;
    }

    let s = Arc::clone(&shared);
    let peer_owned = peer.to_owned();
    tokio::spawn(async move {
        let _ = ensure_session_async(s, &peer_owned).await;
    });
    Ok(())
}

async fn dispatch_actions(shared: Arc<SharedTransport>, actions: Vec<MccAction>) {
    let mut queue: VecDeque<MccAction> = actions.into_iter().collect();
    while let Some(action) = queue.pop_front() {
        match action {
            MccAction::Send {
                peer,
                message_type,
                payload,
            } => {
                shared.counters.mcc_msgs_tx.fetch_add(1, Ordering::Relaxed);
                if peer == shared.self_name {
                    let follow = shared.machine.lock().await.on_inbound(
                        &shared.self_name,
                        message_type,
                        &payload,
                        now_ms(),
                    );
                    queue.extend(follow);
                } else if let Err(err) =
                    send_link_encrypted(Arc::clone(&shared), &peer, message_type, payload).await
                {
                    warn!(peer, error = %err, "overlay send failed");
                }
            }
            MccAction::DeliverIke { proof } => {
                let (outcome, receipt) = shared.sink.deliver(*proof);
                let follow =
                    shared
                        .machine
                        .lock()
                        .await
                        .complete_delivery(receipt, outcome, now_ms());
                queue.extend(follow);
            }
            MccAction::Reject { code } => {
                warn!(node = %shared.self_name, code, "mcc rejected message");
            }
        }
    }
}

async fn dispatch_cascade_actions(shared: Arc<SharedTransport>, actions: Vec<CascadeAction>) {
    let mut queue: VecDeque<CascadeAction> = actions.into_iter().collect();
    while let Some(action) = queue.pop_front() {
        match action {
            CascadeAction::Send {
                peer,
                message_type,
                message,
            } => {
                shared
                    .counters
                    .cascade_msgs_tx
                    .fetch_add(1, Ordering::Relaxed);
                let Ok(bytes) = jdump(&message) else {
                    continue;
                };
                if let Err(err) =
                    send_link_encrypted(Arc::clone(&shared), &peer, message_type, bytes).await
                {
                    warn!(peer, error = %err, "cascade overlay send failed");
                    if let Ok(recovery) = shared.cascade.lock().await.handle_send_failure(
                        &peer,
                        message_type,
                        &message,
                        now_secs(),
                    ) {
                        queue.extend(recovery);
                    }
                }
            }
            CascadeAction::Deliver {
                direction,
                remote_peer,
                payload,
                metadata,
                local_route_ref,
            } => {
                let udp_port = metadata
                    .get("udp_port")
                    .and_then(Value::as_u64)
                    .unwrap_or(500) as u16;
                let remote_ip = shared
                    .config
                    .peers
                    .get(&remote_peer)
                    .map(|p| p.underlay_ip.to_string())
                    .unwrap_or_default();
                let local_ip = shared
                    .config
                    .peers
                    .get(&shared.self_name)
                    .map(|p| p.underlay_ip.to_string())
                    .unwrap_or_default();
                let (x1, x2) = {
                    let uc = shared.cascade.lock().await;
                    if direction == "back" {
                        (
                            uc.source_first_hop(&remote_peer).unwrap_or_default(),
                            String::new(),
                        )
                    } else {
                        (
                            String::new(),
                            uc.endpoint_last_hop(&remote_peer).unwrap_or_default(),
                        )
                    }
                };
                let meta = DeliveredIkeMeta {
                    src: remote_peer.clone(),
                    dst: shared.self_name.clone(),
                    x1,
                    x2,
                    conn_id: local_route_ref.clone(),
                    context: local_route_ref.clone(),
                    direction,
                    ike_src_ip: remote_ip,
                    ike_src_port: udp_port,
                    ike_dst_ip: local_ip,
                    ike_dst_port: udp_port,
                    udp_port,
                    opaque_token: local_route_ref.clone(),
                    expected_copies: shared.config.cascade.parallel_chains,
                    copy_id: 1,
                    message_key: format!("cascade:{local_route_ref}:{}", sha256_hex(&payload)),
                };
                let proof = LocalDeliveryProof::mint_cascade(payload, meta);
                let (_outcome, _receipt) = shared.sink.deliver(proof);
            }
            CascadeAction::RouteReady {
                remote_peer,
                local_route_ref,
                hops,
            } => {
                info!(
                    node = %shared.self_name,
                    remote_peer,
                    route_ref = %local_route_ref,
                    hops,
                    "universal cascade route active"
                );
            }
        }
    }
}

async fn handle_udp_packet(shared: Arc<SharedTransport>, data: Vec<u8>, src: SocketAddr) {
    let Ok(val) = jload(&data) else {
        return;
    };
    let peer = if let Some(p) = shared.addr_to_peer.get(&src) {
        p.clone()
    } else if let Some(from) = val.get("from").and_then(Value::as_str) {
        if from != shared.self_name && shared.config.peers.contains_key(from) {
            from.to_owned()
        } else {
            debug!(%src, from, "dropping packet from unknown udp peer");
            return;
        }
    } else {
        debug!(%src, "dropping packet from unknown udp peer");
        return;
    };
    let Some(t_str) = val.get("t").and_then(Value::as_str) else {
        return;
    };

    if t_str == T_LINK_FRAG {
        let Ok(frame) = serde_json::from_value::<LinkFragFrame>(val) else {
            return;
        };
        let now_s = now_secs();
        let assembled = shared
            .reassembler
            .lock()
            .await
            .ingest(&peer, &frame, now_s)
            .ok()
            .flatten();
        if let Some(full) = assembled {
            Box::pin(handle_udp_packet(shared, full, src)).await;
        }
        return;
    }

    match t_str {
        T_MGMT_INIT => {
            if let Ok(init) = serde_json::from_value::<MgmtInit>(val) {
                let sid = init.sid.clone();
                if let Ok((pending, resp_wire)) =
                    responder_handle_init(&shared.self_name, &peer, &init)
                {
                    shared.pending_resp.lock().await.insert(sid, pending);
                    let _ = send_peer_framed_to(&shared, &peer, &resp_wire, Some(src)).await;
                }
            }
        }
        T_MGMT_INIT_RESP => {
            if let Ok(resp) = serde_json::from_value::<MgmtInitResp>(val) {
                if let Some(tx) = shared.hs_init_waiters.lock().await.remove(&resp.sid) {
                    let _ = tx.send(resp);
                }
            }
        }
        T_MGMT_AUTH => {
            if let Ok(auth) = serde_json::from_value::<MgmtAuth>(val) {
                let maybe_pending = shared.pending_resp.lock().await.remove(&auth.sid);
                if let Some(pending) = maybe_pending {
                    match responder_handle_auth(&shared.self_name, &peer, pending, &auth) {
                        Ok((session, resp_wire)) => {
                            update_authenticated_peer_addr(&shared, &peer, src).await;
                            install_peer_session(&shared, &peer, session).await;
                            let _ =
                                send_peer_framed_to(&shared, &peer, &resp_wire, Some(src)).await;
                            flush_pending_sends(Arc::clone(&shared), &peer).await;
                        }
                        Err(_) => {
                            if let Ok(err_wire) =
                                jdump(&ErrorEnvelope::new("AUTH_FAIL", "mgmt auth failed", None))
                            {
                                let _ =
                                    send_peer_framed_to(&shared, &peer, &err_wire, Some(src)).await;
                            }
                        }
                    }
                }
            }
        }
        T_MGMT_AUTH_RESP => {
            if let Ok(resp2) = serde_json::from_value::<MgmtAuth>(val) {
                let maybe_pending = shared.pending_init_auth.lock().await.remove(&resp2.sid);
                if let Some((hs, kd, done_tx)) = maybe_pending {
                    match hs.finish_auth_resp(&shared.self_name, kd, &resp2) {
                        Ok(session) => {
                            update_authenticated_peer_addr(&shared, &peer, src).await;
                            install_peer_session(&shared, &peer, session).await;
                            let _ = done_tx.send(true);
                            flush_pending_sends(Arc::clone(&shared), &peer).await;
                        }
                        Err(_) => {
                            let _ = done_tx.send(false);
                        }
                    }
                }
            }
        }
        T_ERROR => {
            debug!(peer, "ignoring unauthenticated plaintext error frame");
        }
        other => {
            let Ok(mtype) = MessageType::from_str(other) else {
                return;
            };
            if !mtype.is_secure_hop_message() {
                return;
            }
            let Ok(env) = serde_json::from_value::<SecureEnvelope>(val) else {
                return;
            };
            let decrypt_result = {
                let sessions = shared.sessions.lock().await;
                match sessions.get(&peer) {
                    None => Err(false),
                    Some(slot) => match slot.decrypt(&shared.self_name, &env) {
                        Ok(pt) => Ok(pt),
                        Err((_, _is_active_sid)) => Err(true),
                    },
                }
            };
            let plain = match decrypt_result {
                Ok(pt) => pt,
                Err(had_session) => {
                    trigger_rate_limited_session_recovery(shared, &peer, had_session).await;
                    return;
                }
            };
            update_authenticated_peer_addr(&shared, &peer, src).await;

            if mtype.is_cascade_message() {
                shared
                    .counters
                    .cascade_msgs_rx
                    .fetch_add(1, Ordering::Relaxed);
                let Ok(msg_val) = jload(&plain) else {
                    return;
                };
                let res = {
                    shared
                        .cascade
                        .lock()
                        .await
                        .receive(&peer, mtype, &msg_val, "", now_secs())
                };
                match res {
                    Ok(actions) => dispatch_cascade_actions(shared, actions).await,
                    Err(err) => {
                        debug!(
                            node = %shared.self_name,
                            peer,
                            msg_type = mtype.as_str(),
                            code = err.code(),
                            "cascade rejected message"
                        );
                    }
                }
            } else {
                shared.counters.mcc_msgs_rx.fetch_add(1, Ordering::Relaxed);
                let actions =
                    shared
                        .machine
                        .lock()
                        .await
                        .on_inbound(&peer, mtype, &plain, now_ms());
                dispatch_actions(shared, actions).await;
            }
        }
    }
}
