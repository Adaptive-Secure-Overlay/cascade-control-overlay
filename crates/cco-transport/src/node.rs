#![forbid(unsafe_code)]
//! Asynchronous Tokio UDP overlay node with non-blocking MGMT session worker,
//! `LINK_FRAG` framing, and fail-closed `EndpointSecurity` trust gate.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cco_cascade::mcc::{
    EndpointSecurity, IkeInjectionOutcome, LocalDeliveryProof, MccAction, MccNodeConfig,
    MccNodeMachine,
};
use cco_proto::{
    ErrorEnvelope, LinkFragFrame, LinkFragReassembler, MessageType, MgmtAuth, MgmtInit,
    MgmtInitResp, SecureEnvelope, T_ERROR, T_LINK_FRAG, T_MGMT_AUTH, T_MGMT_AUTH_RESP, T_MGMT_INIT,
    T_MGMT_INIT_RESP, fragment_payload, jdump, jload,
};
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::config::NodeTransportConfig;
use crate::error::TransportError;
use crate::mgmt::{
    InitiatorHandshake, MgmtSession, PendingResponderHandshake, decrypt_link_envelope,
    encrypt_link_envelope, responder_handle_auth, responder_handle_init,
};

const MAX_PENDING_PER_PEER: usize = 64;

type PendingSendMap = HashMap<String, VecDeque<(MessageType, Vec<u8>)>>;

/// Local IKE injection boundary invoked when `MccNodeMachine` emits a single-use [`LocalDeliveryProof`].
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

    sessions: Mutex<HashMap<String, MgmtSession>>,
    pending_resp: Mutex<HashMap<String, PendingResponderHandshake>>,
    hs_init_waiters: Mutex<HashMap<String, oneshot::Sender<MgmtInitResp>>>,
    hs_auth_waiters: Mutex<HashMap<String, oneshot::Sender<MgmtAuth>>>,
    inflight_ensure: Mutex<HashMap<String, Arc<Notify>>>,
    pending_sends: Mutex<PendingSendMap>,
    reassembler: Mutex<LinkFragReassembler>,
    machine: Mutex<MccNodeMachine>,
    sink: Arc<dyn IkeSink>,
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

    /// Submits a local IKEv2 datagram (request or response) into the MCC overlay.
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

    /// Returns initiator route summary `(x1, opaque_token, context)` for `(dst, spi)`, if ready.
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
        let peer_ips: BTreeMap<String, std::net::Ipv4Addr> = config
            .peers
            .iter()
            .map(|(k, v)| (k.clone(), v.underlay_ip))
            .collect();
        let mcc_cfg = MccNodeConfig {
            peers: peer_ips,
            fanout: config.fanout,
            policy: config.policy.clone(),
            deterministic_seed: config.deterministic_seed,
        };
        let machine = MccNodeMachine::new(security, mcc_cfg)
            .map_err(|e| TransportError::Cascade(e.code()))?;

        // Bind UDP socket ONLY after Trust Registry v2 + EndpointSecurity + MccNodeMachine succeeded!
        let socket = UdpSocket::bind(config.bind_addr).await?;
        let local_addr = socket.local_addr()?;

        let mut addr_to_peer = HashMap::new();
        for (name, ep) in &config.peers {
            addr_to_peer.insert(ep.overlay_addr, name.clone());
        }

        let self_name = config.name.clone();
        let preconnect = config.preconnect;
        let preconnect_peers: Vec<String> = config
            .peers
            .keys()
            .filter(|p| p.as_str() != self_name.as_str())
            .cloned()
            .collect();

        let shared = Arc::new(SharedTransport {
            self_name: self_name.clone(),
            config,
            socket,
            addr_to_peer,
            sessions: Mutex::new(HashMap::new()),
            pending_resp: Mutex::new(HashMap::new()),
            hs_init_waiters: Mutex::new(HashMap::new()),
            hs_auth_waiters: Mutex::new(HashMap::new()),
            inflight_ensure: Mutex::new(HashMap::new()),
            pending_sends: Mutex::new(HashMap::new()),
            reassembler: Mutex::new(LinkFragReassembler::new(self_name)),
            machine: Mutex::new(machine),
            sink,
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
                                let packet = buf[..len].to_vec();
                                handle_udp_packet(Arc::clone(&shared_loop), packet, src).await;
                            }
                            Err(err) => {
                                // Windows UDP sockets can surface ICMP Port Unreachable as
                                // ConnectionReset (WSAECONNRESET 10054). Never crash the daemon.
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
                    }
                    cmd = cmd_rx.recv() => {
                        match cmd {
                            Some(ControlCommand::SendLocalIke { dst_user, payload, udp_port, reply }) => {
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

        info!(node = %shared.self_name, addr = %local_addr, "overlay node started");
        Ok(OverlayNodeHandle {
            local_addr,
            shared,
            cmd_tx,
        })
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

async fn send_peer_framed(
    shared: &SharedTransport,
    peer: &str,
    payload: &[u8],
) -> Result<(), TransportError> {
    if peer == shared.self_name {
        return Err(TransportError::UnknownPeer);
    }
    let addr = shared
        .config
        .peers
        .get(peer)
        .ok_or(TransportError::UnknownPeer)?
        .overlay_addr;
    let frames = fragment_payload(&shared.self_name, peer, payload)
        .map_err(|e| TransportError::Protocol(e.code()))?;
    for frame in frames {
        shared.socket.send_to(&frame, addr).await?;
    }
    Ok(())
}

/// Non-blocking 4-step MGMT handshake with deduplication across concurrent callers.
async fn ensure_session_async(
    shared: Arc<SharedTransport>,
    peer: &str,
) -> Result<(), TransportError> {
    if peer == shared.self_name || !shared.config.peers.contains_key(peer) {
        return Err(TransportError::UnknownPeer);
    }
    if shared.sessions.lock().await.contains_key(peer) {
        return Ok(());
    }

    // Check if another task is already negotiating with `peer`.
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
        let _ = tokio::time::timeout(wait_limit, notify.notified()).await;
        return if shared.sessions.lock().await.contains_key(peer) {
            Ok(())
        } else {
            Err(TransportError::MgmtHandshakeFailed)
        };
    }

    let timeout = Duration::from_millis(shared.config.udp_timeout_ms.max(100));
    let retries = shared.config.retries.max(1);
    let mut established = false;

    for _attempt in 0..retries {
        if shared.sessions.lock().await.contains_key(peer) {
            established = true;
            break;
        }
        let Ok((hs, init_wire)) = InitiatorHandshake::start(&shared.self_name, peer) else {
            break;
        };
        let sid = hs.sid.clone();
        let (init_tx, init_rx) = oneshot::channel();
        let (auth_tx, auth_rx) = oneshot::channel();
        {
            shared
                .hs_init_waiters
                .lock()
                .await
                .insert(sid.clone(), init_tx);
            shared
                .hs_auth_waiters
                .lock()
                .await
                .insert(sid.clone(), auth_tx);
        }

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
        if send_peer_framed(&shared, peer, &auth_wire).await.is_err() {
            cleanup_hs_waiters(&shared, &sid).await;
            continue;
        }

        let Ok(Ok(auth_resp)) = tokio::time::timeout(timeout, auth_rx).await else {
            cleanup_hs_waiters(&shared, &sid).await;
            continue;
        };

        if let Ok(session) = hs.finish_auth_resp(&shared.self_name, kd, &auth_resp) {
            shared
                .sessions
                .lock()
                .await
                .insert(peer.to_owned(), session);
            cleanup_hs_waiters(&shared, &sid).await;
            established = true;
            break;
        }
        cleanup_hs_waiters(&shared, &sid).await;
    }

    // Wake any tasks waiting on this session and flush queued messages!
    if let Some(notify) = shared.inflight_ensure.lock().await.remove(peer) {
        notify.notify_waiters();
    }

    if established {
        flush_pending_sends(Arc::clone(&shared), peer).await;
        Ok(())
    } else {
        shared.pending_sends.lock().await.remove(peer);
        Err(TransportError::MgmtHandshakeFailed)
    }
}

async fn cleanup_hs_waiters(shared: &SharedTransport, sid: &str) {
    shared.hs_init_waiters.lock().await.remove(sid);
    shared.hs_auth_waiters.lock().await.remove(sid);
}

async fn flush_pending_sends(shared: Arc<SharedTransport>, peer: &str) {
    let queued = { shared.pending_sends.lock().await.remove(peer) };
    let Some(items) = queued else {
        return;
    };
    for (mtype, payload) in items {
        let maybe_wire = {
            let sessions = shared.sessions.lock().await;
            sessions
                .get(peer)
                .map(|sess| encrypt_link_envelope(sess, &shared.self_name, mtype, &payload, None))
        };
        if let Some(Ok(wire)) = maybe_wire {
            if let Err(err) = send_peer_framed(&shared, peer, &wire).await {
                warn!(peer, error = %err, "queued send after session establishment failed");
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
        sessions
            .get(peer)
            .map(|sess| encrypt_link_envelope(sess, &shared.self_name, mtype, &payload, None))
    };

    if let Some(wire_res) = maybe_wire {
        let wire = wire_res?;
        return send_peer_framed(&shared, peer, &wire).await;
    }

    // Non-blocking session establishment (fixes NO_SESSION_NEXT without blocking recv loop!)
    {
        let mut pending = shared.pending_sends.lock().await;
        let queue = pending.entry(peer.to_owned()).or_default();
        if queue.len() < MAX_PENDING_PER_PEER {
            queue.push_back((mtype, payload));
        }
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
                if let Err(err) =
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

async fn handle_udp_packet(shared: Arc<SharedTransport>, data: Vec<u8>, src: SocketAddr) {
    let Some(peer) = shared.addr_to_peer.get(&src).cloned() else {
        debug!(%src, "dropping packet from unknown udp peer");
        return;
    };
    let Ok(val) = jload(&data) else {
        return;
    };
    let Some(t_str) = val.get("t").and_then(Value::as_str) else {
        return;
    };

    if t_str == T_LINK_FRAG {
        let Ok(frame) = serde_json::from_value::<LinkFragFrame>(val) else {
            return;
        };
        let now_s = (now_ms() as f64) / 1000.0;
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
                    let _ = send_peer_framed(&shared, &peer, &resp_wire).await;
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
                            shared.sessions.lock().await.insert(peer.clone(), session);
                            let _ = send_peer_framed(&shared, &peer, &resp_wire).await;
                            flush_pending_sends(Arc::clone(&shared), &peer).await;
                        }
                        Err(_) => {
                            if let Ok(err_wire) =
                                jdump(&ErrorEnvelope::new("AUTH_FAIL", "mgmt auth failed", None))
                            {
                                let _ = send_peer_framed(&shared, &peer, &err_wire).await;
                            }
                        }
                    }
                }
            }
        }
        T_MGMT_AUTH_RESP => {
            if let Ok(resp2) = serde_json::from_value::<MgmtAuth>(val) {
                if let Some(tx) = shared.hs_auth_waiters.lock().await.remove(&resp2.sid) {
                    let _ = tx.send(resp2);
                }
            }
        }
        T_ERROR => {
            // Unauthenticated plaintext errors are ignored by the authenticated profile.
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
            let plain = {
                let mut sessions = shared.sessions.lock().await;
                let Some(sess) = sessions.get(&peer) else {
                    return;
                };
                match decrypt_link_envelope(sess, &shared.self_name, &env) {
                    Ok(pt) => pt,
                    Err(_) => {
                        if env.sid.is_empty() || sess.sid == env.sid {
                            sessions.remove(&peer);
                        }
                        return;
                    }
                }
            };
            let actions = shared
                .machine
                .lock()
                .await
                .on_inbound(&peer, mtype, &plain, now_ms());
            dispatch_actions(shared, actions).await;
        }
    }
}
