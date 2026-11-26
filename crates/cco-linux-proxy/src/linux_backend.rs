#![deny(unsafe_code)]
//! Privileged Linux socket backend (`IP_TRANSPARENT`, `IP_FREEBIND`, `IP_RECVORIGDSTADDR`,
//! `SO_MARK`, `IP_HDRINCL` raw IPv4/UDP injection).
//!
//! `unsafe` is strictly isolated to minimal `libc` socket option and `recvmsg`/`sendto` wrappers.

#[cfg(target_os = "linux")]
mod imp {
    use std::io::IoSliceMut;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use cco_cascade::mcc::{DeliveryReceipt, IkeInjectionOutcome, LocalDeliveryProof};
    use cco_proto::is_ike_payload;
    use cco_transport::{IkeSink, OverlayNodeHandle};
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrIn, recvmsg};
    use tracing::{debug, info, warn};

    use crate::config::{CaptureSpec, IkeProxyConfig, ProxyError};
    use crate::packet::build_ipv4_udp_packet;

    /// Live Linux transparent IKEv2 capture/inject adapter implementing [`IkeSink`].
    pub struct LinuxIkeProxy {
        config: Arc<IkeProxyConfig>,
        running: Arc<AtomicBool>,
    }

    impl LinuxIkeProxy {
        /// Creates a new Linux proxy instance (call [`Self::start_capture`] after `OverlayNode::start`).
        #[must_use]
        pub fn new(config: IkeProxyConfig) -> Self {
            Self {
                config: Arc::new(config),
                running: Arc::new(AtomicBool::new(false)),
            }
        }

        /// Starts background capture threads for every configured UDP/500 and UDP/4500 redirect port.
        pub fn start_capture(&self, handle: OverlayNodeHandle) -> Result<(), ProxyError> {
            if self.running.swap(true, Ordering::SeqCst) {
                return Ok(());
            }
            for spec in &self.config.capture_specs {
                let fd = make_capture_socket(&self.config, spec)?;
                let cfg = Arc::clone(&self.config);
                let running = Arc::clone(&self.running);
                let spec_cloned = spec.clone();
                let node_handle = handle.clone();
                let rt = tokio::runtime::Handle::current();

                std::thread::Builder::new()
                    .name(format!("ike-cap-{}-{}", spec.ike_port, spec.capture_port))
                    .spawn(move || {
                        capture_loop(fd, cfg, spec_cloned, running, node_handle, rt);
                    })
                    .map_err(ProxyError::Io)?;
            }
            info!(
                node = %self.config.local_node,
                mark = format_args!("0x{:x}", self.config.socket_mark),
                specs = self.config.capture_specs.len(),
                "linux IKE proxy capture started"
            );
            Ok(())
        }

        /// Stops background capture loops.
        pub fn stop(&self) {
            self.running.store(false, Ordering::SeqCst);
        }

        /// Transparently injects a verified IKEv2 payload into local `strongSwan`/`charon`
        /// via a marked raw IPv4/UDP socket (`SO_MARK`, `IP_HDRINCL`).
        pub fn inject_to_charon(
            &self,
            payload: &[u8],
            remote_ip: Ipv4Addr,
            remote_port: u16,
            udp_port: u16,
        ) -> IkeInjectionOutcome {
            let local_ike_port = self.config.reverse_capture_port(udp_port);
            if local_ike_port == 4500 && !is_ike_payload(4500, payload) {
                warn!("refusing to inject non-IKE UDP/4500 payload");
                return IkeInjectionOutcome::Rejected;
            }
            let ip_id = (std::process::id() & 0xffff) as u16;
            let Ok(packet) = build_ipv4_udp_packet(
                remote_ip,
                remote_port,
                self.config.local_ip,
                local_ike_port,
                ip_id,
                payload,
            ) else {
                return IkeInjectionOutcome::Rejected;
            };

            let Ok(fd) = open_raw_marked_socket(self.config.socket_mark) else {
                return IkeInjectionOutcome::Rejected;
            };

            match raw_sendto_ipv4(
                fd.as_raw_fd(),
                &packet,
                self.config.local_ip,
                local_ike_port,
            ) {
                Ok(sent) if sent == packet.len() => {
                    info!(
                        len = payload.len(),
                        remote = %remote_ip,
                        remote_port,
                        local = %self.config.local_ip,
                        local_ike_port,
                        "RAW-INJECT delivered to local charon"
                    );
                    IkeInjectionOutcome::Sent
                }
                _ => IkeInjectionOutcome::Unknown,
            }
        }
    }

    impl IkeSink for LinuxIkeProxy {
        fn deliver(&self, proof: LocalDeliveryProof) -> (IkeInjectionOutcome, DeliveryReceipt) {
            let (payload, meta, receipt) = proof.consume();
            let Ok(remote_ip) = meta.ike_src_ip.parse::<Ipv4Addr>() else {
                return (IkeInjectionOutcome::Rejected, receipt);
            };
            let outcome =
                self.inject_to_charon(&payload, remote_ip, meta.ike_src_port, meta.udp_port);
            (outcome, receipt)
        }
    }

    fn capture_loop(
        fd: OwnedFd,
        config: Arc<IkeProxyConfig>,
        spec: CaptureSpec,
        running: Arc<AtomicBool>,
        handle: OverlayNodeHandle,
        rt: tokio::runtime::Handle,
    ) {
        let mut data_buf = vec![0u8; 65_535];
        let mut cmsg_buf = nix::cmsg_space!(libc::sockaddr_in);

        while running.load(Ordering::Relaxed) {
            let (bytes, orig_dst_ip) = {
                let mut iov = [IoSliceMut::new(&mut data_buf)];
                let recv_res = recvmsg::<SockaddrIn>(
                    fd.as_raw_fd(),
                    &mut iov,
                    Some(&mut cmsg_buf),
                    MsgFlags::empty(),
                );
                let msg = match recv_res {
                    Ok(m) => m,
                    Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
                    Err(err) => {
                        if running.load(Ordering::Relaxed) {
                            warn!(error = %err, port = spec.capture_port, "capture recvmsg failed");
                        }
                        break;
                    }
                };
                let mut orig_dst = Ipv4Addr::UNSPECIFIED;
                if let Ok(cmsgs) = msg.cmsgs() {
                    for cmsg in cmsgs {
                        if let ControlMessageOwned::Ipv4OrigDstAddr(sin) = cmsg {
                            orig_dst = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            break;
                        }
                    }
                }
                (msg.bytes, orig_dst)
            };
            if bytes == 0 {
                continue;
            }
            let payload = data_buf[..bytes].to_vec();
            if !is_ike_payload(spec.ike_port, &payload) {
                warn!(
                    port = spec.ike_port,
                    len = payload.len(),
                    "DROP non-IKE payload on capture socket (ESP must bypass proxy)"
                );
                continue;
            }

            let dst_user = config
                .peer_by_ip(orig_dst_ip)
                .map(str::to_owned)
                .or_else(|| spec.dst_user_hint.clone())
                .or_else(|| config.default_dst_user.clone());

            let Some(dst_user) = dst_user else {
                warn!(%orig_dst_ip, "cannot map captured IKE destination IP to peer");
                continue;
            };
            if dst_user == config.local_node {
                debug!("ignoring local-to-local captured packet");
                continue;
            }

            let h = handle.clone();
            let ike_port = spec.ike_port;
            rt.spawn(async move {
                if let Err(err) = h.send_local_ike(&dst_user, payload, ike_port).await {
                    warn!(dst_user, error = %err, "failed to dispatch captured IKE into overlay");
                }
            });
        }
    }

    #[allow(unsafe_code)]
    fn setsockopt_int(
        fd: libc::c_int,
        level: libc::c_int,
        name: libc::c_int,
        val: libc::c_int,
    ) -> Result<(), std::io::Error> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                (&val as *const libc::c_int).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(unsafe_code)]
    fn make_capture_socket(
        config: &IkeProxyConfig,
        spec: &CaptureSpec,
    ) -> Result<OwnedFd, ProxyError> {
        let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if raw_fd < 0 {
            return Err(ProxyError::Io(std::io::Error::last_os_error()));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        setsockopt_int(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
        let _ = setsockopt_int(fd.as_raw_fd(), libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1);
        if config.enable_tproxy {
            let _ = setsockopt_int(fd.as_raw_fd(), libc::SOL_IP, libc::IP_TRANSPARENT, 1);
            let _ = setsockopt_int(fd.as_raw_fd(), libc::SOL_IP, libc::IP_FREEBIND, 1);
        }

        // 500ms recv timeout so stop() exits cleanly without hanging.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 500_000,
        };
        let rc_to = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&tv as *const libc::timeval).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc_to < 0 {
            return Err(ProxyError::Io(std::io::Error::last_os_error()));
        }

        let bind_addr = SocketAddrV4::new(config.capture_bind, spec.capture_port);
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: bind_addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(bind_addr.ip().octets()),
            },
            sin_zero: [0; 8],
        };
        let rc_bind = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&sin as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if rc_bind < 0 {
            return Err(ProxyError::Io(std::io::Error::last_os_error()));
        }
        Ok(fd)
    }

    #[allow(unsafe_code)]
    fn open_raw_marked_socket(mark: u32) -> Result<OwnedFd, std::io::Error> {
        let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let _ = setsockopt_int(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            mark as libc::c_int,
        );
        let _ = setsockopt_int(fd.as_raw_fd(), libc::IPPROTO_IP, libc::IP_HDRINCL, 1);
        Ok(fd)
    }

    #[allow(unsafe_code)]
    fn raw_sendto_ipv4(
        fd: libc::c_int,
        packet: &[u8],
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> Result<usize, std::io::Error> {
        let sin = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: dst_port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dst_ip.octets()),
            },
            sin_zero: [0; 8],
        };
        let sent = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr().cast::<libc::c_void>(),
                packet.len(),
                0,
                (&sin as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::net::Ipv4Addr;

    use cco_cascade::mcc::{DeliveryReceipt, IkeInjectionOutcome, LocalDeliveryProof};
    use cco_transport::{IkeSink, OverlayNodeHandle};

    use crate::config::{IkeProxyConfig, ProxyError};

    /// Compile-time cross-platform stub allowing `cargo test --workspace` on Windows/macOS.
    #[derive(Debug)]
    pub struct LinuxIkeProxy {
        _config: IkeProxyConfig,
    }

    impl LinuxIkeProxy {
        /// Creates a non-Linux stub instance.
        #[must_use]
        pub fn new(config: IkeProxyConfig) -> Self {
            Self { _config: config }
        }

        /// Fails closed with [`ProxyError::UnsupportedPlatform`] on non-Linux hosts.
        pub fn start_capture(&self, _handle: OverlayNodeHandle) -> Result<(), ProxyError> {
            Err(ProxyError::UnsupportedPlatform)
        }

        /// No-op on non-Linux hosts.
        pub fn stop(&self) {}

        /// Always returns [`IkeInjectionOutcome::Rejected`] on non-Linux hosts.
        #[must_use]
        pub fn inject_to_charon(
            &self,
            _payload: &[u8],
            _remote_ip: Ipv4Addr,
            _remote_port: u16,
            _udp_port: u16,
        ) -> IkeInjectionOutcome {
            IkeInjectionOutcome::Rejected
        }
    }

    impl IkeSink for LinuxIkeProxy {
        fn deliver(&self, proof: LocalDeliveryProof) -> (IkeInjectionOutcome, DeliveryReceipt) {
            let (_payload, _meta, receipt) = proof.consume();
            (IkeInjectionOutcome::Rejected, receipt)
        }
    }
}

pub use imp::LinuxIkeProxy;
