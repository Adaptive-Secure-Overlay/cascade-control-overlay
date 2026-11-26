#![forbid(unsafe_code)]
//! Platform-agnostic safe TUN abstractions (`ChannelTun` for tests & Windows Wintun bridge,
//! `UnixFdTun` for Android `VpnService`, Linux `/dev/net/tun`, and macOS `utun`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};

/// Boxed future type for async [`TunDevice`] methods without external macro dependencies.
pub type TunFuture<'a, T> = Pin<Box<dyn Future<Output = std::io::Result<T>> + Send + 'a>>;

/// Abstract L3 IP packet TUN device consumed by [`crate::SplitWireGuardTunnel`].
pub trait TunDevice: Send + Sync + 'static {
    /// Reads one raw IPv4/IPv6 packet outbound from the local OS stack.
    fn read_packet<'a>(&'a self) -> TunFuture<'a, Vec<u8>>;

    /// Writes one decrypted inbound IPv4/IPv6 packet back into the local OS stack.
    fn write_packet<'a>(&'a self, packet: Vec<u8>) -> TunFuture<'a, ()>;
}

/// Safe in-memory TUN device backed by bounded Tokio channels.
///
/// Used by cross-platform 4-node E2E tests (zero root privileges) and by the Windows
/// `Wintun` bridge in `cco-ffi` where the host pushes/pulls raw IP frames safely.
pub struct ChannelTun {
    rx_from_app: Mutex<mpsc::Receiver<Vec<u8>>>,
    tx_to_app: mpsc::Sender<Vec<u8>>,
}

/// Application / OS-side handle paired with a [`ChannelTun`].
pub struct ChannelTunPeer {
    tx_to_tunnel: mpsc::Sender<Vec<u8>>,
    rx_from_tunnel: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl ChannelTun {
    /// Creates a connected `(tunnel_side, app_or_os_side)` pair of L3 packet channels.
    #[must_use]
    pub fn pair(capacity: usize) -> (Arc<Self>, ChannelTunPeer) {
        let cap = capacity.max(16);
        let (tx_to_tunnel, rx_from_app) = mpsc::channel(cap);
        let (tx_to_app, rx_from_tunnel) = mpsc::channel(cap);
        (
            Arc::new(Self {
                rx_from_app: Mutex::new(rx_from_app),
                tx_to_app,
            }),
            ChannelTunPeer {
                tx_to_tunnel,
                rx_from_tunnel: Mutex::new(rx_from_tunnel),
            },
        )
    }
}

impl ChannelTunPeer {
    /// Injects an outbound IP packet as if written by the local OS network stack.
    pub async fn send_outbound_ip(&self, ip_packet: Vec<u8>) -> std::io::Result<()> {
        self.tx_to_tunnel
            .send(ip_packet)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "channel_tun_closed"))
    }

    /// Non-blocking outbound IP packet push (used by synchronous FFI bridges such as Windows Wintun).
    pub fn try_send_outbound_ip(&self, ip_packet: Vec<u8>) -> std::io::Result<()> {
        self.tx_to_tunnel.try_send(ip_packet).map_err(|err| {
            let kind = match err {
                mpsc::error::TrySendError::Full(_) => std::io::ErrorKind::WouldBlock,
                mpsc::error::TrySendError::Closed(_) => std::io::ErrorKind::BrokenPipe,
            };
            std::io::Error::new(kind, "channel_tun_send_failed")
        })
    }

    /// Receives a decrypted inbound IP packet delivered from the remote peer over direct WG type 4.
    pub async fn recv_inbound_ip(&self) -> Option<Vec<u8>> {
        self.rx_from_tunnel.lock().await.recv().await
    }

    /// Non-blocking poll for a decrypted inbound IP packet (used by synchronous FFI bridges).
    pub fn try_recv_inbound_ip(&self) -> Option<Vec<u8>> {
        self.rx_from_tunnel
            .try_lock()
            .ok()
            .and_then(|mut rx| rx.try_recv().ok())
    }
}

impl TunDevice for ChannelTun {
    fn read_packet<'a>(&'a self) -> TunFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.rx_from_app
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "tun_closed"))
        })
    }

    fn write_packet<'a>(&'a self, packet: Vec<u8>) -> TunFuture<'a, ()> {
        Box::pin(async move {
            self.tx_to_app
                .send(packet)
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "tun_closed"))
        })
    }
}

/// Safe Unix TUN wrapper over an already-opened `OwnedFd` (Android `VpnService.detachFd()`,
/// Linux `/dev/net/tun` with `IFF_NO_PI`, or macOS `utun` with 4-byte PI header).
///
/// Uses zero `unsafe`: owns two cloned `std::fs::File` handles and bridges blocking fd I/O
/// through bounded async channels so Android's blocking TUN fd works out of the box.
#[cfg(unix)]
pub struct UnixFdTun {
    rx_outbound: Mutex<mpsc::Receiver<Vec<u8>>>,
    tx_inbound: mpsc::Sender<Vec<u8>>,
}

#[cfg(unix)]
impl UnixFdTun {
    /// Wraps a Unix TUN file descriptor.
    ///
    /// Set `has_pi_header = true` on macOS/BSD `utun` (4-byte AF_INET/AF_INET6 prefix),
    /// and `false` on Android `VpnService` and Linux `IFF_NO_PI`.
    pub fn from_owned_fd(
        fd: std::os::fd::OwnedFd,
        has_pi_header: bool,
    ) -> std::io::Result<Arc<Self>> {
        use std::io::{Read, Write};

        let mut reader_file = std::fs::File::from(fd);
        let mut writer_file = reader_file.try_clone()?;

        let (tx_outbound, rx_outbound) = mpsc::channel::<Vec<u8>>(256);
        let (tx_inbound, mut rx_inbound) = mpsc::channel::<Vec<u8>>(256);

        std::thread::Builder::new()
            .name("cco-tun-reader".to_owned())
            .spawn(move || {
                let mut buf = vec![0u8; 65_536];
                loop {
                    match reader_file.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let pkt = if has_pi_header {
                                if n <= 4 {
                                    continue;
                                }
                                buf[4..n].to_vec()
                            } else {
                                buf[..n].to_vec()
                            };
                            if tx_outbound.blocking_send(pkt).is_err() {
                                break;
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })?;

        std::thread::Builder::new()
            .name("cco-tun-writer".to_owned())
            .spawn(move || {
                while let Some(pkt) = rx_inbound.blocking_recv() {
                    if pkt.is_empty() {
                        continue;
                    }
                    let res = if has_pi_header {
                        let af_byte = match pkt[0] >> 4 {
                            4 => 2u8,  // AF_INET (macOS/BSD)
                            6 => 30u8, // AF_INET6 (macOS)
                            _ => continue,
                        };
                        let mut framed = Vec::with_capacity(4 + pkt.len());
                        framed.extend_from_slice(&[0, 0, 0, af_byte]);
                        framed.extend_from_slice(&pkt);
                        writer_file.write_all(&framed)
                    } else {
                        writer_file.write_all(&pkt)
                    };
                    if res.is_err() {
                        break;
                    }
                }
            })?;

        Ok(Arc::new(Self {
            rx_outbound: Mutex::new(rx_outbound),
            tx_inbound,
        }))
    }
}

#[cfg(unix)]
impl TunDevice for UnixFdTun {
    fn read_packet<'a>(&'a self) -> TunFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.rx_outbound.lock().await.recv().await.ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unix_tun_closed")
            })
        })
    }

    fn write_packet<'a>(&'a self, packet: Vec<u8>) -> TunFuture<'a, ()> {
        Box::pin(async move {
            self.tx_inbound
                .send(packet)
                .await
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "unix_tun_closed"))
        })
    }
}
