#![deny(unsafe_code)]
//! Linux transparent UDP proxy backend for IKEv2 (`strongSwan`/`charon`) and WireGuard.
//!
//! Compiles cleanly on Windows/macOS via a safe fail-closed stub while providing the full
//! `IP_TRANSPARENT` / `IP_FREEBIND` / `IP_RECVORIGDSTADDR` / `SO_MARK` / `IP_HDRINCL`
//! raw-injection backend on Linux.

pub mod config;
pub mod linux_backend;
pub mod packet;

pub use config::{
    CaptureSpec, DEFAULT_CAPTURE_BASE_500, DEFAULT_CAPTURE_BASE_4500, DEFAULT_SOCKET_MARK,
    IkeProxyConfig, ProxyError,
};
pub use linux_backend::LinuxIkeProxy;
pub use packet::{
    build_ipv4_udp_packet, ipv4_header_checksum, render_nftables_rules, render_xfrm_bypass_script,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn raw_ipv4_udp_packet_checksum_and_fields_are_valid() {
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(192, 0, 2, 20);
        let payload = b"ikev2-test-payload";
        let pkt = build_ipv4_udp_packet(src, 500, dst, 500, 0x1234, payload).unwrap();

        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[9], 17); // UDP
        assert_eq!(&pkt[12..16], &src.octets());
        assert_eq!(&pkt[16..20], &dst.octets());
        // Valid IPv4 header verifies to 0x0000 checksum!
        assert_eq!(ipv4_header_checksum(&pkt[..20]), 0);
        // UDP ports & length
        assert_eq!(u16::from_be_bytes([pkt[20], pkt[21]]), 500);
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 500);
        assert_eq!(
            u16::from_be_bytes([pkt[24], pkt[25]]) as usize,
            8 + payload.len()
        );
        assert_eq!(&pkt[28..], payload);
    }

    #[test]
    fn nftables_and_xfrm_generators_contain_no_hardcoded_lab_ips_and_preserve_nonesp_filter() {
        let mut peers = BTreeMap::new();
        peers.insert("A".to_owned(), Ipv4Addr::new(192, 0, 2, 1));
        peers.insert("B".to_owned(), Ipv4Addr::new(192, 0, 2, 2));
        peers.insert("X1".to_owned(), Ipv4Addr::new(192, 0, 2, 3));
        peers.insert("X2".to_owned(), Ipv4Addr::new(192, 0, 2, 4));

        let cfg = IkeProxyConfig::from_peers(
            "A",
            peers,
            DEFAULT_CAPTURE_BASE_500,
            DEFAULT_CAPTURE_BASE_4500,
            DEFAULT_SOCKET_MARK,
        )
        .unwrap();

        let nft = render_nftables_rules(&cfg);
        assert!(nft.contains("priority -100; policy accept;"));
        assert!(nft.contains("meta mark 0x53 notrack"));
        assert!(nft.contains("meta mark 0x53 return"));
        assert!(nft.contains("@th,64,32 0x00000000 redirect to :15202"));
        assert!(nft.contains("ip daddr 192.0.2.2 udp dport 500 redirect to :15102"));
        assert!(!nft.contains("ip daddr 192.0.2.1 udp dport 500"));

        let xfrm = render_xfrm_bypass_script(&cfg, 9000, 1);
        assert!(xfrm.contains("src 192.0.2.1/32 dst 192.0.2.2/32 proto udp sport 9000 dport 9000 action allow priority 1"));
        assert!(!xfrm.contains("src 192.0.2.1/32 dst 192.0.2.1/32"));
    }
}
