#if os(macOS)
import Darwin
import Foundation

/// Opens a native macOS userspace `utun` tunnel interface (requires root / `sudo` when running
/// outside a signed `NEPacketTunnelProvider` extension).
public enum UtunDevice {
    private static let utunControlName = "com.apple.net.utun_control"
    private static let ctlIocGInfo: UInt = 0xC064_4E03 // _IOWR('N', 3, struct ctl_info)
    private static let utunOptIfname: Int32 = 2

    public struct OpenedUtun {
        public let fd: Int32
        public let interfaceName: String
    }

    public static func open() throws -> OpenedUtun {
        let fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)
        guard fd >= 0 else {
            throw CcoFfiError(code: "utun_socket_failed_\(errno)")
        }

        var info = ctl_info()
        withUnsafeMutableBytes(of: &info.ctl_name) { dst in
            let bytes = Array(utunControlName.utf8)
            for idx in 0..<min(bytes.count, dst.count - 1) {
                dst[idx] = bytes[idx]
            }
        }

        if ioctl(fd, ctlIocGInfo, &info) != 0 {
            let err = errno
            close(fd)
            throw CcoFfiError(code: "utun_ioctl_failed_\(err)")
        }

        var addr = sockaddr_ctl()
        addr.sc_len = UInt8(MemoryLayout<sockaddr_ctl>.size)
        addr.sc_family = UInt8(AF_SYSTEM)
        addr.ss_sysaddr = UInt16(AF_SYS_CONTROL)
        addr.sc_id = info.ctl_id
        addr.sc_unit = 0 // kernel assigns next free utunN

        let connectRc = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                Darwin.connect(fd, saPtr, socklen_t(MemoryLayout<sockaddr_ctl>.size))
            }
        }
        if connectRc != 0 {
            let err = errno
            close(fd)
            throw CcoFfiError(code: "utun_connect_failed_\(err)")
        }

        var nameBuf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var nameLen = socklen_t(nameBuf.count)
        let optRc = getsockopt(fd, SYSPROTO_CONTROL, utunOptIfname, &nameBuf, &nameLen)
        let ifName = (optRc == 0) ? String(cString: nameBuf) : "utun"
        return OpenedUtun(fd: fd, interfaceName: ifName)
    }
}
#endif
