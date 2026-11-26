#if os(macOS)
import Foundation
import NetworkExtension

/// Bridge between Apple's `NEPacketTunnelProvider` packet flow and the Rust `CcoTunnelSession`
/// channel engine, ready to be embedded inside a signed macOS Network Extension target.
public final class PacketTunnelAdapter {
    private let packetFlow: NEPacketTunnelFlow
    private var session: CcoTunnelSession?
    private let queue = DispatchQueue(label: "org.adaptivesecureoverlay.cco.ne.pump", qos: .userInitiated)
    private var running = false

    public init(packetFlow: NEPacketTunnelFlow) {
        self.packetFlow = packetFlow
    }

    public func start(configJson: String) throws {
        let tunnel = try CcoTunnelSession.startChannel(configJson: configJson)
        self.session = tunnel
        self.running = true
        readNextPacketsFromSystem()
        startInboundPump()
    }

    public func stop() {
        running = false
        session?.stop()
        session = nil
    }

    public func stats() throws -> TunnelStats {
        guard let session else { throw CcoFfiError(code: "tunnel_stopped") }
        return try session.stats()
    }

    private func readNextPacketsFromSystem() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, self.running, let session = self.session else { return }
            for pkt in packets {
                _ = session.pushOutboundIp(pkt)
            }
            self.readNextPacketsFromSystem()
        }
    }

    private func startInboundPump() {
        queue.async { [weak self] in
            while let self, self.running, let session = self.session {
                if let pkt = session.popInboundIp() {
                    let proto: NSNumber = (pkt.first.map { ($0 >> 4) == 6 } ?? false)
                        ? NSNumber(value: AF_INET6)
                        : NSNumber(value: AF_INET)
                    self.packetFlow.writePackets([pkt], withProtocols: [proto])
                } else {
                    Thread.sleep(forTimeInterval: 0.002)
                }
            }
        }
    }
}
#endif
