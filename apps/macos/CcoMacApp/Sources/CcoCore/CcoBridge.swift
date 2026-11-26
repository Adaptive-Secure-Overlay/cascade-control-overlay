import CCcoFfi
import Foundation

public struct CcoFfiError: Error, LocalizedError, Equatable {
    public let code: String

    public init(code: String) {
        self.code = code
    }

    public var errorDescription: String? {
        "CCO FFI error: \(code)"
    }
}

private struct FfiEnvelope<T: Decodable>: Decodable {
    let ok: Bool
    let data: T?
    let error: String?
}

public struct TrustStatus: Codable, Equatable {
    public let authenticated: Bool
    public let schema: String
    public let version: UInt64
    public let signerKeyId: String
    public let nodes: [String]
    public let sha256: String
    public let recovered: Bool

    enum CodingKeys: String, CodingKey {
        case authenticated
        case schema
        case version
        case signerKeyId = "signer_key_id"
        case nodes
        case sha256
        case recovered
    }
}

public struct TunnelStats: Codable, Equatable {
    public let state: String
    public let overlayHandshakeTx: UInt64
    public let overlayHandshakeRx: UInt64
    public let directHandshakeTx: UInt64
    public let directHandshakeRxDropped: UInt64
    public let directDataTx: UInt64
    public let directDataRx: UInt64
    public let directBytesTx: UInt64
    public let directBytesRx: UInt64
    public let handshakeMs: UInt64?
    public let selectedRouteHops: UInt8
    public let selectedX1: String?
    public let mccMode: String
    public let trustRegistryVersion: UInt64
    public let trustRegistrySha256: String
    public let lastErrorCode: String?

    public var controlPlaneInvariantHolds: Bool {
        directHandshakeTx == 0
    }

    enum CodingKeys: String, CodingKey {
        case state
        case overlayHandshakeTx = "overlay_handshake_tx"
        case overlayHandshakeRx = "overlay_handshake_rx"
        case directHandshakeTx = "direct_handshake_tx"
        case directHandshakeRxDropped = "direct_handshake_rx_dropped"
        case directDataTx = "direct_data_tx"
        case directDataRx = "direct_data_rx"
        case directBytesTx = "direct_bytes_tx"
        case directBytesRx = "direct_bytes_rx"
        case handshakeMs = "handshake_ms"
        case selectedRouteHops = "selected_route_hops"
        case selectedX1 = "selected_x1"
        case mccMode = "mcc_mode"
        case trustRegistryVersion = "trust_registry_version"
        case trustRegistrySha256 = "trust_registry_sha256"
        case lastErrorCode = "last_error_code"
    }
}

public struct SanitizedEvent: Codable, Equatable, Identifiable {
    public var id: String { "\(timestampMs)-\(code)-\(peer ?? "")" }
    public let timestampMs: UInt64
    public let level: String
    public let code: String
    public let peer: String?

    enum CodingKeys: String, CodingKey {
        case timestampMs = "timestamp_ms"
        case level
        case code
        case peer
    }
}

public struct AnalyticsSummary: Codable, Equatable {
    public let n: Int
    public let m: Int
    public let j: Int
    public let i2pRoutes: String
    public let f1Routes: String
    public let f3Routes: String
    public let f4Routes: String
    public let f1EntropyBits: Double
    public let f3EntropyBits: Double
    public let f4EntropyBits: Double
    public let f1CompromisePct: Double
    public let f3CompromisePct: Double
    public let f4CompromisePct: Double
    public let f1N50: Int?
    public let f3N50: Int?
    public let f4N50: Int?
    public let f4MonteCarloPct: Double?
    public let f4MonteCarloAbsError: Double?
    public let f4MonteCarloMs: Double?

    enum CodingKeys: String, CodingKey {
        case n, m, j
        case i2pRoutes = "i2p_routes"
        case f1Routes = "f1_routes"
        case f3Routes = "f3_routes"
        case f4Routes = "f4_routes"
        case f1EntropyBits = "f1_entropy_bits"
        case f3EntropyBits = "f3_entropy_bits"
        case f4EntropyBits = "f4_entropy_bits"
        case f1CompromisePct = "f1_compromise_pct"
        case f3CompromisePct = "f3_compromise_pct"
        case f4CompromisePct = "f4_compromise_pct"
        case f1N50 = "f1_n50"
        case f3N50 = "f3_n50"
        case f4N50 = "f4_n50"
        case f4MonteCarloPct = "f4_monte_carlo_pct"
        case f4MonteCarloAbsError = "f4_monte_carlo_abs_error"
        case f4MonteCarloMs = "f4_monte_carlo_ms"
    }
}

public enum CcoClient {
    public static let allowedMccModes = ["first", "window", "adaptive", "wait-all"]

    private static func takeString(_ ptr: UnsafeMutablePointer<CChar>?) -> String {
        guard let ptr else { return "" }
        defer { cco_string_free(ptr) }
        return String(cString: ptr)
    }

    private static func decodeEnvelope<T: Decodable>(_ raw: String) throws -> T {
        guard let data = raw.data(using: .utf8) else {
            throw CcoFfiError(code: "utf8_error")
        }
        let env = try JSONDecoder().decode(FfiEnvelope<T>.self, from: data)
        guard env.ok, let payload = env.data else {
            throw CcoFfiError(code: env.error ?? "unknown_ffi_error")
        }
        return payload
    }

    public static func version() -> String {
        takeString(cco_version())
    }

    public static func verifyTrustBundle(
        registryJson: String,
        rootJson: String,
        requiredNodes: [String]
    ) throws -> TrustStatus {
        let reqData = try JSONSerialization.data(withJSONObject: requiredNodes, options: [])
        guard let reqJson = String(data: reqData, encoding: .utf8) else {
            throw CcoFfiError(code: "invalid_required_nodes")
        }
        let raw = registryJson.withCString { regPtr in
            rootJson.withCString { rootPtr in
                reqJson.withCString { reqPtr in
                    takeString(cco_verify_trust_bundle(regPtr, rootPtr, reqPtr))
                }
            }
        }
        return try decodeEnvelope(raw)
    }

    public static func analyticsSummary(n: Int, m: Int, j: Int) throws -> AnalyticsSummary {
        guard n >= 3, m >= 0, j > 0 else {
            throw CcoFfiError(code: "invalid_analytics_parameters")
        }
        let raw = takeString(cco_analytics_summary(UInt32(n), UInt32(m), UInt32(j)))
        return try decodeEnvelope(raw)
    }

    public static func generateDemoProfileJson(localNode: String = "A", peerNode: String = "B") throws -> String {
        let raw = localNode.withCString { localPtr in
            peerNode.withCString { peerPtr in
                takeString(cco_generate_demo_bundle(localPtr, peerPtr))
            }
        }
        guard let rawData = raw.data(using: .utf8),
              let root = try JSONSerialization.jsonObject(with: rawData) as? [String: Any]
        else {
            throw CcoFfiError(code: "json_parse_error")
        }
        guard let ok = root["ok"] as? Bool, ok, let payload = root["data"] else {
            let err = (root["error"] as? String) ?? "demo_generation_failed"
            throw CcoFfiError(code: err)
        }
        let pretty = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        guard let str = String(data: pretty, encoding: .utf8) else {
            throw CcoFfiError(code: "utf8_error")
        }
        return str
    }

    public static func prepareTunnelStartConfig(
        profileJson: String,
        replayDbPath: String,
        mccMode: String,
        x1Fanout: Int,
        x2Fanout: Int,
        hasPiHeader: Bool,
        initiateHandshake: Bool = true
    ) throws -> String {
        guard allowedMccModes.contains(mccMode) else {
            throw CcoFfiError(code: "invalid_mcc_mode")
        }
        guard let data = profileJson.data(using: .utf8),
              var obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            throw CcoFfiError(code: "invalid_profile_json")
        }
        obj["replay_db_path"] = replayDbPath
        obj["mcc_mode"] = mccMode
        obj["x1_fanout"] = min(max(x1Fanout, 1), 8)
        obj["x2_fanout"] = min(max(x2Fanout, 1), 8)
        obj["ike_fanout"] = 1
        obj["has_pi_header"] = hasPiHeader
        obj["initiate_handshake"] = initiateHandshake
        let outData = try JSONSerialization.data(withJSONObject: obj, options: [])
        guard let str = String(data: outData, encoding: .utf8) else {
            throw CcoFfiError(code: "utf8_error")
        }
        return str
    }
}

public final class CcoTunnelSession {
    private let lock = NSLock()
    private var handle: OpaquePointer?

    private init(handle: OpaquePointer) {
        self.handle = handle
    }

    public static func startChannel(configJson: String) throws -> CcoTunnelSession {
        var errPtr: UnsafeMutablePointer<CChar>?
        let h = configJson.withCString { cfgPtr in
            cco_tunnel_start_channel(cfgPtr, &errPtr)
        }
        guard let h else {
            let code = errPtr.map { ptr -> String in
                defer { cco_string_free(ptr) }
                return String(cString: ptr)
            } ?? "tunnel_start_failed"
            throw CcoFfiError(code: code)
        }
        return CcoTunnelSession(handle: h)
    }

    public static func startWithUtunFd(configJson: String, tunFd: Int32) throws -> CcoTunnelSession {
        var errPtr: UnsafeMutablePointer<CChar>?
        let h = configJson.withCString { cfgPtr in
            cco_tunnel_start_fd(cfgPtr, tunFd, nil, nil, &errPtr)
        }
        guard let h else {
            let code = errPtr.map { ptr -> String in
                defer { cco_string_free(ptr) }
                return String(cString: ptr)
            } ?? "tunnel_start_failed"
            throw CcoFfiError(code: code)
        }
        return CcoTunnelSession(handle: h)
    }

    @discardableResult
    public func initiateHandshake() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return false }
        return cco_tunnel_initiate(handle) == 0
    }

    public func pushOutboundIp(_ packet: Data) -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return -1 }
        return packet.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return cco_tunnel_push_outbound_ip(handle, base, packet.count)
        }
    }

    public func popInboundIp(maxBytes: Int = 65536) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return nil }
        var buf = Data(count: maxBytes)
        let n = buf.withUnsafeMutableBytes { rawBuf -> Int in
            guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return Int(cco_tunnel_pop_inbound_ip(handle, base, maxBytes))
        }
        guard n > 0 else { return nil }
        return buf.prefix(n)
    }

    public func stats() throws -> TunnelStats {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { throw CcoFfiError(code: "tunnel_stopped") }
        guard let ptr = cco_tunnel_stats(handle) else { throw CcoFfiError(code: "null_stats") }
        defer { cco_string_free(ptr) }
        let raw = String(cString: ptr)
        guard let data = raw.data(using: .utf8) else { throw CcoFfiError(code: "utf8_error") }
        let env = try JSONDecoder().decode(FfiEnvelope<TunnelStats>.self, from: data)
        guard env.ok, let payload = env.data else {
            throw CcoFfiError(code: env.error ?? "stats_error")
        }
        return payload
    }

    public func drainEvents() throws -> [SanitizedEvent] {
        lock.lock()
        defer { lock.unlock() }
        guard let handle else { return [] }
        guard let ptr = cco_tunnel_drain_events(handle) else { return [] }
        defer { cco_string_free(ptr) }
        let raw = String(cString: ptr)
        guard let data = raw.data(using: .utf8) else { throw CcoFfiError(code: "utf8_error") }
        let env = try JSONDecoder().decode(FfiEnvelope<[SanitizedEvent]>.self, from: data)
        guard env.ok, let payload = env.data else {
            throw CcoFfiError(code: env.error ?? "events_error")
        }
        return payload
    }

    public func stop() {
        lock.lock()
        let current = handle
        handle = nil
        lock.unlock()
        if let current {
            cco_tunnel_stop(current)
        }
    }

    deinit {
        stop()
    }
}
