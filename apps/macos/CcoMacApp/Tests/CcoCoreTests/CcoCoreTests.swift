import CcoCore
import Foundation
import XCTest

final class CcoCoreTests: XCTestCase {
    func testVersionAndDissertationChapter3ControlValues() throws {
        XCTAssertFalse(CcoClient.version().isEmpty)

        // Exact control table from Chapter 3 (n=20, m=2, j=3): M1=4896, M3=6174, M4=6516
        let summary = try CcoClient.analyticsSummary(n: 20, m: 2, j: 3)
        XCTAssertEqual(summary.f1Routes, "4896")
        XCTAssertEqual(summary.f3Routes, "6174")
        XCTAssertEqual(summary.f4Routes, "6516")
        XCTAssertEqual(summary.i2pRoutes, "23970816")
        XCTAssertEqual(summary.f1EntropyBits, 12.257388, accuracy: 1e-4)
        XCTAssertEqual(summary.f3EntropyBits, 12.591990, accuracy: 1e-4)
        XCTAssertEqual(summary.f4EntropyBits, 12.669771, accuracy: 1e-4)
        XCTAssertNotNil(summary.f4MonteCarloPct)
    }

    func testDemoBundleTrustRegistryVerifiesAndRejectsTampering() throws {
        let profile = try CcoClient.generateDemoProfileJson(localNode: "A", peerNode: "B")
        let data = try XCTUnwrap(profile.data(using: .utf8))
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let regJson = try XCTUnwrap(obj["trust_registry_json"] as? String)
        let rootJson = try XCTUnwrap(obj["trust_root_json"] as? String)

        let status = try CcoClient.verifyTrustBundle(
            registryJson: regJson,
            rootJson: rootJson,
            requiredNodes: ["A", "X1", "X2", "B"]
        )
        XCTAssertTrue(status.authenticated)
        XCTAssertEqual(status.version, 1)

        let tampered = regJson.replacingOccurrences(of: "\"version\":1", with: "\"version\":999")
        XCTAssertThrowsError(
            try CcoClient.verifyTrustBundle(
                registryJson: tampered,
                rootJson: rootJson,
                requiredNodes: ["A", "X1", "X2", "B"]
            )
        )
    }

    func testPrepareTunnelStartConfigSetsUtunPiHeaderFlag() throws {
        let profile = try CcoClient.generateDemoProfileJson(localNode: "A", peerNode: "B")
        let cfg = try CcoClient.prepareTunnelStartConfig(
            profileJson: profile,
            replayDbPath: "/tmp/cco-replay.sqlite",
            mccMode: "adaptive",
            x1Fanout: 2,
            x2Fanout: 2,
            hasPiHeader: true
        )
        XCTAssertTrue(cfg.contains("\"has_pi_header\":true"))
        XCTAssertTrue(cfg.contains("\"mcc_mode\":\"adaptive\""))
    }
}
