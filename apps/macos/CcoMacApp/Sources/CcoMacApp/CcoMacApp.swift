import CcoCore
import Foundation
import SwiftUI

@MainActor
final class CcoViewModel: ObservableObject {
    @Published var coreVersion: String = CcoClient.version()
    @Published var profileJson: String?
    @Published var trustStatus: TrustStatus?
    @Published var trustError: String?
    @Published var mccMode: String = "adaptive"
    @Published var x1Fanout: Int = 2
    @Published var x2Fanout: Int = 2
    @Published var isRunning: Bool = false
    @Published var stats: TunnelStats?
    @Published var events: [SanitizedEvent] = []
    @Published var lastError: String?

    @Published var analyticsN: Int = 20
    @Published var analyticsM: Int = 2
    @Published var analyticsJ: Int = 3
    @Published var analytics: AnalyticsSummary?

    private var session: CcoTunnelSession?
    private var pollTimer: Timer?

    init() {
        recomputeAnalytics()
    }

    func generateDemoProfile() {
        do {
            let demo = try CcoClient.generateDemoProfileJson(localNode: "A", peerNode: "B")
            try loadAndVerifyProfile(demo)
            trustError = nil
        } catch {
            trustError = error.localizedDescription
        }
    }

    func loadAndVerifyProfile(_ raw: String) throws {
        guard let data = raw.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let regJson = obj["trust_registry_json"] as? String,
              let rootJson = obj["trust_root_json"] as? String,
              let peers = obj["peers"] as? [[String: Any]]
        else {
            throw CcoFfiError(code: "invalid_profile_json")
        }
        let reqNodes = peers.compactMap { $0["name"] as? String }
        trustStatus = try CcoClient.verifyTrustBundle(
            registryJson: regJson,
            rootJson: rootJson,
            requiredNodes: reqNodes
        )
        profileJson = raw
    }

    func toggleTunnel() {
        if isRunning {
            stopTunnel()
            return
        }
        guard let profileJson, trustStatus?.authenticated == true else {
            lastError = "Load or generate a verified Trust Registry v2 profile first."
            return
        }
        do {
            let replayPath = FileManager.default.temporaryDirectory
                .appendingPathComponent("cco-macos-replay.sqlite").path
            let cfg = try CcoClient.prepareTunnelStartConfig(
                profileJson: profileJson,
                replayDbPath: replayPath,
                mccMode: mccMode,
                x1Fanout: x1Fanout,
                x2Fanout: x2Fanout,
                hasPiHeader: false
            )
            session = try CcoTunnelSession.startChannel(configJson: cfg)
            isRunning = true
            lastError = nil
            startPolling()
        } catch {
            lastError = error.localizedDescription
            stopTunnel()
        }
    }

    func initiateHandshake() {
        session?.initiateHandshake()
    }

    func stopTunnel() {
        pollTimer?.invalidate()
        pollTimer = nil
        session?.stop()
        session = nil
        isRunning = false
    }

    func recomputeAnalytics() {
        let clampedM = min(analyticsM, max(analyticsN - 2, 1))
        analytics = try? CcoClient.analyticsSummary(n: analyticsN, m: clampedM, j: analyticsJ)
    }

    private func startPolling() {
        pollTimer?.invalidate()
        pollTimer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let session = self.session else { return }
                if let s = try? session.stats() {
                    self.stats = s
                }
                if let drained = try? session.drainEvents(), !drained.isEmpty {
                    self.events = (drained.reversed() + self.events).prefix(120).map { $0 }
                }
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var vm = CcoViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Cascade Control Overlay")
                        .font(.title2.bold())
                    Text("Rust cco-ffi v\(vm.coreVersion) · Split WG / MCC Overlay (macOS)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                let holds = vm.stats?.controlPlaneInvariantHolds ?? true
                Text(holds ? "DIRECT WG HANDSHAKE TX = 0" : "DIRECT HANDSHAKE VIOLATION")
                    .font(.system(.caption, design: .monospaced).bold())
                    .foregroundColor(holds ? .green : .red)
            }
            .padding(.bottom, 4)

            TabView {
                tunnelTab
                    .tabItem { Label("Tunnel", systemImage: "shield.lefthalf.filled") }
                telemetryTab
                    .tabItem { Label("Telemetry & Proof", systemImage: "checkmark.shield") }
                analyticsTab
                    .tabItem { Label("Research Analytics", systemImage: "chart.bar.xaxis") }
            }
        }
        .padding(16)
        .frame(minWidth: 760, minHeight: 540)
    }

    private var tunnelTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                GroupBox("Tunnel Lifecycle") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("State: \(vm.stats?.state.uppercased() ?? (vm.isRunning ? "RUNNING" : "DISCONNECTED"))")
                            .font(.headline)
                        if let err = vm.lastError {
                            Text(err).foregroundColor(.red).font(.caption)
                        }
                        HStack {
                            Button(vm.isRunning ? "Disconnect" : "Connect Split Tunnel") {
                                vm.toggleTunnel()
                            }
                            .buttonStyle(.borderedProminent)
                            if vm.isRunning {
                                Button("Initiate MCC Handshake") { vm.initiateHandshake() }
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                GroupBox("Ed25519 Trust Registry v2") {
                    VStack(alignment: .leading, spacing: 8) {
                        if let st = vm.trustStatus {
                            Text("VERIFIED v\(st.version) · signer=\(st.signerKeyId) · sha256=\(st.sha256.prefix(16))...")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.green)
                        } else {
                            Text("No verified profile loaded yet.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        if let err = vm.trustError {
                            Text("Fail-closed error: \(err)").foregroundColor(.red).font(.caption)
                        }
                        Button("Generate RFC 5737 Demo Profile") {
                            vm.generateDemoProfile()
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }

                GroupBox("MCC Control-Plane Parameters") {
                    HStack(spacing: 16) {
                        Picker("Mode", selection: $vm.mccMode) {
                            ForEach(CcoClient.allowedMccModes, id: \.self) { Text($0).tag($0) }
                        }
                        .frame(width: 180)
                        Stepper("X1 Fanout: \(vm.x1Fanout)", value: $vm.x1Fanout, in: 1...4)
                        Stepper("X2 Fanout: \(vm.x2Fanout)", value: $vm.x2Fanout, in: 1...4)
                    }
                    .padding(6)
                }
            }
            .padding(.top, 8)
        }
    }

    private var telemetryTab: some View {
        VStack(alignment: .leading, spacing: 12) {
            GroupBox("Split-Plane Proof Counters") {
                if let s = vm.stats {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Overlay Handshake TX/RX:  \(s.overlayHandshakeTx) / \(s.overlayHandshakeRx)")
                        Text("Direct Handshake TX:      \(s.directHandshakeTx) (INVARIANT: 0)")
                        Text("Direct Handshake Dropped: \(s.directHandshakeRxDropped)")
                        Text("Direct WG Type 4 TX/RX:   \(s.directDataTx) / \(s.directDataRx)")
                        Text("Direct Data Bytes TX/RX:  \(s.directBytesTx) B / \(s.directBytesRx) B")
                        Text("Handshake Latency:        \(s.handshakeMs.map { "\($0) ms" } ?? "pending")")
                        Text("Selected X1 (X2 hidden):  \(s.selectedX1 ?? "pending")")
                    }
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                } else {
                    Text("Start a tunnel to view live split-plane proof counters.")
                        .foregroundColor(.secondary)
                        .padding(6)
                }
            }

            List(vm.events) { ev in
                Text("[\(ev.level.uppercased())] \(ev.code) peer=\(ev.peer ?? "-")")
                    .font(.system(.caption, design: .monospaced))
            }
        }
        .padding(.top, 8)
    }

    private var analyticsTab: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 16) {
                Stepper("n = \(vm.analyticsN)", value: $vm.analyticsN, in: 4...40)
                Stepper("m = \(vm.analyticsM)", value: $vm.analyticsM, in: 1...max(vm.analyticsN - 2, 1))
                Stepper("j = \(vm.analyticsJ)", value: $vm.analyticsJ, in: 1...6)
                Button("Compute") { vm.recomputeAnalytics() }
                    .buttonStyle(.borderedProminent)
            }
            if let a = vm.analytics {
                GroupBox("Chapter 3 Exact Combinatorics & Rayon Monte Carlo") {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("I2P routes:   \(a.i2pRoutes)")
                        Text(String(format: "F1 (Tor):     %@ routes | H=%.4f b | P=%.2f%% | n50=%@",
                                    a.f1Routes, a.f1EntropyBits, a.f1CompromisePct, a.f1N50.map(String.init) ?? "-"))
                        Text(String(format: "F3 (No-Rep):  %@ routes | H=%.4f b | P=%.2f%% | n50=%@",
                                    a.f3Routes, a.f3EntropyBits, a.f3CompromisePct, a.f3N50.map(String.init) ?? "-"))
                        Text(String(format: "F4 (With-Rep):%@ routes | H=%.4f b | P=%.2f%% | n50=%@",
                                    a.f4Routes, a.f4EntropyBits, a.f4CompromisePct, a.f4N50.map(String.init) ?? "-"))
                        if let mc = a.f4MonteCarloPct, let err = a.f4MonteCarloAbsError, let ms = a.f4MonteCarloMs {
                            Text(String(format: "Rayon MC 100k: %.2f%% (err=%.5f, %.2f ms)", mc, err, ms))
                        }
                    }
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(6)
                }
            }
            Spacer()
        }
        .padding(.top, 8)
    }
}

@main
struct CcoMacAppMain: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
