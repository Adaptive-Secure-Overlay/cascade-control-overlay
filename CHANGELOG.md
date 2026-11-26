# Changelog

All notable changes to `cascade-control-overlay` are documented in this file.

## [0.2.0] - 2026-11-26

### Added
- **Userspace Split WireGuard Engine (`cco-wg-tunnel`):** `#![forbid(unsafe_code)]` in-process userspace WireGuard tunnel powered by Cloudflare's `boringtun 0.7.1` with strict architectural split: `WG Type 1/2/3` handshakes traverse the MCC overlay (`A -> X1 -> X2 -> B`, Ed25519/X25519/SQLite anti-replay) while `WG Type 4` encrypted transport packets flow directly (`A <-> B`), and unsolicited direct handshakes are dropped fail-closed.
- **RFC WireGuard Framing & Linux TUN Support (`cco-proto`, `cco-cascade`, `cco-linux-proxy`, `cco-cli`):** Added `parse_wireguard_packet_rfc` (WireGuard spec Section 5.4.6 unpadded Type 4 compatibility), MCC support for WireGuard control handshakes (`WG_OVERLAY_CONTROL_PORT = 51820`), `SocketProtector` hook in `cco-transport` for Android `VpnService.protect(fd)`, `/dev/net/tun` helper in `cco-linux-proxy`, and `cco wg-keygen` / `cco wg-tunnel` CLI subcommands.
- **Live Userspace WireGuard L3 Verification (`lab/scripts/wg_userspace_e2e.sh`):** 4-node Linux `ip netns` + `/dev/net/tun` + `tcpdump` verification proving `direct_wg_control_total == 0`, `direct_wg_type4_data > 0`, `handshake_ms = 105 ms`, and 5/5 ICMP replies (`0.452 ms` avg RTT), automated in CI (`wg-userspace-l3-live`).
- **Unified Cross-Platform FFI (`cco-ffi`):** Panic-safe C-ABI (`include/cco_ffi.h`, `cdylib` + `staticlib`) for Windows C# and macOS Swift, plus native Android JNI (`org.adaptivesecureoverlay.cco.NativeBridge`) with direct `VpnService.protect(fd)` callback and 4-node C-ABI E2E tests (`ffi_roundtrip`).
- **Android Material 3 Client (`apps/android`):** Rootless Kotlin + Jetpack Compose client with native `VpnService`, `libcco_ffi.so` (`arm64-v8a` + `x86_64`), 3 tabs (Tunnel, Telemetry & Proof, Chapter 3 Research Analytics), JVM unit tests, and automated CI APK build (`android-build`).
- **Windows `.NET 9` WPF Client (`apps/windows`):** Clean open-source C# WPF desktop client with P/Invoke bindings to `cco_ffi.dll`, SHA-256 verified official signed `wintun.dll` 0.14.1 (`scripts/fetch-wintun.ps1`), xUnit P/Invoke integration suite, and CI build (`windows-gui-build`).
- **macOS SwiftUI Client (`apps/macos`):** Swift Package Manager SwiftUI client statically linked against `libcco_ffi.a` via C-ABI (`CCcoFfi`), native `utun` and `NEPacketTunnelProvider` adapters, XCTest integration suite, and `macos-latest` CI build (`macos-gui-build`).
- **Release Pipeline & Scopus Research Plan:** Extended `.github/workflows/release.yml` to publish Android APK, Windows WPF ZIP, and macOS `.app` bundle alongside CLI binaries and `SHA256SUMS.txt`; added `docs/SCOPUS-EXPERIMENT-PLAN.md` and userspace-vs-kernel benchmark tables in `docs/BENCHMARKS.md`.

## [0.1.1] - 2026-11-26

### Changed & Fixed
- **Security:** Upgraded `rusqlite` (`0.32 -> 0.43`, bundled `libsqlite3-sys 0.40`) to resolve `RUSTSEC-2026-0459` (SQLite CVE-2026-119375).
- **Audit:** Added `.cargo/audit.toml` documenting the scoped offline benchmark exception (`RUSTSEC-2023-0071` in `cco-analytics` Table 4.6 RSA-3072 baseline) and switched CI security audit to `cargo-audit`.
- **CI / L3 Lab:** Added Ubuntu 24.04 AppArmor profile handling for ephemeral `ip netns` strongSwan verification and fixed `umask` scoping + failure diagnostics in `lab/scripts/netns_e2e.sh` (all 7/7 CI jobs passing).
- **Releases:** Added automated multi-platform GitHub Release workflow publishing binaries for Linux (`x86_64-musl`, `aarch64-musl`), Windows (`x86_64-msvc`), and macOS (`aarch64-apple-darwin`) with `SHA256SUMS.txt`.

## [0.1.0] - 2026-11-26

### Added
- **Workspace & Cryptography (`cco-crypto`):** Pure-Rust `X25519` (with contributory check), `HKDF-SHA256`, `AES-128-GCM` / `AES-256-GCM`, `Ed25519` (`verify_strict`), `ZeroizeOnDrop` wrappers, and wire-exact KDF/AAD contexts verified against Python golden vectors.
- **Trust Registry v2 (`cco-trust`):** Fail-closed verification against pinned external trust root, strict duplicate-free canonical JSON, monotonic anti-rollback store with atomic `fsync + rename` updates, `last-valid` recovery, offline provisioning helpers, and 12-test negative security matrix.
- **Protocol & Parsers (`cco-proto`):** All overlay message types (`MGMT_*`, `MCC_*`, `PRIV_*`, `CASCADE_*`, `LINK_FRAG`), `LinkFrag` UDP fragmentation (`<= 1200 B`, chunk 700 B, TTL 15 s), and zero-panic IKEv2 (UDP/500 & UDP/4500 Non-ESP) and WireGuard (`type 1/2/3` vs rejected `type 4`) parsers.
- **Sans-I/O State Machines (`cco-cascade`):**
  - Authenticated MCC with 4 selection modes (`first`, `window`, `adaptive`, `wait-all`), opaque privacy continuation tokens, move-only `LocalDeliveryProof`, and durable SQLite anti-replay ledger.
  - Generalized `UniversalCascade` (`H >= 2`) with cell-level privacy, `CASCADE_REJECT` rerouting, and `CASCADE_ABORT` recovery.
  - WireGuard Handshake Overlay engine and canonical 27-scenario verification matrix (`json`, `csv`, `eve-json`).
- **Analytics & Benchmarks (`cco-analytics`):** Exact `BigUint` Chapter 3 combinatorics (`F1/Tor`, `I2P`, `F3`, `F4`), exact compromise probabilities and `n50` thresholds, parallel `rayon` Monte Carlo simulator, and X25519 vs RSA-3072 benchmark (Table 4.6).
- **Async Transport & CLI (`cco-transport`, `cco-cli`):** Tokio UDP peer mesh, 4-step MGMT handshake with rekey/crossing overlap, sized UDP socket buffers, non-blocking session worker, unified `cco` CLI, localhost 4-node & 10-node UDP E2E suite, and live Rust↔Python UDP wire cross-compatibility test.
- **Linux Proxy & Verification Lab (`cco-linux-proxy`, `lab/`):** Linux `IP_TRANSPARENT` / `IP_RECVORIGDSTADDR` / `SO_MARK` / `SOCK_RAW` (`IP_HDRINCL`) backend, parameterized `nftables` / `ip xfrm` generators, lightweight multi-stage `Dockerfile` (~200 MB), `docker-compose.yml`, and standalone Linux `ip netns` strongSwan verification harness (`verify_no_direct_ike.sh`).
- **CI & Documentation:** GitHub Actions workflow (`fmt`, `clippy -D warnings`, Linux + Windows tests with Python cross-compat, static `musl` build, live `netns` strongSwan verification, security audit) and full EN/RU documentation.
